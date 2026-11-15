/**
 * The `tools/list` gate: manifest pinning, wired to a lock file (ADR-005).
 *
 * The pure half (normalising, hashing, diffing) lives in `@tunedness/mcpguard-core`. This
 * is the half that decides what a diff *means* for the traffic: first contact
 * pins, a later difference halts or is flagged, and a server that cannot be
 * held to a lock is not trusted by default.
 *
 * Three things are easy to get wrong and are handled here on purpose:
 * - A paginated `tools/list` shows one page at a time. A page is never read as
 *   the whole catalogue, or every tool on another page would look removed.
 * - A refused list must not leave `tools/call` open. The gate remembers it
 *   refused, and the call path asks it.
 * - What goes back to the client never carries a tool name or description: they
 *   are the server's words, and this gate exists because the server may be
 *   hostile. The names go to stderr and the record, JSON-encoded.
 */
import {
  diffServer,
  emptyLock,
  hashTool,
  lockServer,
  type ManifestDiff,
  type ServerLock,
  serverLockOf,
  type ToolDefinition,
  toToolDefinition,
  withServerLock,
} from '@tunedness/mcpguard-core';
import type { Gates } from '@tunedness/mcpguard-proxy';
import { messageOf } from './errors.js';
import type { LockStore } from './lock-file.js';

/** `tools/list`, as the gate sees it: the request, the upstream call, and who is asking. */
type ListHandler<X> = (
  request: Parameters<Gates['onList']>[0],
  forward: Parameters<Gates['onList']>[1],
  context?: X,
) => ReturnType<Gates['onList']>;

/** What scanning one tool's description and annotations found. */
export interface ToolScan {
  readonly ruleIds: readonly string[];
  readonly score: number;
  /** `allow` when nothing reached the flag threshold. */
  readonly action: 'allow' | 'flag' | 'strip' | 'block';
}

/** Why the gate refused or flagged a manifest. */
export type MismatchReason =
  | 'changed'
  | 'unpinned'
  | 'unreadable'
  | 'malformed'
  | 'write_failed'
  /** A call arrived before any list and the upstream could not be asked for its tools. */
  | 'unverified';

/** What the gate tells the host happened. The host turns it into events and records. */
export type ManifestEvent =
  | { readonly kind: 'pinned'; readonly toolCount: number }
  | {
      readonly kind: 'description_flagged';
      readonly tool: string;
      readonly ruleIds: readonly string[];
      readonly score: number;
    }
  | {
      readonly kind: 'mismatch';
      /** `halt` refused the list; `flag` forwarded it. */
      readonly action: 'halt' | 'flag';
      readonly reason: MismatchReason;
      readonly diff?: ManifestDiff | undefined;
      /** Why the lock or the write failed, or what was malformed. Not server text. */
      readonly detail?: string | undefined;
    };

/** Thrown to refuse a request. The message is safe to hand to the client. */
export class ManifestGateError extends Error {
  readonly reason: MismatchReason;

  constructor(reason: MismatchReason, message: string) {
    super(message);
    this.name = 'ManifestGateError';
    this.reason = reason;
  }
}

/**
 * What the host injects to build the gate.
 *
 * `X` is whatever the host knows about the caller of one request (which session,
 * which identity). A host with one connection has none and `X` is `undefined`;
 * one gate serving many callers hands each request's through, so what the gate
 * reports is attributed to the right one.
 */
export interface ManifestGateDeps<X = undefined> {
  readonly serverName: string;
  readonly onFirstUse: 'write' | 'require';
  readonly onMismatch: 'halt' | 'flag';
  readonly store: LockStore;
  /** Scans one tool's description, annotations and schema text. */
  readonly scanTool: (tool: ToolDefinition) => ToolScan;
  readonly report: (event: ManifestEvent, context: X) => void;
  /**
   * Which paginated `tools/list` walk a request belongs to. Requests that share a
   * key share a walk; two callers paging through the list at once must not share
   * one, or each would read the other's pages as its own.
   */
  readonly walkKey?: ((context: X) => string) | undefined;
  /**
   * Which server record a request belongs to (`servers.<name>`). A halt belongs to
   * the server that showed the mismatch, not to the session that happened to see
   * it and not to the connection that carried it (ADR-005, "halt yapışkandır"): it
   * stays until `lock --accept` changes the pin, no clean list from anyone lifts
   * it, and it stops every session, the ones opened afterwards included. `serve`
   * holds one gate per server and keys it by the server's name; absent, every
   * request shares one state (`wrap`).
   */
  readonly stateKey?: ((context: X) => string) | undefined;
  /**
   * Which upstream connection a request travels on. Whether a manifest has been
   * checked before a call is a fact about a connection: a new one (a new legacy
   * session's, or a re-established shared one) owes the check. Absent, the
   * `stateKey` is used.
   */
  readonly connectionKey?: ((context: X) => string) | undefined;
  /**
   * Asks the upstream for its whole tool list. Used to check a pinned manifest
   * before the first `tools/call` of a session that never listed: a client that
   * remembers the catalogue from last time would otherwise call straight past
   * the gate. Absent means that check is not made.
   */
  readonly fetchTools?: ((context: X) => Promise<readonly unknown[]>) | undefined;
}

/** The gate: a `tools/list` handler and a question for the call path. */
export interface ManifestGate<X = undefined> {
  readonly onList: ListHandler<X>;
  /**
   * The error that refuses a `tools/call` right now, or undefined to let it
   * through. Async because, with a pin and no list seen yet this session, it
   * checks the upstream's manifest first.
   */
  callGuard(context?: X): Promise<ManifestGateError | undefined>;
}

const PIN_HINT = 'run `mcpguard lock --diff` to see it, `mcpguard lock --accept` to approve it';

function refusal(reason: MismatchReason, diff?: ManifestDiff): ManifestGateError {
  switch (reason) {
    case 'changed': {
      const counts = diff
        ? `${diff.altered.length} altered, ${diff.added.length} added, ${diff.removed.length} removed`
        : 'changed';
      return new ManifestGateError(
        reason,
        `[mcpguard] tools/list refused · the server's tools no longer match guardlock.json · ${counts} · ${PIN_HINT}`,
      );
    }
    case 'unpinned':
      return new ManifestGateError(
        reason,
        '[mcpguard] refused · no pinned manifest for this server and lock.on_first_use is require · `mcpguard lock --accept` pins it',
      );
    case 'unreadable':
      return new ManifestGateError(
        reason,
        '[mcpguard] refused · guardlock.json cannot be read or is malformed · fix or restore the file',
      );
    case 'malformed':
      return new ManifestGateError(
        reason,
        '[mcpguard] tools/list refused · the server advertised a tool with no name, or the same name twice',
      );
    case 'write_failed':
      return new ManifestGateError(
        reason,
        '[mcpguard] tools/list refused · the manifest could not be pinned to guardlock.json · check the path is writable',
      );
    case 'unverified':
      return new ManifestGateError(
        reason,
        '[mcpguard] refused · the upstream tool list could not be read to check the manifest',
      );
  }
}

/** One in-progress walk over a paginated `tools/list`. */
interface Walk {
  /** False when the first page seen carried a cursor: earlier pages were not seen. */
  readonly fromStart: boolean;
  readonly tools: ToolDefinition[];
  readonly names: Set<string>;
  malformed: boolean;
}

function newWalk(fromStart: boolean): Walk {
  return { fromStart, tools: [], names: new Set(), malformed: false };
}

/** Adds one page of raw entries to a walk and returns the definitions it added. */
function ingest(walk: Walk, raws: readonly unknown[]): ToolDefinition[] {
  const added: ToolDefinition[] = [];
  for (const raw of raws) {
    const tool = toToolDefinition(raw);
    if (tool === undefined || walk.names.has(tool.name)) {
      walk.malformed = true;
      continue;
    }
    walk.names.add(tool.name);
    walk.tools.push(tool);
    added.push(tool);
  }
  return added;
}

/** The most paginated walks held at once; a caller that never finishes one cannot grow the table. */
const MAX_WALKS = 64;

/** The most connections whose verdict is held at once; a connection that is gone is not asked about again. */
const MAX_CONNECTIONS = 4_096;

/** What the gate has concluded about one server's manifest. */
interface UpstreamState {
  /** Set by a mismatch; cleared only when the pin changes (`lock --accept`). */
  halted: MismatchReason | undefined;
  /** What the pin looked like when it halted; a different one means the operator acted. */
  haltedAgainst: string | undefined;
  /** Bumped when a halt is lifted, so every connection owes the check again. */
  epoch: number;
}

/** Builds the manifest gate for one server. */
export function createManifestGate<X = undefined>(deps: ManifestGateDeps<X>): ManifestGate<X> {
  const states = new Map<string, UpstreamState>();
  /** The epoch each connection was last verified in. */
  const verifiedIn = new Map<string, number>();

  const stateOf = (context: X): UpstreamState => {
    const key = deps.stateKey?.(context) ?? '';
    let state = states.get(key);
    if (state === undefined) {
      state = { halted: undefined, haltedAgainst: undefined, epoch: 0 };
      states.set(key, state);
      // A forgotten upstream is checked afresh on its next call, so the table can
      // be bounded; a refused one is the last to be forgotten.
      while (states.size > MAX_CONNECTIONS) {
        const others = [...states].filter(([held]) => held !== key);
        const victim = (others.find(([, held]) => held.halted === undefined) ?? others[0])?.[0];
        if (victim === undefined) break;
        states.delete(victim);
      }
    }
    return state;
  };
  const connectionOf = (context: X): string =>
    deps.connectionKey?.(context) ?? deps.stateKey?.(context) ?? '';
  const isVerified = (context: X): boolean =>
    verifiedIn.get(connectionOf(context)) === stateOf(context).epoch;
  const markVerified = (context: X): void => {
    const key = connectionOf(context);
    verifiedIn.delete(key);
    verifiedIn.set(key, stateOf(context).epoch);
    while (verifiedIn.size > MAX_CONNECTIONS) {
      const oldest = verifiedIn.keys().next().value;
      if (oldest === undefined) break;
      verifiedIn.delete(oldest);
    }
  };

  /** The pin as the operator would change it: what `lock --accept` rewrites. */
  const pinFingerprint = (): string => {
    const stored = deps.store.read();
    if (stored.kind === 'invalid') return `invalid:${stored.reason}`;
    if (stored.kind === 'absent') return 'absent';
    const pin = serverLockOf(stored.lock, deps.serverName);
    return pin === undefined ? 'unpinned' : JSON.stringify(pin);
  };

  /** Lifts a halt the operator has answered by changing the pin; nothing else lifts one. */
  const releaseIfAnswered = (state: UpstreamState): void => {
    if (state.halted === undefined || pinFingerprint() === state.haltedAgainst) return;
    state.halted = undefined;
    state.haltedAgainst = undefined;
    state.epoch += 1;
  };

  const walks = new Map<string, Walk>();
  /** Scan results by tool hash: a re-list is neither rescanned nor re-reported. */
  const scans = new Map<string, ToolScan>();

  /** Refuses the request: reports, remembers, and throws. */
  const halt = (
    context: X,
    reason: MismatchReason,
    diff?: ManifestDiff,
    detail?: string,
  ): never => {
    deps.report({ kind: 'mismatch', action: 'halt', reason, diff, detail }, context);
    const state = stateOf(context);
    state.halted = reason;
    state.haltedAgainst = pinFingerprint();
    throw refusal(reason, diff);
  };

  /** A mismatch the operator chose how to treat: `halt` refuses, `flag` reports and goes on. */
  const mismatch = (
    context: X,
    reason: MismatchReason,
    diff?: ManifestDiff,
    detail?: string,
  ): void => {
    if (deps.onMismatch === 'halt') halt(context, reason, diff, detail);
    deps.report({ kind: 'mismatch', action: 'flag', reason, diff, detail }, context);
  };

  /** Scans a tool once per distinct definition, reporting a flagged one the first time. */
  const scanOf = (tool: ToolDefinition, context: X): ToolScan => {
    // `hashTool` covers exactly the fields the scan reads.
    const key = hashTool(tool);
    const known = scans.get(key);
    if (known !== undefined) return known;
    const scan = deps.scanTool(tool);
    scans.set(key, scan);
    if (scan.action !== 'allow' && scan.ruleIds.length > 0) {
      deps.report(
        {
          kind: 'description_flagged',
          tool: tool.name,
          ruleIds: scan.ruleIds,
          score: scan.score,
        },
        context,
      );
    }
    return scan;
  };

  /** Decides what a manifest means for the traffic. Throws to refuse. */
  const judge = (current: Walk, complete: boolean, context: X): void => {
    // A mismatch the operator chose to flag falls through to here: the manifest
    // has been looked at, and the traffic goes on.
    if (current.malformed) {
      mismatch(context, 'malformed');
      markVerified(context);
      return;
    }

    const stored = deps.store.read();
    if (stored.kind === 'invalid') {
      // Never fall through to a first-use write: that would overwrite a lock the
      // operator may be in the middle of repairing.
      mismatch(context, 'unreadable', undefined, stored.reason);
      markVerified(context);
      return;
    }

    const pinned: ServerLock | undefined =
      stored.kind === 'ok' ? serverLockOf(stored.lock, deps.serverName) : undefined;

    if (pinned === undefined) {
      if (deps.onFirstUse === 'require') {
        // `require` is not a mismatch the operator can wave through with `flag`:
        // the point of it is that nothing runs without a reviewed lock.
        halt(context, 'unpinned');
      }
      if (!complete) return;
      try {
        const lock = withServerLock(
          stored.kind === 'ok' ? stored.lock : emptyLock(),
          deps.serverName,
          lockServer(
            current.tools,
            scanFindings(current.tools, (tool) => scanOf(tool, context)),
          ),
        );
        deps.store.write(lock);
      } catch (error) {
        halt(context, 'write_failed', undefined, messageOf(error));
      }
      deps.report({ kind: 'pinned', toolCount: current.tools.length }, context);
      markVerified(context);
      return;
    }

    const diff = diffServer(pinned, current.tools);
    // A page that is not the last cannot say what is missing.
    const effective: ManifestDiff = complete
      ? diff
      : { ...diff, removed: [], changed: diff.added.length > 0 || diff.altered.length > 0 };
    if (effective.changed) {
      mismatch(context, 'changed', effective);
      markVerified(context);
      return;
    }
    markVerified(context);
  };

  const onList: ListHandler<X> = async (request, forward, context) => {
    const x = context as X;
    const state = stateOf(x);
    releaseIfAnswered(state);
    // A halted upstream is not listed from: a clean list is not an answer to a
    // halt, and showing one beside refused calls would only confuse the client.
    if (state.halted !== undefined) throw refusal(state.halted);
    const page = await forward();
    const cursor = request.params?.cursor;
    const key = deps.walkKey?.(x) ?? '';
    let current = walks.get(key);
    if (cursor === undefined || current === undefined) current = newWalk(cursor === undefined);
    // Re-inserted, so the oldest walk is the first to go when the table is full.
    walks.delete(key);
    walks.set(key, current);
    while (walks.size > MAX_WALKS) {
      const oldest = walks.keys().next().value;
      if (oldest === undefined) break;
      walks.delete(oldest);
    }

    const added = ingest(current, Array.isArray(page.tools) ? (page.tools as unknown[]) : []);
    for (const tool of added) scanOf(tool, x);
    judge(current, current.fromStart && typeof page.nextCursor !== 'string', x);
    return page;
  };

  const callError = (reason: MismatchReason): ManifestGateError =>
    new ManifestGateError(
      reason,
      `[mcpguard] tools/call refused · this server's manifest is not trusted (${reason}) · it stays refused until \`mcpguard lock --accept\` has been run or guardlock.json is fixed`,
    );

  const standingRefusal = (context: X): MismatchReason | undefined => {
    const state = stateOf(context);
    releaseIfAnswered(state);
    if (state.halted !== undefined) return state.halted;
    if (deps.onFirstUse === 'require') {
      const state = deps.store.read();
      if (state.kind === 'invalid') return deps.onMismatch === 'halt' ? 'unreadable' : undefined;
      if (state.kind === 'absent' || serverLockOf(state.lock, deps.serverName) === undefined) {
        return 'unpinned';
      }
    }
    return undefined;
  };

  /** With a pin and no list seen yet, checks the upstream's manifest before a call goes through. */
  const verifyBeforeCall = async (context: X): Promise<ManifestGateError | undefined> => {
    if (isVerified(context) || deps.fetchTools === undefined) return undefined;
    const state = deps.store.read();
    if (state.kind === 'invalid') {
      // An unreadable lock is a refusal under `halt`, as it is for a list: a call
      // must not run on a pin nobody can read just because it came first.
      try {
        mismatch(context, 'unreadable', undefined, state.reason);
      } catch (error) {
        if (error instanceof ManifestGateError) return callError(error.reason);
        throw error;
      }
      markVerified(context);
      return undefined;
    }
    if (state.kind !== 'ok' || serverLockOf(state.lock, deps.serverName) === undefined) {
      return undefined;
    }
    let raws: readonly unknown[];
    try {
      raws = await deps.fetchTools(context);
    } catch (error) {
      // Not remembered as a halt: the upstream may only be slow, and the next
      // call tries again.
      deps.report(
        {
          kind: 'mismatch',
          action: 'halt',
          reason: 'unverified',
          detail: messageOf(error),
        },
        context,
      );
      return callError('unverified');
    }
    const checked = newWalk(true);
    for (const tool of ingest(checked, raws)) scanOf(tool, context);
    try {
      judge(checked, true, context);
    } catch (error) {
      if (error instanceof ManifestGateError) return callError(error.reason);
      throw error;
    }
    // The upstream was asked, and while it answered another caller may have seen a
    // mismatch and halted it. A clean answer to this call does not outvote that.
    const halted = stateOf(context).halted;
    if (halted !== undefined) return callError(halted);
    return undefined;
  };

  return {
    onList,
    callGuard: async (context) => {
      const reason = standingRefusal(context as X);
      if (reason !== undefined) return callError(reason);
      return verifyBeforeCall(context as X);
    },
  };
}

/** The rule ids that fired on each tool's description, for the lock file. */
export function scanFindings(
  tools: readonly ToolDefinition[],
  scanTool: (tool: ToolDefinition) => ToolScan,
): Map<string, readonly string[]> {
  const out = new Map<string, readonly string[]>();
  for (const tool of tools) {
    const scan = scanTool(tool);
    if (scan.action !== 'allow' && scan.ruleIds.length > 0) out.set(tool.name, scan.ruleIds);
  }
  return out;
}

const MAX_TEXT_NODES = 5_000;
const MAX_TEXT_DEPTH = 8;

/**
 * The text of a tool definition a model will read: the title and description,
 * every string in the annotations, and the `description` and `title` of every
 * node of both schemas (a parameter's description is as much a prompt as the tool's).
 */
export function describedText(tool: ToolDefinition): string {
  const parts: string[] = [];
  if (tool.title !== undefined) parts.push(tool.title);
  if (tool.description !== undefined) parts.push(tool.description);
  let budget = MAX_TEXT_NODES;

  const walkAnnotations = (value: unknown, depth: number): void => {
    if (budget-- <= 0 || depth > MAX_TEXT_DEPTH) return;
    if (typeof value === 'string') parts.push(value);
    else if (Array.isArray(value)) for (const entry of value) walkAnnotations(entry, depth + 1);
    else if (typeof value === 'object' && value !== null) {
      for (const entry of Object.values(value)) walkAnnotations(entry, depth + 1);
    }
  };
  const walkSchema = (value: unknown, depth: number): void => {
    if (budget-- <= 0 || depth > MAX_TEXT_DEPTH) return;
    if (Array.isArray(value)) {
      for (const entry of value) walkSchema(entry, depth + 1);
    } else if (typeof value === 'object' && value !== null) {
      for (const [key, entry] of Object.entries(value)) {
        if ((key === 'description' || key === 'title') && typeof entry === 'string') {
          parts.push(entry);
        } else walkSchema(entry, depth + 1);
      }
    }
  };
  walkAnnotations(tool.annotations, 0);
  walkSchema(tool.inputSchema, 0);
  walkSchema(tool.outputSchema, 0);
  return parts.join('\n');
}
