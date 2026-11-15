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

type ListHandler = Gates['onList'];

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

/** What the host injects to build the gate. */
export interface ManifestGateDeps {
  readonly serverName: string;
  readonly onFirstUse: 'write' | 'require';
  readonly onMismatch: 'halt' | 'flag';
  readonly store: LockStore;
  /** Scans one tool's description, annotations and schema text. */
  readonly scanTool: (tool: ToolDefinition) => ToolScan;
  readonly report: (event: ManifestEvent) => void;
  /**
   * Asks the upstream for its whole tool list. Used to check a pinned manifest
   * before the first `tools/call` of a session that never listed: a client that
   * remembers the catalogue from last time would otherwise call straight past
   * the gate. Absent means that check is not made.
   */
  readonly fetchTools?: (() => Promise<readonly unknown[]>) | undefined;
}

/** The gate: a `tools/list` handler and a question for the call path. */
export interface ManifestGate {
  readonly onList: ListHandler;
  /**
   * The error that refuses a `tools/call` right now, or undefined to let it
   * through. Async because, with a pin and no list seen yet this session, it
   * checks the upstream's manifest first.
   */
  callGuard(): Promise<ManifestGateError | undefined>;
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

/** Builds the manifest gate for one connection. */
export function createManifestGate(deps: ManifestGateDeps): ManifestGate {
  let halted: MismatchReason | undefined;
  /** True once a manifest has been checked against the pin this session. */
  let verified = false;
  let walk: Walk | undefined;
  /** Scan results by tool hash: a re-list is neither rescanned nor re-reported. */
  const scans = new Map<string, ToolScan>();

  /** Refuses the request: reports, remembers, and throws. */
  const halt = (reason: MismatchReason, diff?: ManifestDiff, detail?: string): never => {
    deps.report({ kind: 'mismatch', action: 'halt', reason, diff, detail });
    halted = reason;
    throw refusal(reason, diff);
  };

  /** A mismatch the operator chose how to treat: `halt` refuses, `flag` reports and goes on. */
  const mismatch = (reason: MismatchReason, diff?: ManifestDiff, detail?: string): void => {
    if (deps.onMismatch === 'halt') halt(reason, diff, detail);
    deps.report({ kind: 'mismatch', action: 'flag', reason, diff, detail });
  };

  /** Scans a tool once per distinct definition, reporting a flagged one the first time. */
  const scanOf = (tool: ToolDefinition): ToolScan => {
    // `hashTool` covers exactly the fields the scan reads.
    const key = hashTool(tool);
    const known = scans.get(key);
    if (known !== undefined) return known;
    const scan = deps.scanTool(tool);
    scans.set(key, scan);
    if (scan.action !== 'allow' && scan.ruleIds.length > 0) {
      deps.report({
        kind: 'description_flagged',
        tool: tool.name,
        ruleIds: scan.ruleIds,
        score: scan.score,
      });
    }
    return scan;
  };

  /** Decides what a manifest means for the traffic. Throws to refuse. */
  const judge = (current: Walk, complete: boolean): void => {
    // A mismatch the operator chose to flag falls through to here: the manifest
    // has been looked at, and the traffic goes on.
    if (current.malformed) {
      mismatch('malformed');
      verified = true;
      return;
    }

    const state = deps.store.read();
    if (state.kind === 'invalid') {
      // Never fall through to a first-use write: that would overwrite a lock the
      // operator may be in the middle of repairing.
      mismatch('unreadable', undefined, state.reason);
      verified = true;
      return;
    }

    const pinned: ServerLock | undefined =
      state.kind === 'ok' ? serverLockOf(state.lock, deps.serverName) : undefined;

    if (pinned === undefined) {
      if (deps.onFirstUse === 'require') {
        // `require` is not a mismatch the operator can wave through with `flag`:
        // the point of it is that nothing runs without a reviewed lock.
        halt('unpinned');
      }
      if (!complete) return;
      try {
        const lock = withServerLock(
          state.kind === 'ok' ? state.lock : emptyLock(),
          deps.serverName,
          lockServer(current.tools, scanFindings(current.tools, scanOf)),
        );
        deps.store.write(lock);
      } catch (error) {
        halt('write_failed', undefined, messageOf(error));
      }
      deps.report({ kind: 'pinned', toolCount: current.tools.length });
      halted = undefined;
      verified = true;
      return;
    }

    const diff = diffServer(pinned, current.tools);
    // A page that is not the last cannot say what is missing.
    const effective: ManifestDiff = complete
      ? diff
      : { ...diff, removed: [], changed: diff.added.length > 0 || diff.altered.length > 0 };
    if (effective.changed) {
      mismatch('changed', effective);
      verified = true;
      return;
    }
    halted = undefined;
    verified = true;
  };

  const onList: ListHandler = async (request, forward) => {
    const page = await forward();
    const cursor = request.params?.cursor;
    if (cursor === undefined || walk === undefined) walk = newWalk(cursor === undefined);
    const current = walk;

    const added = ingest(current, Array.isArray(page.tools) ? (page.tools as unknown[]) : []);
    for (const tool of added) scanOf(tool);
    judge(current, current.fromStart && typeof page.nextCursor !== 'string');
    return page;
  };

  const callError = (reason: MismatchReason): ManifestGateError =>
    new ManifestGateError(
      reason,
      `[mcpguard] tools/call refused · this server's manifest is not trusted (${reason}) · list its tools again once guardlock.json is fixed or \`mcpguard lock --accept\` has been run`,
    );

  const standingRefusal = (): MismatchReason | undefined => {
    if (halted !== undefined) return halted;
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
  const verifyBeforeCall = async (): Promise<ManifestGateError | undefined> => {
    if (verified || deps.fetchTools === undefined) return undefined;
    const state = deps.store.read();
    if (state.kind !== 'ok' || serverLockOf(state.lock, deps.serverName) === undefined) {
      return undefined;
    }
    let raws: readonly unknown[];
    try {
      raws = await deps.fetchTools();
    } catch (error) {
      // Not remembered as a halt: the upstream may only be slow, and the next
      // call tries again.
      deps.report({
        kind: 'mismatch',
        action: 'halt',
        reason: 'unverified',
        detail: messageOf(error),
      });
      return callError('unverified');
    }
    const checked = newWalk(true);
    for (const tool of ingest(checked, raws)) scanOf(tool);
    try {
      judge(checked, true);
    } catch (error) {
      if (error instanceof ManifestGateError) return callError(error.reason);
      throw error;
    }
    return undefined;
  };

  return {
    onList,
    callGuard: async () => {
      const reason = standingRefusal();
      if (reason !== undefined) return callError(reason);
      return verifyBeforeCall();
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
