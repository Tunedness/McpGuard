/**
 * Turning a policy and a ruleset into the guard gates the proxy calls.
 *
 * The host builds this once per connection: it resolves scan options from the
 * policy, wires the access decision and the content scan into the three gates,
 * and threads the session id and the audit sink through. The proxy knows the
 * gates turn a request into a result; this is where they learn how.
 */
import {
  type AuditFields,
  type CallMark,
  type CompiledPolicy,
  evaluateCombinations,
  evaluateServerAccess,
  type GuardPolicy,
  type IdentityResolution,
  type SecurityEvent,
  type SecurityEventKind,
  type SessionSource,
  type TelemetrySink,
  type ToolDefinition,
  toolKey,
} from '@tunedness/mcpguard-core';
import type { CompiledRuleset, ScanOptions } from '@tunedness/mcpguard-detect';
import { scanContent } from '@tunedness/mcpguard-detect';
import {
  blockedResult,
  extractText,
  type Gates,
  type GuardContext,
  guardCall,
  guardResource,
  guardResult,
} from '@tunedness/mcpguard-proxy';
import type { LockStore } from './lock-file.js';
import {
  createManifestGate,
  describedText,
  type ManifestEvent,
  type ToolScan,
} from './manifest-gate.js';

/**
 * What the gates need to know about one call, beyond the call itself.
 *
 * A connection-bound host (`wrap`) knows this once and gives it to the gates when
 * they are built. A host that serves many callers through one set of gates
 * (`serve`) resolves it for each request and hands it in. The gate code is the
 * same either way, so the three guards cannot fork between the two.
 */
export interface CallContext {
  /** The session the call is attributed to, and how sure that answer is (ADR-006). */
  readonly session: {
    readonly id: string;
    readonly source: SessionSource;
    readonly exact: boolean;
  };
  /** Who the caller is, and which rung of the ADR-010 ladder said so. */
  readonly identity: IdentityResolution;
  /**
   * Asks this caller's upstream for its whole tool list, for the manifest check
   * before a first call. Absent, the gates use `RuntimeDeps.fetchTools`.
   */
  readonly listTools?: (() => Promise<readonly unknown[]>) | undefined;
  /**
   * The upstream connection this call is served by: whether its manifest has been
   * checked is a fact about it, so a new connection owes the check. Absent, the
   * host has one connection (`wrap`).
   */
  readonly connection?: string | undefined;
  /**
   * The server record a halt is held against (`servers.<name>`): the same for every
   * session and both eras, so a mismatch seen on one stops them all and survives
   * reconnects. Only `lock --accept` or a restart lifts it (ADR-005). Absent, the
   * host has one server and one connection (`wrap`).
   */
  readonly upstream?: string | undefined;
}

/** What the host injects to build the gates. */
export interface RuntimeDeps {
  readonly policy: GuardPolicy;
  readonly compiledPolicy: CompiledPolicy;
  readonly ruleset: CompiledRuleset;
  readonly serverName: string;
  /**
   * The connection's own session, for a host that has one (`wrap`). Used when a
   * gate is called without a {@link CallContext}; a host that always passes one
   * leaves these out.
   */
  readonly sessionId?: string | undefined;
  readonly sessionExact?: boolean | undefined;
  /**
   * Who the caller is, asked per call: the `clientInfo` rung is only known once
   * the client has initialised, so it cannot be fixed when the gates are built.
   * Used when a gate is called without a {@link CallContext}.
   */
  readonly resolveIdentity?: (() => IdentityResolution) | undefined;
  /** The key correlation tags are computed with; absent → no tags. */
  readonly correlationKey?: string | undefined;
  /** The chained audit writer, or undefined when auditing is off. */
  readonly audit: AuditRecorder | undefined;
  /**
   * Where `guardlock.json` lives. Absent, or `policy.lock.enabled` false, means
   * the `tools/list` gate lets everything through (what v0.1.0 did).
   */
  readonly lock?: LockStore | undefined;
  /** Asks the upstream for its whole tool list, for the manifest check before a first call. */
  readonly fetchTools?: (() => Promise<readonly unknown[]>) | undefined;
  /**
   * What each session has called, for the combination rules. Absent, a store is
   * made for this set of gates; a host that serves many sessions through one
   * set of gates passes one it shares, keyed by whatever session id it resolves.
   */
  readonly history?: CombinationHistory | undefined;
  readonly clock: () => number;
  /** Reports a security event to stderr diagnostics. */
  readonly onEvent: (event: string, detail: Record<string, unknown>) => void;
  /** The OTLP sink, off by default. */
  readonly telemetry: TelemetrySink;
}

/** The most calls remembered for one session. The oldest go first. */
export const MAX_HISTORY_PER_SESSION = 512;
/**
 * The longest tool name the history will hold. Real names are a few dozen
 * characters; the name comes from the client and is kept whole so globs match it
 * whole, so without a ceiling the count caps above would bound entries but not bytes.
 */
export const MAX_TRACKED_NAME_LENGTH = 4_096;
/** The most sessions remembered at once. The one touched longest ago goes first. */
export const MAX_HISTORY_SESSIONS = 1_024;

/**
 * The calls each session has made, for the combination rules (PRD 7.5).
 *
 * Keyed by session id and owned by no one session, so a host that resolves a
 * session per request can share one store across all of them. Bounded three
 * ways: a mark older than the longest rule window can never matter and is
 * dropped, a session keeps at most {@link MAX_HISTORY_PER_SESSION} marks, and
 * at most {@link MAX_HISTORY_SESSIONS} sessions are kept. The caps cost
 * a missed combination only for a session that made hundreds of calls inside
 * one window, or after a thousand other sessions have come and gone.
 */
export class CombinationHistory {
  private readonly sessions = new Map<string, CallMark[]>();

  /** @param horizonMs the longest window of any rule: older marks are dead weight. */
  constructor(private readonly horizonMs: number) {}

  /** The marks of `sessionId` still inside the horizon, oldest first. */
  recent(sessionId: string, now: number): readonly CallMark[] {
    const since = now - this.horizonMs;
    return (this.sessions.get(sessionId) ?? []).filter((mark) => mark.at >= since);
  }

  /** Remembers a call that is going to happen. */
  record(sessionId: string, mark: CallMark): void {
    const marks = [...this.recent(sessionId, mark.at), mark].slice(-MAX_HISTORY_PER_SESSION);
    // Re-inserted, so the Map's iteration order is least-recently-used first.
    this.sessions.delete(sessionId);
    this.sessions.set(sessionId, marks);
    while (this.sessions.size > MAX_HISTORY_SESSIONS) {
      const oldest = this.sessions.keys().next().value;
      if (oldest === undefined) break;
      this.sessions.delete(oldest);
    }
  }

  /**
   * Forgets a session that has ended. Nothing in `wrap` calls it: its one session
   * lives as long as the process. A host that serves many sessions may.
   */
  forget(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}

/** A writer that turns fields plus raw content into a chained, appended record. */
export interface AuditRecorder {
  record(fields: AuditFields, rawContent: string): void;
}

/** What the identity ladder reads (ADR-010). */
export interface IdentityInputs {
  /** `--identity`. Exact. */
  readonly flag?: string | undefined;
  /** `MCPGUARD_IDENTITY`. Exact. */
  readonly env?: string | undefined;
  /**
   * `clientInfo.name` from `initialize`. Heuristic, and only legitimate in the
   * legacy era; the caller passes `undefined` for a modern connection.
   */
  readonly clientName?: string | undefined;
}

/**
 * Walks the ADR-010 ladder: flag, then env, then `clientInfo.name`.
 *
 * The first two are exact because the person who set the proxy up gave the
 * value; `clientInfo` is not, because a client names itself however it likes.
 * Nothing answering means no identity, never a guessed one.
 */
export function resolveIdentity(inputs: IdentityInputs): IdentityResolution {
  // Trimmed, not just checked: a secret mount or env file that leaves a trailing
  // newline must not turn `alice` into `alice\n`, which maps to no role and
  // would let a role-scoped deny rule be skipped while the record says "exact".
  const pick = (value: string | undefined): string | undefined => {
    const trimmed = value?.trim();
    return trimmed === undefined || trimmed === '' ? undefined : trimmed;
  };
  const flag = pick(inputs.flag);
  if (flag !== undefined) return { identity: flag, source: 'flag', exact: true };
  const env = pick(inputs.env);
  if (env !== undefined) return { identity: env, source: 'env', exact: true };
  const client = pick(inputs.clientName);
  if (client !== undefined) {
    // The client picks this string, and it is copied into every record and
    // event, so a name that is huge or that carries line separators or
    // direction controls is refused rather than logged. The record says why.
    if (client.length > MAX_CLIENT_NAME_LENGTH || UNSAFE_CLIENT_NAME.test(client)) {
      return { identity: undefined, source: 'none', exact: false, note: 'client_info_rejected' };
    }
    return { identity: client, source: 'client_info', exact: false };
  }
  return { identity: undefined, source: 'none', exact: false };
}

/**
 * Scans a tool's description, annotations and schema text with the policy's
 * scan settings for that tool. Shared by the `tools/list` gate and `lock`, so
 * the findings pinned to the lock are the ones the gate would have raised.
 */
export function toolScanner(
  deps: Pick<RuntimeDeps, 'policy' | 'compiledPolicy' | 'ruleset' | 'serverName'>,
): (tool: ToolDefinition) => ToolScan {
  return (tool) => {
    const text = describedText(tool);
    if (text === '') return { ruleIds: [], score: 0, action: 'allow' };
    // PII masking is for what the model is shown; here only the rules matter,
    // and the description is forwarded exactly as the server sent it.
    const options: ScanOptions = {
      ...scanOptionsFor(deps.policy, deps.compiledPolicy, deps.serverName, tool.name),
      pii: undefined,
    };
    const verdict = scanContent(
      {
        id: 'tool_description',
        text,
        kind: 'tool_description',
        channel: `${deps.serverName}__${tool.name}`,
      },
      deps.ruleset,
      options,
    );
    return {
      ruleIds: verdict.findings.map((finding) => finding.ruleId),
      score: verdict.score,
      action: verdict.action,
    };
  };
}

/** How many tool names a manifest event lists, and how long each may be. */
const MAX_DIFF_NAMES = 100;
const MAX_DIFF_NAME_LENGTH = 200;

/** The longest `clientInfo.name` accepted as an identity. */
export const MAX_CLIENT_NAME_LENGTH = 128;

/** Control, format (bidi, zero-width) and line/paragraph separator characters. */
const UNSAFE_CLIENT_NAME = /[\p{Cc}\p{Cf}\u2028\u2029]/u;

/** Builds the scan options from the policy for one tool. */
export function scanOptionsFor(
  policy: GuardPolicy,
  compiled: CompiledPolicy,
  serverName: string,
  toolName: string,
  correlationKey?: string | undefined,
): ScanOptions {
  const scan = compiled.scanFor(serverName, toolName);
  // A server may switch masking on or off for itself; what is masked stays the policy's.
  const piiEnabled = policy.servers[serverName]?.pii?.enabled ?? policy.pii.enabled;
  const pii = piiEnabled
    ? {
        recognizers: policy.pii.recognizers,
        strictChecksum: policy.pii.strict_checksum,
        keepLast: policy.pii.keep_last,
        correlationTags: policy.pii.correlation_tags,
        correlationKey,
      }
    : undefined;
  return {
    action: scan.action,
    flagAt: scan.flag_at,
    blockAt: scan.block_at,
    maxBytes: scan.max_bytes,
    onDegraded: scan.on_degraded,
    ...(pii !== undefined ? { pii } : {}),
  };
}

/**
 * The gates the bridge is wired with.
 *
 * Each takes the call's {@link CallContext} last. Without one, the connection's
 * own (`RuntimeDeps.sessionId` and `resolveIdentity`) is used, which is how
 * `wrap` calls them.
 */
export interface GuardGates {
  onCall(
    request: Parameters<Gates<CallContext>['onCall']>[0],
    forward: Parameters<Gates<CallContext>['onCall']>[1],
    context?: CallContext,
  ): ReturnType<Gates<CallContext>['onCall']>;
  onList(
    request: Parameters<Gates<CallContext>['onList']>[0],
    forward: Parameters<Gates<CallContext>['onList']>[1],
    context?: CallContext,
  ): ReturnType<Gates<CallContext>['onList']>;
  onRead(
    request: Parameters<Gates<CallContext>['onRead']>[0],
    forward: Parameters<Gates<CallContext>['onRead']>[1],
    context?: CallContext,
  ): ReturnType<Gates<CallContext>['onRead']>;
  onRequest(
    request: Parameters<Gates<CallContext>['onRequest']>[0],
    forward: Parameters<Gates<CallContext>['onRequest']>[1],
    context?: CallContext,
  ): ReturnType<Gates<CallContext>['onRequest']>;
}

/**
 * Thrown to refuse a request the server's role list does not admit, so the
 * client gets a JSON-RPC error and not an empty list or an empty result. The
 * message is safe to hand to the client: it names the method it sent and nothing
 * about which roles would have been enough.
 */
export class ServerAccessError extends Error {
  constructor(method: string) {
    super(
      `[mcpguard] ${method.slice(0, 64)} refused · the caller holds none of the roles this server admits · check the identity and servers.<name>.roles`,
    );
    this.name = 'ServerAccessError';
  }
}

/**
 * Messages that belong to the connection and not to the server behind it. The SDK
 * answers `initialize` and `ping` itself and they never reach the gates;
 * `server/discover` is the modern era's `initialize`, a client learning what the
 * server is before it names a caller, so it is let through here for the same reason.
 */
const CONNECTION_LEVEL_METHODS: ReadonlySet<string> = new Set([
  'initialize',
  'ping',
  'server/discover',
]);

/** Builds the gates for one server. */
export function buildGates(deps: RuntimeDeps): GuardGates {
  const enforce = deps.policy.mode === 'enforce';

  /** The call's context, or the connection's own when the host passed none. */
  const contextOf = (given: CallContext | undefined): CallContext => {
    if (given !== undefined) return given;
    if (deps.sessionId === undefined || deps.resolveIdentity === undefined) {
      throw new Error('a gate was called without a call context and has no connection of its own');
    }
    return {
      session: { id: deps.sessionId, source: 'connection', exact: deps.sessionExact ?? true },
      identity: deps.resolveIdentity(),
    };
  };

  /** A stderr diagnostic, always carrying the session it is about and how it was resolved. */
  const notify = (call: CallContext, event: string, detail: Record<string, unknown>): void => {
    deps.onEvent(event, {
      session: call.session.id,
      sessionSource: call.session.source,
      sessionExact: call.session.exact,
      ...detail,
    });
  };

  const emit = (
    call: CallContext,
    kind: SecurityEventKind,
    type: SecurityEvent['type'],
    toolName: string | undefined,
    action: string,
    score: number | undefined,
    evidence: readonly string[],
  ): void => {
    deps.telemetry.emit({
      type,
      kind,
      at: deps.clock(),
      sessionId: call.session.id,
      serverName: deps.serverName,
      toolName,
      score,
      action,
      evidence,
      callerIdentity: call.identity,
      sessionSource: call.session.source,
      sessionExact: call.session.exact,
    });
  };

  const contextFor = (toolName: string): GuardContext => ({
    policy: deps.compiledPolicy,
    ruleset: deps.ruleset,
    scanOptions: scanOptionsFor(
      deps.policy,
      deps.compiledPolicy,
      deps.serverName,
      toolName,
      deps.correlationKey,
    ),
    enforce,
  });

  const record = (
    call: CallContext,
    kind: 'tool_call' | 'resource_read' | 'tool_list' | 'access_denied',
    toolName: string | undefined,
    action: string,
    score: number | undefined,
    findings: readonly string[],
    piiKinds: readonly string[],
    masked: string,
    raw: string,
  ): void => {
    // The writer owns the hash chain — it holds the running head and the
    // sequence — so the runtime only supplies the fields and the raw content the
    // fingerprint is computed over.
    deps.audit?.record(
      {
        at: deps.clock(),
        sessionId: call.session.id,
        kind,
        serverName: deps.serverName,
        toolName,
        action,
        score,
        findings,
        piiKinds,
        maskedContent: masked.slice(0, 4_096),
        sessionExact: call.session.exact,
        sessionSource: call.session.source,
        callerIdentity: call.identity,
      },
      raw,
    );
  };

  /**
   * Writes down that the server's role list does not admit this caller, in the
   * three places a refusal goes (stderr, the security event, the audit record).
   * Under `flag` the request still goes ahead and the record says `flag`; the
   * caller refuses on its own when `enforce` is set. `identityExact: false` is a
   * guessed role, not a granted one (ADR-010).
   */
  const reportServerRefusal = (
    call: CallContext,
    method: string,
    subject: string | undefined,
    kind: 'tool_call' | 'resource_read' | 'tool_list' | 'access_denied',
    rule: string | undefined,
  ): void => {
    const action = enforce ? 'deny' : 'flag';
    const caller = call.identity;
    const named = subject?.slice(0, MAX_DIFF_NAME_LENGTH);
    notify(call, 'access_denied', {
      method,
      ...(method === 'tools/call' && named !== undefined ? { tool: named } : {}),
      ...(method === 'resources/read' && named !== undefined ? { resource: named } : {}),
      rule,
      action,
      identity: caller.identity,
      identitySource: caller.source,
      identityExact: caller.exact,
    });
    emit(call, 'access_denied', 'policy_decision', named, action, undefined, [rule ?? '']);
    record(call, kind, named, action, undefined, [rule ?? ''], [], '', '');
  };

  /**
   * Asks the server's role list about one request that is not a `tools/call`.
   * True when it must be refused; under `flag` it is reported and goes ahead.
   */
  const serverRefuses = (
    call: CallContext,
    method: string,
    subject: string | undefined,
    kind: 'resource_read' | 'tool_list' | 'access_denied',
  ): boolean => {
    const access = evaluateServerAccess(
      deps.compiledPolicy,
      deps.serverName,
      call.identity.identity,
    );
    if (!access.refused) return false;
    reportServerRefusal(call, method, subject, kind, access.matchedRule);
    return enforce;
  };

  const scanTool = toolScanner(deps);

  const rules = deps.compiledPolicy.combinations;
  const history =
    rules.length === 0
      ? undefined
      : (deps.history ??
        new CombinationHistory(Math.max(...rules.map((combination) => combination.rule.window))));

  /**
   * Checks one call that access control has let through against the combination
   * rules, and says whether it must be refused.
   *
   * The call is tried as the newest entry of the session's history, and only a
   * rule whose evidence includes *this* call counts: a rule satisfied earlier
   * (and let through under `flag`) must not fire again on an unrelated call.
   * `evaluateCombinations` prefers the earliest call it can assign to a glob, so
   * the call under test is handed over first: whenever any complete assignment
   * uses it, it is in the evidence.
   *
   * A refused call is not remembered, because it did not happen.
   */
  const checkCombinations = (toolName: string, call: CallContext): boolean => {
    if (history === undefined) return false;
    const caller = call.identity;
    const now = deps.clock();
    if (toolName.length > MAX_TRACKED_NAME_LENGTH) {
      // A name this long cannot be remembered, and clipping it would let a
      // suffix glob be dodged, so the call is judged on what the rules would have
      // done: refused if one of them denies, otherwise let through and reported.
      const refused = enforce && rules.some((combination) => combination.rule.action === 'deny');
      const action = refused ? 'deny' : 'flag';
      notify(call, 'combination_detected', {
        tool: toolName.slice(0, MAX_DIFF_NAME_LENGTH),
        rule: 'combination.name_too_long',
        action,
        length: toolName.length,
        identity: caller.identity,
        identitySource: caller.source,
        identityExact: caller.exact,
      });
      emit(
        call,
        'combination_detected',
        'policy_decision',
        toolName.slice(0, MAX_DIFF_NAME_LENGTH),
        action,
        undefined,
        ['combination.name_too_long'],
      );
      record(
        call,
        'tool_call',
        toolName.slice(0, MAX_DIFF_NAME_LENGTH),
        action,
        undefined,
        ['combination.name_too_long'],
        [],
        JSON.stringify({ reason: 'name_too_long', length: toolName.length }),
        '',
      );
      return refused;
    }
    const mark: CallMark = {
      serverName: deps.serverName,
      // Whole, not clipped: the globs are matched against it, and a clipped name
      // would lose the suffix a pattern like `*_upload` is written for.
      toolName,
      at: now,
    };
    const hits = evaluateCombinations(
      deps.compiledPolicy,
      [mark, ...history.recent(call.session.id, now)],
      now,
    ).filter((hit) => hit.evidence.includes(mark));
    if (hits.length === 0) {
      history.record(call.session.id, mark);
      return false;
    }
    const refused = enforce && hits.some((hit) => hit.action === 'deny');
    // Clipped for what is written out, never for what is matched.
    const matched = (evidence: readonly CallMark[]): string[] =>
      evidence.map((entry) =>
        toolKey(entry.serverName, entry.toolName).slice(0, MAX_DIFF_NAME_LENGTH),
      );
    for (const hit of hits) {
      const action = enforce && hit.action === 'deny' ? 'deny' : 'flag';
      notify(call, 'combination_detected', {
        tool: toolName,
        rule: hit.id,
        action,
        matched: matched(hit.evidence),
        note: hit.note,
        identity: caller.identity,
        identitySource: caller.source,
        identityExact: caller.exact,
      });
      emit(call, 'combination_detected', 'policy_decision', toolName, action, undefined, [
        hit.id,
        ...matched(hit.evidence),
      ]);
    }
    // Rule ids and the tool names that satisfied them; never what the calls carried (ADR-004).
    record(
      call,
      'tool_call',
      toolName,
      refused ? 'deny' : 'flag',
      undefined,
      hits.map((hit) => hit.id),
      [],
      JSON.stringify({
        combinations: hits.map((hit) => ({ rule: hit.id, matched: matched(hit.evidence) })),
      }),
      '',
    );
    if (!refused) history.record(call.session.id, mark);
    return refused;
  };

  const reportManifest = (event: ManifestEvent, given: CallContext | undefined): void => {
    const call = contextOf(given);
    switch (event.kind) {
      case 'pinned':
        notify(call, 'manifest_pinned', {
          server: deps.serverName,
          tools: event.toolCount,
          lock: deps.lock?.path,
        });
        record(
          call,
          'tool_list',
          undefined,
          'allow',
          undefined,
          [],
          [],
          `pinned ${event.toolCount}`,
          '',
        );
        return;
      case 'description_flagged':
        notify(call, 'injection_detected', {
          surface: 'tool_description',
          tool: event.tool,
          action: 'flag',
          score: event.score,
          rules: event.ruleIds,
        });
        emit(
          call,
          'injection_detected',
          'security_event',
          event.tool,
          'flag',
          event.score,
          event.ruleIds,
        );
        record(call, 'tool_list', event.tool, 'flag', event.score, event.ruleIds, [], '', '');
        return;
      case 'mismatch': {
        const diff = event.diff;
        const evidence = [
          `manifest.${event.reason}`,
          ...(diff !== undefined && diff.altered.length > 0 ? ['manifest.altered'] : []),
          ...(diff !== undefined && diff.added.length > 0 ? ['manifest.added'] : []),
          ...(diff !== undefined && diff.removed.length > 0 ? ['manifest.removed'] : []),
        ];
        // The names are the server's words: JSON-encoded here, never interpolated
        // into a line a terminal or a log viewer will interpret.
        const names = (list: readonly string[] | undefined): string[] | undefined =>
          list?.slice(0, MAX_DIFF_NAMES).map((name) => name.slice(0, MAX_DIFF_NAME_LENGTH));
        const detail = {
          server: deps.serverName,
          action: event.action,
          reason: event.reason,
          altered: names(diff?.altered),
          added: names(diff?.added),
          removed: names(diff?.removed),
          detail: event.detail,
          lock: deps.lock?.path,
        };
        notify(call, 'manifest_mismatch', detail);
        emit(
          call,
          'manifest_mismatch',
          'security_event',
          undefined,
          event.action,
          undefined,
          evidence,
        );
        record(
          call,
          'tool_list',
          undefined,
          event.action === 'halt' ? 'block' : 'flag',
          undefined,
          evidence,
          [],
          JSON.stringify({ altered: detail.altered, added: detail.added, removed: detail.removed }),
          '',
        );
        return;
      }
    }
  };

  const manifest =
    deps.lock !== undefined && deps.policy.lock.enabled
      ? createManifestGate<CallContext | undefined>({
          serverName: deps.serverName,
          onFirstUse: deps.policy.lock.on_first_use,
          onMismatch: deps.policy.lock.on_mismatch,
          store: deps.lock,
          scanTool,
          report: reportManifest,
          // Two callers paging through the list at once must not read each
          // other's pages as their own; one walk per session.
          walkKey: (given) => given?.session.id ?? '',
          stateKey: (given) => given?.upstream ?? given?.connection ?? '',
          connectionKey: (given) => given?.connection ?? '',
          fetchTools: async (given) => {
            const listTools = given?.listTools ?? deps.fetchTools;
            if (listTools === undefined) throw new Error('no way to list the upstream tools');
            return listTools();
          },
        })
      : undefined;

  return {
    onCall: async (request, forward, given) => {
      const call = contextOf(given);
      const toolName = String(request.params?.name ?? 'unknown');
      // The caller's identity, not the session id: a ULID is minted per
      // connection and no role mapping can ever name it (ADR-010).
      const caller = call.identity;
      const access = guardCall(contextFor(toolName), deps.serverName, toolName, caller.identity);
      // First, before the manifest gate: a caller the server does not admit must
      // not be able to make the proxy read the upstream or touch the lock.
      if (access.refusedByServer) {
        reportServerRefusal(call, 'tools/call', toolName, 'tool_call', access.matchedRule);
        if (enforce) return blockedResult('deny', 0, deps.ruleset.rulesetVersion) as never;
      }
      // A list the gate refused leaves no open door: the call is refused too,
      // until a later `tools/list` passes. Not downgraded in observe mode, for
      // the same reason the list is not: `lock.on_mismatch` is the operator's
      // explicit word on what a changed manifest means.
      const refused = await manifest?.callGuard(call);
      if (refused !== undefined) {
        notify(call, 'manifest_call_refused', {
          server: deps.serverName,
          tool: toolName,
          reason: refused.reason,
        });
        record(
          call,
          'tool_call',
          toolName,
          'deny',
          undefined,
          [`manifest.${refused.reason}`],
          [],
          '',
          '',
        );
        throw refused;
      }
      if (access.action === 'deny' && enforce) {
        notify(call, 'access_denied', {
          tool: toolName,
          rule: access.matchedRule,
          action: 'deny',
          identity: caller.identity,
          identitySource: caller.source,
          identityExact: caller.exact,
        });
        emit(call, 'access_denied', 'policy_decision', toolName, 'deny', undefined, [
          access.matchedRule ?? '',
        ]);
        record(
          call,
          'tool_call',
          toolName,
          'deny',
          undefined,
          [access.matchedRule ?? ''],
          [],
          '',
          '',
        );
        return blockedResult('deny', 0, deps.ruleset.rulesetVersion) as never;
      }
      if (checkCombinations(toolName, call)) {
        return blockedResult('deny', 0, deps.ruleset.rulesetVersion) as never;
      }
      const upstream = await forward();
      const guarded = guardResult(contextFor(toolName), deps.serverName, toolName, upstream);
      const findings = guarded.verdicts.flatMap((v) => v.findings.map((f) => f.ruleId));
      const piiKinds = guarded.verdicts.flatMap((v) => v.piiFindings.map((f) => f.kind));
      const score = Math.max(0, ...guarded.verdicts.map((v) => v.score));
      if (guarded.action !== 'allow') {
        notify(call, 'injection_detected', { tool: toolName, action: guarded.action, score });
        emit(
          call,
          'injection_detected',
          'security_event',
          toolName,
          guarded.action,
          score,
          findings,
        );
      }
      if (piiKinds.length > 0)
        emit(call, 'pii_masked', 'security_event', toolName, guarded.action, undefined, piiKinds);
      const maskedText = guarded.verdicts.map((v) => v.text).join('\n');
      record(
        call,
        'tool_call',
        toolName,
        guarded.action,
        score,
        findings,
        piiKinds,
        maskedText,
        rawTextOf(upstream),
      );
      if (guarded.action === 'block') {
        return blockedResult('block', findings.length, deps.ruleset.rulesetVersion) as never;
      }
      return guarded.result as never;
    },
    onList: async (request, forward, given) => {
      const call = contextOf(given);
      if (serverRefuses(call, 'tools/list', undefined, 'tool_list')) {
        throw new ServerAccessError('tools/list');
      }
      return manifest !== undefined ? manifest.onList(request, forward, call) : forward();
    },
    onRequest: async (request, forward, given) => {
      if (!CONNECTION_LEVEL_METHODS.has(request.method)) {
        const call = contextOf(given);
        if (serverRefuses(call, request.method, request.method, 'access_denied')) {
          throw new ServerAccessError(request.method);
        }
      }
      return forward();
    },
    onRead: async (request, forward, given) => {
      const call = contextOf(given);
      const uri = String(request.params?.uri ?? 'unknown');
      if (serverRefuses(call, 'resources/read', uri, 'resource_read')) {
        throw new ServerAccessError('resources/read');
      }
      const upstream = await forward();
      const guarded = guardResource(contextFor(uri), deps.serverName, uri, upstream);
      const findings = guarded.verdicts.flatMap((v) => v.findings.map((f) => f.ruleId));
      const piiKinds = guarded.verdicts.flatMap((v) => v.piiFindings.map((f) => f.kind));
      const score = Math.max(0, ...guarded.verdicts.map((v) => v.score));
      if (guarded.action !== 'allow') {
        notify(call, 'injection_detected', { resource: uri, action: guarded.action, score });
      }
      record(
        call,
        'resource_read',
        uri,
        guarded.action,
        score,
        findings,
        piiKinds,
        guarded.verdicts.map((v) => v.text).join('\n'),
        rawTextOf(upstream),
      );
      if (guarded.action === 'block') {
        return blockedResult('block', findings.length, deps.ruleset.rulesetVersion) as never;
      }
      return guarded.result as never;
    },
  };
}

/**
 * The upstream result's text blocks as the server sent them, unmasked.
 *
 * This is what the audit fingerprint is computed over (ADR-004). It is the
 * fingerprint's input only: the record never stores it, and it is dropped as
 * soon as the HMAC is taken. Hashing anything derived from the masked text, or
 * a byte count, would make the fingerprint useless for the one thing it is for,
 * which is telling whether two records saw the same raw content.
 */
function rawTextOf(upstream: Parameters<typeof extractText>[0]): string {
  return extractText(upstream)
    .map((block) => block.text)
    .join('\n');
}
