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
  type GuardPolicy,
  type IdentityResolution,
  type SecurityEvent,
  type SecurityEventKind,
  type TelemetrySink,
  type ToolDefinition,
  toolKey,
} from '@mcpguard/core';
import type { CompiledRuleset, ScanOptions } from '@mcpguard/detect';
import { scanContent } from '@mcpguard/detect';
import {
  blockedResult,
  extractText,
  type Gates,
  type GuardContext,
  guardCall,
  guardResource,
  guardResult,
} from '@mcpguard/proxy';
import type { LockStore } from './lock-file.js';
import {
  createManifestGate,
  describedText,
  type ManifestEvent,
  type ToolScan,
} from './manifest-gate.js';

/** What the host injects to build the gates. */
export interface RuntimeDeps {
  readonly policy: GuardPolicy;
  readonly compiledPolicy: CompiledPolicy;
  readonly ruleset: CompiledRuleset;
  readonly serverName: string;
  readonly sessionId: string;
  readonly sessionExact: boolean;
  /**
   * Who the caller is, asked per call: the `clientInfo` rung is only known once
   * the client has initialised, so it cannot be fixed when the gates are built.
   */
  readonly resolveIdentity: () => IdentityResolution;
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
   * lives as long as the process. The HTTP gateway (Faz 18) will, when a session ends.
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
  const pii = policy.pii.enabled
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

/** The gates the bridge is wired with. */
export function buildGates(deps: RuntimeDeps): Gates {
  const enforce = deps.policy.mode === 'enforce';

  const emit = (
    kind: SecurityEventKind,
    type: SecurityEvent['type'],
    toolName: string | undefined,
    action: string,
    score: number | undefined,
    evidence: readonly string[],
    callerIdentity: IdentityResolution,
  ): void => {
    deps.telemetry.emit({
      type,
      kind,
      at: deps.clock(),
      sessionId: deps.sessionId,
      serverName: deps.serverName,
      toolName,
      score,
      action,
      evidence,
      callerIdentity,
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
    kind: 'tool_call' | 'resource_read' | 'tool_list',
    toolName: string | undefined,
    action: string,
    score: number | undefined,
    findings: readonly string[],
    piiKinds: readonly string[],
    masked: string,
    raw: string,
    callerIdentity: IdentityResolution,
  ): void => {
    // The writer owns the hash chain — it holds the running head and the
    // sequence — so the runtime only supplies the fields and the raw content the
    // fingerprint is computed over.
    deps.audit?.record(
      {
        at: deps.clock(),
        sessionId: deps.sessionId,
        kind,
        serverName: deps.serverName,
        toolName,
        action,
        score,
        findings,
        piiKinds,
        maskedContent: masked.slice(0, 4_096),
        sessionExact: deps.sessionExact,
        callerIdentity,
      },
      raw,
    );
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
  const checkCombinations = (toolName: string, caller: IdentityResolution): boolean => {
    if (history === undefined) return false;
    const now = deps.clock();
    if (toolName.length > MAX_TRACKED_NAME_LENGTH) {
      // A name this long cannot be remembered, and clipping it would let a
      // suffix glob be dodged, so the call is judged on what the rules would have
      // done: refused if one of them denies, otherwise let through and reported.
      const refused = enforce && rules.some((combination) => combination.rule.action === 'deny');
      const action = refused ? 'deny' : 'flag';
      deps.onEvent('combination_detected', {
        tool: toolName.slice(0, MAX_DIFF_NAME_LENGTH),
        rule: 'combination.name_too_long',
        action,
        length: toolName.length,
        identity: caller.identity,
        identitySource: caller.source,
        identityExact: caller.exact,
      });
      emit(
        'combination_detected',
        'policy_decision',
        toolName.slice(0, MAX_DIFF_NAME_LENGTH),
        action,
        undefined,
        ['combination.name_too_long'],
        caller,
      );
      record(
        'tool_call',
        toolName.slice(0, MAX_DIFF_NAME_LENGTH),
        action,
        undefined,
        ['combination.name_too_long'],
        [],
        JSON.stringify({ reason: 'name_too_long', length: toolName.length }),
        '',
        caller,
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
      [mark, ...history.recent(deps.sessionId, now)],
      now,
    ).filter((hit) => hit.evidence.includes(mark));
    if (hits.length === 0) {
      history.record(deps.sessionId, mark);
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
      deps.onEvent('combination_detected', {
        tool: toolName,
        rule: hit.id,
        action,
        matched: matched(hit.evidence),
        note: hit.note,
        identity: caller.identity,
        identitySource: caller.source,
        identityExact: caller.exact,
      });
      emit(
        'combination_detected',
        'policy_decision',
        toolName,
        action,
        undefined,
        [hit.id, ...matched(hit.evidence)],
        caller,
      );
    }
    // Rule ids and the tool names that satisfied them; never what the calls carried (ADR-004).
    record(
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
      caller,
    );
    if (!refused) history.record(deps.sessionId, mark);
    return refused;
  };

  const reportManifest = (event: ManifestEvent): void => {
    const caller = deps.resolveIdentity();
    switch (event.kind) {
      case 'pinned':
        deps.onEvent('manifest_pinned', {
          server: deps.serverName,
          tools: event.toolCount,
          lock: deps.lock?.path,
        });
        record(
          'tool_list',
          undefined,
          'allow',
          undefined,
          [],
          [],
          `pinned ${event.toolCount}`,
          '',
          caller,
        );
        return;
      case 'description_flagged':
        deps.onEvent('injection_detected', {
          surface: 'tool_description',
          tool: event.tool,
          action: 'flag',
          score: event.score,
          rules: event.ruleIds,
        });
        emit(
          'injection_detected',
          'security_event',
          event.tool,
          'flag',
          event.score,
          event.ruleIds,
          caller,
        );
        record('tool_list', event.tool, 'flag', event.score, event.ruleIds, [], '', '', caller);
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
        deps.onEvent('manifest_mismatch', detail);
        emit(
          'manifest_mismatch',
          'security_event',
          undefined,
          event.action,
          undefined,
          evidence,
          caller,
        );
        record(
          'tool_list',
          undefined,
          event.action === 'halt' ? 'block' : 'flag',
          undefined,
          evidence,
          [],
          JSON.stringify({ altered: detail.altered, added: detail.added, removed: detail.removed }),
          '',
          caller,
        );
        return;
      }
    }
  };

  const manifest =
    deps.lock !== undefined && deps.policy.lock.enabled
      ? createManifestGate({
          serverName: deps.serverName,
          onFirstUse: deps.policy.lock.on_first_use,
          onMismatch: deps.policy.lock.on_mismatch,
          store: deps.lock,
          scanTool,
          report: reportManifest,
          fetchTools: deps.fetchTools,
        })
      : undefined;

  return {
    onCall: async (request, forward) => {
      const toolName = String(request.params?.name ?? 'unknown');
      // A list the gate refused leaves no open door: the call is refused too,
      // until a later `tools/list` passes. Not downgraded in observe mode, for
      // the same reason the list is not: `lock.on_mismatch` is the operator's
      // explicit word on what a changed manifest means.
      const refused = await manifest?.callGuard();
      if (refused !== undefined) {
        const caller = deps.resolveIdentity();
        deps.onEvent('manifest_call_refused', {
          server: deps.serverName,
          tool: toolName,
          reason: refused.reason,
        });
        record(
          'tool_call',
          toolName,
          'deny',
          undefined,
          [`manifest.${refused.reason}`],
          [],
          '',
          '',
          caller,
        );
        throw refused;
      }
      // The caller's identity, not the session id: a ULID is minted per
      // connection and no role mapping can ever name it (ADR-010).
      const caller = deps.resolveIdentity();
      const access = guardCall(contextFor(toolName), deps.serverName, toolName, caller.identity);
      if (access.action === 'deny' && enforce) {
        deps.onEvent('access_denied', {
          tool: toolName,
          rule: access.matchedRule,
          identity: caller.identity,
          identitySource: caller.source,
          identityExact: caller.exact,
        });
        emit(
          'access_denied',
          'policy_decision',
          toolName,
          'deny',
          undefined,
          [access.matchedRule ?? ''],
          caller,
        );
        record(
          'tool_call',
          toolName,
          'deny',
          undefined,
          [access.matchedRule ?? ''],
          [],
          '',
          '',
          caller,
        );
        return blockedResult('deny', 0, deps.ruleset.rulesetVersion) as never;
      }
      if (checkCombinations(toolName, caller)) {
        return blockedResult('deny', 0, deps.ruleset.rulesetVersion) as never;
      }
      const upstream = await forward();
      const guarded = guardResult(contextFor(toolName), deps.serverName, toolName, upstream);
      const findings = guarded.verdicts.flatMap((v) => v.findings.map((f) => f.ruleId));
      const piiKinds = guarded.verdicts.flatMap((v) => v.piiFindings.map((f) => f.kind));
      const score = Math.max(0, ...guarded.verdicts.map((v) => v.score));
      if (guarded.action !== 'allow') {
        deps.onEvent('injection_detected', { tool: toolName, action: guarded.action, score });
        emit(
          'injection_detected',
          'security_event',
          toolName,
          guarded.action,
          score,
          findings,
          caller,
        );
      }
      if (piiKinds.length > 0)
        emit('pii_masked', 'security_event', toolName, guarded.action, undefined, piiKinds, caller);
      const maskedText = guarded.verdicts.map((v) => v.text).join('\n');
      record(
        'tool_call',
        toolName,
        guarded.action,
        score,
        findings,
        piiKinds,
        maskedText,
        rawTextOf(upstream),
        caller,
      );
      if (guarded.action === 'block') {
        return blockedResult('block', findings.length, deps.ruleset.rulesetVersion) as never;
      }
      return guarded.result as never;
    },
    onList: async (request, forward) =>
      manifest !== undefined ? manifest.onList(request, forward) : forward(),
    onRead: async (request, forward) => {
      const uri = String(request.params?.uri ?? 'unknown');
      const caller = deps.resolveIdentity();
      const upstream = await forward();
      const guarded = guardResource(contextFor(uri), deps.serverName, uri, upstream);
      const findings = guarded.verdicts.flatMap((v) => v.findings.map((f) => f.ruleId));
      const piiKinds = guarded.verdicts.flatMap((v) => v.piiFindings.map((f) => f.kind));
      const score = Math.max(0, ...guarded.verdicts.map((v) => v.score));
      if (guarded.action !== 'allow') {
        deps.onEvent('injection_detected', { resource: uri, action: guarded.action, score });
      }
      record(
        'resource_read',
        uri,
        guarded.action,
        score,
        findings,
        piiKinds,
        guarded.verdicts.map((v) => v.text).join('\n'),
        rawTextOf(upstream),
        caller,
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
