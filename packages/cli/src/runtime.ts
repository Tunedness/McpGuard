/**
 * Turning a policy and a ruleset into the guard gates the proxy calls.
 *
 * The host builds this once per connection: it resolves scan options from the
 * policy, wires the access decision and the content scan into the three gates,
 * and threads the session id and the audit sink through. The proxy knows the
 * gates turn a request into a result; this is where they learn how.
 */
import type {
  AuditFields,
  CompiledPolicy,
  GuardPolicy,
  IdentityResolution,
  SecurityEvent,
  SecurityEventKind,
  TelemetrySink,
} from '@mcpguard/core';
import type { CompiledRuleset, ScanOptions } from '@mcpguard/detect';
import {
  blockedResult,
  extractText,
  type Gates,
  type GuardContext,
  guardCall,
  guardResource,
  guardResult,
} from '@mcpguard/proxy';

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
  readonly clock: () => number;
  /** Reports a security event to stderr diagnostics. */
  readonly onEvent: (event: string, detail: Record<string, unknown>) => void;
  /** The OTLP sink, off by default. */
  readonly telemetry: TelemetrySink;
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
    kind: 'tool_call' | 'resource_read',
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

  return {
    onCall: async (request, forward) => {
      const toolName = String(request.params?.name ?? 'unknown');
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
    onList: async (_request, forward) => forward(),
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
