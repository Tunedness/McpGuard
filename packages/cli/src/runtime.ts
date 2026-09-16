/**
 * Turning a policy and a ruleset into the guard gates the proxy calls.
 *
 * The host builds this once per connection: it resolves scan options from the
 * policy, wires the access decision and the content scan into the three gates,
 * and threads the session id and the audit sink through. The proxy knows the
 * gates turn a request into a result; this is where they learn how.
 */
import type { AuditFields, CompiledPolicy, GuardPolicy } from '@mcpguard/core';
import type { CompiledRuleset, ScanOptions } from '@mcpguard/detect';
import {
  blockedResult,
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
  /** The chained audit writer, or undefined when auditing is off. */
  readonly audit: AuditRecorder | undefined;
  readonly clock: () => number;
  /** Reports a security event to stderr diagnostics. */
  readonly onEvent: (event: string, detail: Record<string, unknown>) => void;
}

/** A writer that turns fields plus raw content into a chained, appended record. */
export interface AuditRecorder {
  record(fields: AuditFields, rawContent: string): void;
}

/** Builds the scan options from the policy for one tool. */
export function scanOptionsFor(
  policy: GuardPolicy,
  compiled: CompiledPolicy,
  serverName: string,
  toolName: string,
): ScanOptions {
  const scan = compiled.scanFor(serverName, toolName);
  const pii = policy.pii.enabled
    ? {
        recognizers: policy.pii.recognizers,
        strictChecksum: policy.pii.strict_checksum,
        keepLast: policy.pii.keep_last,
        correlationTags: policy.pii.correlation_tags,
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

  const contextFor = (toolName: string): GuardContext => ({
    policy: deps.compiledPolicy,
    ruleset: deps.ruleset,
    scanOptions: scanOptionsFor(deps.policy, deps.compiledPolicy, deps.serverName, toolName),
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
      },
      raw,
    );
  };

  return {
    onCall: async (request, forward) => {
      const toolName = String(request.params?.name ?? 'unknown');
      const access = guardCall(contextFor(toolName), deps.serverName, toolName, deps.sessionId);
      if (access.action === 'deny' && enforce) {
        deps.onEvent('access_denied', { tool: toolName, rule: access.matchedRule });
        record('tool_call', toolName, 'deny', undefined, [access.matchedRule ?? ''], [], '', '');
        return blockedResult('deny', 0, deps.ruleset.rulesetVersion) as never;
      }
      const upstream = await forward();
      const guarded = guardResult(contextFor(toolName), deps.serverName, toolName, upstream);
      const findings = guarded.verdicts.flatMap((v) => v.findings.map((f) => f.ruleId));
      const piiKinds = guarded.verdicts.flatMap((v) => v.piiFindings.map((f) => f.kind));
      const score = Math.max(0, ...guarded.verdicts.map((v) => v.score));
      if (guarded.action !== 'allow') {
        deps.onEvent('injection_detected', { tool: toolName, action: guarded.action, score });
      }
      const maskedText = guarded.verdicts.map((v) => v.text).join('\n');
      const rawText = guarded.verdicts.map((v) => v.totalBytes).join(',');
      record('tool_call', toolName, guarded.action, score, findings, piiKinds, maskedText, rawText);
      if (guarded.action === 'block') {
        return blockedResult('block', findings.length, deps.ruleset.rulesetVersion) as never;
      }
      return guarded.result as never;
    },
    onList: async (_request, forward) => forward(),
    onRead: async (request, forward) => {
      const uri = String(request.params?.uri ?? 'unknown');
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
        '',
      );
      if (guarded.action === 'block') {
        return blockedResult('block', findings.length, deps.ruleset.rulesetVersion) as never;
      }
      return guarded.result as never;
    },
  };
}
