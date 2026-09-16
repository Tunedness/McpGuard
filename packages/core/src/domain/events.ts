/**
 * The events McpGuard emits, and the two names it is allowed to emit them under.
 *
 * The umbrella's telemetry decision (Tunedness ADR-003) partitions five event
 * types across the platform's tools. `security_event` is this tool's, and the
 * sibling tool has a test that fails its build if the string appears in its
 * source at all. The reverse holds here: `loop_detection` and `budget_event`
 * are AgentFuse's, and nothing in this package produces one.
 */

/** What happened, in the shared `tunedness.*` vocabulary. */
export type EventType = 'security_event' | 'policy_decision';

/** Why a call or a piece of content was treated the way it was. */
export type SecurityEventKind =
  | 'injection_detected'
  | 'pii_masked'
  | 'manifest_mismatch'
  | 'access_denied'
  | 'combination_detected'
  | 'scan_degraded'
  | 'audit_checkpoint';

/** One emitted event. Attribute encoding is the sink's business, not the engine's. */
export interface SecurityEvent {
  readonly type: EventType;
  readonly kind: SecurityEventKind;
  /** From the injected clock, so a replay reproduces it. */
  readonly at: number;
  readonly sessionId: string;
  readonly serverName: string;
  readonly toolName: string | undefined;
  /** 0–100, integer. Absent for events that are not the scanner's. */
  readonly score: number | undefined;
  /** What was actually done about it. */
  readonly action: string;
  /** Rule or recogniser ids, for correlation. Never content. */
  readonly evidence: readonly string[];
}
