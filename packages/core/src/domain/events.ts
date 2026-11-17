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
  | 'server_unmatched'
  | 'scan_degraded'
  | 'audit_checkpoint'
  | 'judge_unavailable';

/**
 * Which rung of the identity ladder answered (ADR-010, ADR-011).
 *
 * `token` is the HTTP gateway's: a static bearer token mapped to an identity in
 * the policy. It is exact, because the operator wrote the mapping.
 */
export type IdentitySource = 'flag' | 'env' | 'client_info' | 'token' | 'none';

/**
 * Which rung of the session ladder answered (ADR-006).
 *
 * `connection` is `wrap`'s: one child process is one connection is one session.
 * The other four are the HTTP ladder, top to bottom; only `client-address` is a
 * guess.
 */
export type SessionSource =
  | 'traceparent'
  | 'baggage'
  | 'mcp-session-id'
  | 'client-address'
  | 'connection';

/**
 * Who the caller was taken to be, and how sure the answer is (ADR-010).
 *
 * `flag` and `env` are exact: the person who set the proxy up supplied the
 * value. `client_info` is a heuristic: a client names itself however it likes.
 * `none` means nothing answered, so no roles are granted.
 */
export interface IdentityResolution {
  readonly identity: string | undefined;
  readonly source: IdentitySource;
  readonly exact: boolean;
  /** Why a rung that spoke was not used, e.g. `client_info_rejected`. */
  readonly note?: string | undefined;
}

/** What the judge's answer did to the decision (ADR-012). */
export type JudgeEffect = 'none' | 'raised_to_flag' | 'raised_to_block';

/**
 * What the judge said about one scanned item, with the inputs `applyJudge` needs
 * to reproduce what it did to that item: the item's own tier-1 score and action.
 */
export interface JudgeItemRecord {
  /** The item's tier-1 score, 0-100. Not the call's: a call can carry several items. */
  readonly score: number;
  /** What tier 1 decided for this item, before any observe-mode downgrade. */
  readonly tier1Action: 'allow' | 'flag' | 'strip' | 'block';
  readonly outcome: 'injection' | 'benign' | 'timeout' | 'error' | 'skipped';
  /** The error or skip code, when `outcome` is one of those. */
  readonly reason?: string | undefined;
  readonly confidence?: number | undefined;
  /** What the judge's answer did to this item, as `applyJudge` computes it. */
  readonly effect: JudgeEffect;
}

/**
 * The judge's answer, as a recorded input (ADR-012 item 8).
 *
 * Only enums, integers and the model's name: the judge's own words never reach a
 * record, because the model's output is attacker-influenced text a terminal or a
 * SIEM would otherwise be asked to render. The final decision is a pure function
 * of the tier-1 verdict and this, so an auditor can reproduce it from the record.
 *
 * A call can carry several scanned items. The record's own `score`, `tier1Action`,
 * `outcome` and `effect` describe **one** of them: the item whose judge answer set
 * the call's action when it did, otherwise one the judge moved, otherwise one it
 * answered. When more than one item was judged, `items` lists every one of them
 * (the headline item among them), each with its own score and action. An auditor
 * replays `items` when it is there and this record itself when it is not, and takes
 * the worst of those results and the call-level `tier1Action`.
 */
export interface JudgeRecord extends JudgeItemRecord {
  readonly adapter: string;
  readonly model: string;
  readonly modelRevision?: string | undefined;
  readonly latencyMs: number;
  readonly truncated: boolean;
  readonly cached: boolean;
  /** Every judged item, only when there was more than one. */
  readonly items?: readonly JudgeItemRecord[] | undefined;
}

/**
 * The W3C trace context a call arrived with: the caller's trace and the span that
 * made the call (`traceparent`'s trace-id and parent-id), lower-case hex.
 *
 * It rides on an event so a collector can put McpGuard's records in the same
 * trace as the caller's. It is a correlation handle, never a credential: it
 * changes nothing about what is decided.
 */
export interface TraceContext {
  /** 32 lower-case hex digits, not all zero. */
  readonly traceId: string;
  /** 16 lower-case hex digits, not all zero. */
  readonly spanId: string;
}

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
  /** The resolved caller identity, when the event is about a call (ADR-010). */
  readonly callerIdentity?: IdentityResolution | undefined;
  /** Which rung resolved `sessionId`, and whether that answer is exact (ADR-006). */
  readonly sessionSource?: SessionSource | undefined;
  readonly sessionExact?: boolean | undefined;
  /** The caller's trace context, when the call carried a valid `traceparent`. */
  readonly trace?: TraceContext | undefined;
  /** The judge's part in this event, when the judge was asked (ADR-012). */
  readonly judge?: Pick<JudgeRecord, 'model' | 'outcome' | 'effect'> | undefined;
}
