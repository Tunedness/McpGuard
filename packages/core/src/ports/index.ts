/**
 * Every edge of the engine, expressed as an interface.
 *
 * `@tunedness/mcpguard-core` performs no I/O and reads no ambient state. Time, identity,
 * persistence, telemetry and the audit key all arrive through these ports.
 *
 * For a security proxy that is not an aesthetic preference. The product's
 * central claim is that a decision it made six months ago can be reproduced by
 * whoever audits it, and a decision that read a clock, a file or an environment
 * variable cannot be. Ports are what make the whole engine replayable under a
 * fake clock — which is also what makes the benchmark corpus meaningful,
 * because it runs through the real engine rather than a model of it.
 *
 * All of these are frozen as of phase 2, so the scanner, the proxy and the CLI
 * can be built against them in parallel.
 */
import type { SecurityEvent } from '../domain/events.js';

/** Where "now" comes from. Milliseconds since the epoch. */
export interface Clock {
  now(): number;
}

/** Where identifiers come from. Monotonic and sortable, so ULIDs in practice. */
export interface IdGenerator {
  next(): string;
}

/**
 * The secret that fingerprints raw content in an audit record.
 *
 * Separate from a plain string parameter so the key can be absent in a
 * deployment that has not configured one, and so no call site can accidentally
 * log it by having it in scope as ordinary data.
 */
export interface AuditKey {
  /** Returns the HMAC key, or `undefined` when none is configured. */
  value(): string | undefined;
}

/**
 * Where audit records go.
 *
 * Synchronous on purpose: this sits on the hot path of every guarded call, and
 * an `await` here would put the proxy's added latency at the mercy of a disk.
 * The CLI's implementation buffers and flushes; the ordering guarantee the hash
 * chain needs is the caller's, not the sink's.
 */
export interface AuditSink {
  /** Appends one record. The record already carries its chain link. */
  append(record: string): void;
  /** Publishes the running chain head outside the file. */
  checkpoint(digest: string, sequence: number): void;
}

/** Where security events go when telemetry is on. A no-op sink when it is off. */
export interface TelemetrySink {
  emit(event: SecurityEvent): void;
}

/** The full set of ports the engine depends on. */
export interface Ports {
  readonly clock: Clock;
  readonly ids: IdGenerator;
  readonly auditKey: AuditKey;
  readonly audit: AuditSink;
  readonly telemetry: TelemetrySink;
}

/**
 * What the tier-2 judge is asked about one content item (ADR-012).
 *
 * The text is what the model is shown, so it is the item **after** PII masking
 * and **before** strip: a masked identity never leaves the proxy, and the span
 * a strip would have removed is exactly what the judge needs to see.
 */
export interface JudgeRequest {
  /** As the policy masks PII (raw when masking is off), strip not applied. Untrusted: the attacker wrote it. */
  readonly text: string;
  readonly kind: 'tool_result' | 'resource';
  /** `<server>__<tool>` or a URI. Data, never an instruction. */
  readonly channel: string;
  /** The tier-1 score, 0–100 integer. */
  readonly tier1Score: number;
}

/**
 * What the judge answered, or why it did not.
 *
 * `reason` on `error` is a fixed code and never content: it is copied into logs
 * a terminal or a SIEM will read.
 */
export type JudgeOutcome =
  | {
      readonly kind: 'verdict';
      readonly label: 'injection' | 'benign';
      /** 0–100 integer. The adapter converts; no float reaches the engine (ADR-009). */
      readonly confidence: number;
    }
  | { readonly kind: 'timeout' }
  | { readonly kind: 'error'; readonly reason: string }
  | {
      readonly kind: 'skipped';
      readonly reason: 'busy' | 'circuit_open' | 'degraded' | 'out_of_band';
    };

/** A judge's answer with what it takes to audit it. */
export interface JudgeResult {
  readonly outcome: JudgeOutcome;
  /** The model name the endpoint reported, or the configured one. */
  readonly model: string;
  /** The revision or digest the operator pinned in the policy, if any. */
  readonly modelRevision?: string | undefined;
  readonly latencyMs: number;
  /** True when the text was sampled to fit the judge's input budget. */
  readonly truncated: boolean;
  /** True when the answer came from the in-process cache and the model was not asked. */
  readonly cached: boolean;
}

/**
 * The tier-2 judge. It can only ever answer; it cannot write to the content, and
 * what it says can only raise a decision (see `applyJudge`).
 *
 * Not part of {@link Ports}: that bag is frozen, and a host that has no judge
 * must not have to supply one.
 */
export interface Judge {
  /** `null`, `openai_chat`, ... */
  readonly adapter: string;
  /** The model the policy names. Empty for the null judge. */
  readonly model: string;
  /** The revision the policy pins, when it does. */
  readonly modelRevision?: string | undefined;
  /** `timeoutMs` is a number and not an `AbortSignal`: the engine holds no timer concept. */
  judge(request: JudgeRequest, timeoutMs: number): Promise<JudgeResult>;
}

/** The judge that is always off. The default everywhere. */
export const NULL_JUDGE: Judge = {
  adapter: 'null',
  model: '',
  judge: async () => ({
    outcome: { kind: 'skipped', reason: 'out_of_band' },
    model: '',
    latencyMs: 0,
    truncated: false,
    cached: false,
  }),
};
