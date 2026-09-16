/**
 * Every edge of the engine, expressed as an interface.
 *
 * `@mcpguard/core` performs no I/O and reads no ambient state. Time, identity,
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
