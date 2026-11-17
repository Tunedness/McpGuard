/**
 * The telemetry sink: batches security events and posts them as OTLP logs.
 *
 * Off unless the policy turns it on (ADR-003 / ADR-007): McpGuard is fully
 * functional with no collector, and a security proxy that phones home by default
 * is a line item in a procurement review. When on, events are batched and
 * flushed to the configured endpoint; a failed post is dropped rather than
 * allowed to stall the proxy — telemetry must never be able to block a call.
 */
import type { GuardPolicy, SecurityEvent, TelemetrySink } from '@tunedness/mcpguard-core';
import type { CheckpointSink } from '../audit-writer.js';
import { toLogRecord, toLogsPayload } from './otlp.js';
import { parseSyslogTarget, SyslogCheckpointSink } from './syslog.js';

/** How the sink reaches its collector. Injected so tests avoid the network. */
export type Poster = (payload: unknown) => Promise<void>;

/** How the sink is configured. */
export interface TelemetryOptions {
  readonly service: string;
  readonly post: Poster;
  readonly batchSize?: number;
  readonly onError?: (error: Error) => void;
}

/** A batching, best-effort OTLP telemetry sink. */
export class OtlpTelemetrySink implements TelemetrySink {
  readonly #service: string;
  readonly #post: Poster;
  readonly #batchSize: number;
  readonly #onError: (error: Error) => void;
  #batch: Record<string, unknown>[] = [];

  constructor(options: TelemetryOptions) {
    this.#service = options.service;
    this.#post = options.post;
    this.#batchSize = options.batchSize ?? 32;
    this.#onError = options.onError ?? (() => {});
  }

  emit(event: SecurityEvent): void {
    this.#batch.push(toLogRecord(event, this.#service));
    if (this.#batch.length >= this.#batchSize) void this.flush();
  }

  /** Sends what is buffered. Errors are reported, never thrown at the caller. */
  async flush(): Promise<void> {
    if (this.#batch.length === 0) return;
    const records = this.#batch;
    this.#batch = [];
    try {
      await this.#post(toLogsPayload(records, this.#service));
    } catch (error) {
      this.#onError(error instanceof Error ? error : new Error(String(error)));
    }
  }
}

/** A no-op sink, for when telemetry is off. */
export const NULL_TELEMETRY: TelemetrySink = { emit: () => {} };

/**
 * Where the audit writer publishes its chain-head checkpoint, per `audit.checkpoint_to`.
 *
 * `stderr` is the host's own stream and `none` is no sink. `syslog` is a socket
 * whose every failure goes to `onError` (see `syslog.ts` for what each transport
 * can tell). The policy schema requires and vets the target before anything gets
 * here, so a missing or unparsable one is a bug, not an operator mistake, and
 * throws at startup rather than running with a checkpoint that goes nowhere.
 *
 * @throws {Error} when `checkpoint_to` is `syslog` and the target is absent or invalid.
 */
export function checkpointSinkFor(
  audit: GuardPolicy['audit'],
  stderr: CheckpointSink,
  onError: (error: Error) => void,
): CheckpointSink | undefined {
  if (audit.checkpoint_to === 'stderr') return stderr;
  if (audit.checkpoint_to !== 'syslog') return undefined;
  if (audit.syslog.target === undefined) {
    throw new Error('audit.checkpoint_to is syslog but audit.syslog.target is not set');
  }
  return new SyslogCheckpointSink({
    address: parseSyslogTarget(audit.syslog.target),
    facility: audit.syslog.facility,
    onError,
  });
}

/** What a failed checkpoint is reported through. */
export interface CheckpointFailureOptions {
  /** The host's stderr diagnostic: `(event, detail)`. */
  readonly out: (event: string, detail: Record<string, unknown>) => void;
  readonly telemetry: TelemetrySink;
  readonly clock: () => number;
  /** The session and server the event is filed under; the checkpoint belongs to neither call. */
  readonly sessionId: string;
  readonly serverName: string;
}

/**
 * Turns a checkpoint that did not leave cleanly into the two records an operator
 * can see: a `checkpoint_error` line on stderr and a `security_event`
 * (`audit_checkpoint`, action `checkpoint_failed`). A checkpoint is what proves
 * the audit file was not swapped; one that went missing is a fact about the
 * audit trail, so it is never only a log line.
 */
export function checkpointFailureReporter(
  options: CheckpointFailureOptions,
): (error: Error) => void {
  return (error) => {
    const raw = (error as NodeJS.ErrnoException).code;
    // The code goes into an event field: only an identifier-shaped one, never free text.
    const code = typeof raw === 'string' && /^[A-Z][A-Z0-9_]{1,40}$/.test(raw) ? raw : 'ERROR';
    options.out('checkpoint_error', { sink: 'syslog', code, message: error.message });
    options.telemetry.emit({
      type: 'security_event',
      kind: 'audit_checkpoint',
      at: options.clock(),
      sessionId: options.sessionId,
      serverName: options.serverName,
      toolName: undefined,
      score: undefined,
      action: 'checkpoint_failed',
      evidence: [`syslog.${code}`],
    });
  };
}
