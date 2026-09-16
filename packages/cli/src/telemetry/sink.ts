/**
 * The telemetry sink: batches security events and posts them as OTLP logs.
 *
 * Off unless the policy turns it on (ADR-003 / ADR-007): McpGuard is fully
 * functional with no collector, and a security proxy that phones home by default
 * is a line item in a procurement review. When on, events are batched and
 * flushed to the configured endpoint; a failed post is dropped rather than
 * allowed to stall the proxy — telemetry must never be able to block a call.
 */
import type { SecurityEvent, TelemetrySink } from '@mcpguard/core';
import { toLogRecord, toLogsPayload } from './otlp.js';

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
