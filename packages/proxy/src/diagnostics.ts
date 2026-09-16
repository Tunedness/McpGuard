/**
 * The stderr diagnostic writer.
 *
 * In wrap mode stdout is the agent's JSON-RPC stream, so a single stray byte on
 * it corrupts every frame after — with the blame landing on the wrapped server.
 * Every diagnostic this proxy emits goes to stderr, prefixed and rate-limited so
 * a flood of findings cannot itself become a denial of service against the log
 * reader. `block()` writes a pre-rendered refusal verbatim and is not
 * rate-limited: a blocked call's explanation must always get through.
 *
 * This module imports neither engine package. See `boundary.test.ts`.
 */

export const DIAGNOSTIC_PREFIX = '[mcpguard]';

/** Where a diagnostic goes. Injected so tests can capture it. */
export interface DiagnosticSink {
  write(chunk: string): unknown;
}

/** Rate-limited stderr diagnostics. */
export class Diagnostics {
  readonly #sink: DiagnosticSink;
  readonly #now: () => number;
  readonly #windowMs: number;
  readonly #limit: number;
  #windowStart = 0;
  #count = 0;
  #suppressed = 0;

  constructor(
    sink: DiagnosticSink,
    options: { now?: () => number; windowMs?: number; limit?: number } = {},
  ) {
    this.#sink = sink;
    this.#now = options.now ?? (() => 0);
    this.#windowMs = options.windowMs ?? 1_000;
    this.#limit = options.limit ?? 20;
  }

  /** Emits one structured diagnostic, subject to the rate limit. */
  emit(event: string, detail: Record<string, unknown> = {}): void {
    const now = this.#now();
    if (now - this.#windowStart >= this.#windowMs) {
      if (this.#suppressed > 0) {
        this.#write('diagnostics_suppressed', { count: this.#suppressed });
        this.#suppressed = 0;
      }
      this.#windowStart = now;
      this.#count = 0;
    }
    if (this.#count >= this.#limit) {
      this.#suppressed++;
      return;
    }
    this.#count++;
    this.#write(event, detail);
  }

  /** Writes a pre-rendered block verbatim. Never rate-limited. */
  block(text: string): void {
    this.#sink.write(`${text}\n`);
  }

  #write(event: string, detail: Record<string, unknown>): void {
    this.#sink.write(`${DIAGNOSTIC_PREFIX} ${JSON.stringify({ event, ...detail })}\n`);
  }
}
