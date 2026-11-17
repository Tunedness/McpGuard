/**
 * What stands between the proxy and a slow or absent model (ADR-012, item 7).
 *
 * A judge call sits on the path of a tool result, so a model that is slow, down
 * or flooded must cost the agent at most one bounded wait and never a queue:
 *
 * - **No retry.** Tier 1's decision is ready before the call starts, so a retry
 *   buys only latency.
 * - **No queue.** At `maxInflight` a new item is skipped (`busy`). A queue would
 *   let a slow model grow the agent's latency without bound.
 * - **A circuit breaker.** After `failureThreshold` consecutive timeouts or
 *   errors the judge is off for `openForMs`, then one trial call decides whether
 *   it stays off. While off, items skip with `circuit_open` and wait for nothing.
 * - **A small cache.** The same masked text asked twice (a polled tool) is
 *   answered from memory, with the same answer, and says so (`cached`).
 *
 * Every refusal is a `skipped` outcome, which `applyJudge` reads as "tier 1
 * stands".
 */
import { type Judge, type JudgeRequest, type JudgeResult, sha256 } from '@tunedness/mcpguard-core';

/** The cache's size. */
export const CACHE_ENTRIES = 256;
/** How long past `timeoutMs` the limiter waits for an adapter that ignores its deadline. */
const GRACE_MS = 250;

/** How the limiter is configured. */
export interface LimiterOptions {
  readonly inner: Judge;
  readonly maxInflight: number;
  readonly failureThreshold: number;
  readonly openForMs: number;
  readonly clock: () => number;
  /** Called once each time the breaker opens after a healthy stretch. */
  readonly onUnavailable?: ((info: { failures: number; openForMs: number }) => void) | undefined;
  readonly cacheEntries?: number | undefined;
}

interface CachedVerdict {
  readonly result: JudgeResult;
}

/** A {@link Judge} that bounds another one. */
export class LimitedJudge implements Judge {
  readonly adapter: string;
  readonly model: string;
  readonly modelRevision: string | undefined;
  readonly #inner: Judge;
  readonly #options: LimiterOptions;
  readonly #cache = new Map<string, CachedVerdict>();
  #inflight = 0;
  #failures = 0;
  /** 0 while closed; otherwise the time before which the breaker stays open. */
  #openUntil = 0;
  #probing = false;
  #announced = false;

  constructor(options: LimiterOptions) {
    this.#inner = options.inner;
    this.#options = options;
    this.adapter = options.inner.adapter;
    this.model = options.inner.model;
    this.modelRevision = options.inner.modelRevision;
  }

  async judge(request: JudgeRequest, timeoutMs: number): Promise<JudgeResult> {
    const key = sha256(request.text);
    const hit = this.#cache.get(key);
    if (hit !== undefined) {
      // Re-inserted, so the Map's iteration order is least recently used first.
      this.#cache.delete(key);
      this.#cache.set(key, hit);
      return { ...hit.result, latencyMs: 0, cached: true };
    }

    const now = this.#options.clock();
    let probe = false;
    if (this.#openUntil > 0) {
      if (now < this.#openUntil || this.#probing) return this.#skipped('circuit_open');
      probe = true;
    }
    if (this.#inflight >= this.#options.maxInflight) return this.#skipped('busy');
    if (probe) this.#probing = true;

    this.#inflight++;
    let result: JudgeResult;
    try {
      result = await this.#bounded(request, timeoutMs);
    } finally {
      this.#inflight--;
    }

    const kind = result.outcome.kind;
    if (kind === 'verdict') {
      this.#failures = 0;
      this.#openUntil = 0;
      this.#probing = false;
      this.#announced = false;
      this.#remember(key, result);
    } else if (kind === 'timeout' || kind === 'error') {
      this.#failures++;
      if (probe || this.#failures >= this.#options.failureThreshold) this.#open(probe);
    } else if (probe) {
      this.#probing = false;
    }
    return result;
  }

  /** Asks the inner judge, and gives up shortly after the deadline whatever it does. */
  async #bounded(request: JudgeRequest, timeoutMs: number): Promise<JudgeResult> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const started = this.#options.clock();
    const gaveUp = new Promise<JudgeResult>((resolve) => {
      timer = setTimeout(
        () => resolve(this.#failed({ kind: 'timeout' }, started)),
        timeoutMs + GRACE_MS,
      );
      timer.unref?.();
    });
    try {
      return await Promise.race([this.#inner.judge(request, timeoutMs), gaveUp]);
    } catch {
      // An adapter that throws is a bug, and a bug must not become the agent's error.
      return this.#failed({ kind: 'error', reason: 'internal' }, started);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  #open(wasProbe: boolean): void {
    const wasClosed = this.#openUntil === 0;
    this.#openUntil = this.#options.clock() + this.#options.openForMs;
    this.#probing = false;
    if (wasProbe) this.#failures = this.#options.failureThreshold;
    if (wasClosed && !this.#announced) {
      this.#announced = true;
      this.#options.onUnavailable?.({
        failures: this.#failures,
        openForMs: this.#options.openForMs,
      });
    }
  }

  #remember(key: string, result: JudgeResult): void {
    this.#cache.set(key, { result });
    const limit = this.#options.cacheEntries ?? CACHE_ENTRIES;
    while (this.#cache.size > limit) {
      const oldest = this.#cache.keys().next().value;
      if (oldest === undefined) break;
      this.#cache.delete(oldest);
    }
  }

  #skipped(reason: 'busy' | 'circuit_open'): JudgeResult {
    return {
      outcome: { kind: 'skipped', reason },
      model: this.model,
      ...(this.modelRevision !== undefined ? { modelRevision: this.modelRevision } : {}),
      latencyMs: 0,
      truncated: false,
      cached: false,
    };
  }

  #failed(outcome: JudgeResult['outcome'], started: number): JudgeResult {
    return {
      outcome,
      model: this.model,
      ...(this.modelRevision !== undefined ? { modelRevision: this.modelRevision } : {}),
      latencyMs: Math.max(0, this.#options.clock() - started),
      truncated: false,
      cached: false,
    };
  }
}
