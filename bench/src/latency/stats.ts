/**
 * Percentile statistics, and why the added-latency figure is a difference of
 * percentiles rather than a percentile of differences.
 *
 * The direct run and the guarded run are separate processes making separate
 * calls; pairing call i of one with call i of the other would invent a
 * correspondence that does not exist. So the honest "added latency" is
 * p95(guarded) − p95(direct): what the proxy did to the shape of the
 * distribution, not to any one call.
 */

/** The summary of one set of measurements, in milliseconds. */
export interface Stats {
  readonly n: number;
  readonly min: number;
  readonly mean: number;
  readonly p50: number;
  readonly p95: number;
  readonly p99: number;
  readonly max: number;
}

/** Summarises a set of samples. */
export function summarize(samples: readonly number[]): Stats {
  const sorted = [...samples].sort((a, b) => a - b);
  const n = sorted.length;
  const at = (q: number): number => sorted[Math.min(n - 1, Math.floor(q * n))] ?? 0;
  const sum = sorted.reduce((a, b) => a + b, 0);
  return {
    n,
    min: sorted[0] ?? 0,
    mean: n === 0 ? 0 : sum / n,
    p50: at(0.5),
    p95: at(0.95),
    p99: at(0.99),
    max: sorted[n - 1] ?? 0,
  };
}

/** The percentile-by-percentile difference between two runs. */
export function addedLatency(guarded: Stats, direct: Stats): Stats {
  return {
    n: Math.min(guarded.n, direct.n),
    min: guarded.min - direct.min,
    mean: guarded.mean - direct.mean,
    p50: guarded.p50 - direct.p50,
    p95: guarded.p95 - direct.p95,
    p99: guarded.p99 - direct.p99,
    max: guarded.max - direct.max,
  };
}
