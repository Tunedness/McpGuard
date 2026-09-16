import { describe, expect, it } from 'vitest';
import { addedLatency, summarize } from './stats.js';

/**
 * The stat helpers, and the one non-obvious decision they encode: added latency
 * is a difference of percentiles, because pairing two independent runs call by
 * call would invent a correspondence that is not there.
 */

describe('summarize', () => {
  it('reports the percentiles of a known set', () => {
    const stats = summarize([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(stats.n).toBe(10);
    expect(stats.min).toBe(1);
    expect(stats.max).toBe(10);
    expect(stats.p50).toBe(6);
    expect(stats.mean).toBe(5.5);
  });

  it('survives an empty sample set', () => {
    expect(summarize([]).p95).toBe(0);
  });
});

describe('addedLatency', () => {
  it('subtracts percentile by percentile, not call by call', () => {
    const guarded = summarize([10, 11, 12, 13, 14]);
    const direct = summarize([2, 3, 4, 5, 6]);
    const added = addedLatency(guarded, direct);
    expect(added.p50).toBe(guarded.p50 - direct.p50);
    expect(added.min).toBe(guarded.min - direct.min);
  });
});
