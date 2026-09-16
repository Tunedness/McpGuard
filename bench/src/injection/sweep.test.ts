import { EMPTY_RULESET } from '@mcpguard/detect';
import { describe, expect, it } from 'vitest';
import { generateCorpus } from './corpus.js';
import { optionsAt, replay } from './replay.js';
import { metricsAt, partition, sweep } from './sweep.js';

/**
 * The replay path, checked against the one thing it must not do: model the
 * engine. Every number here comes from `scanContent()` itself.
 */

const corpus = generateCorpus();

describe('replay', () => {
  it('runs the real engine, so an empty ruleset catches nothing', () => {
    const results = replay(corpus, EMPTY_RULESET, optionsAt(40, 70));

    // Phase 3: the honest baseline. Every positive is missed and every negative
    // is left alone, because there is nothing yet to detect with.
    const caught = results.filter((r) => r.action !== 'allow');
    expect(caught).toHaveLength(0);
  });

  it('marks a positive correct only when it was caught', () => {
    const results = replay(corpus, EMPTY_RULESET, optionsAt(40, 70));
    const positive = results.find((r) => r.item.label === 'positive');
    const negative = results.find((r) => r.item.label === 'negative');

    // With nothing caught, positives are all wrong and negatives all right.
    expect(positive?.correct).toBe(false);
    expect(negative?.correct).toBe(true);
  });
});

describe('metrics', () => {
  it('reports the definitions it promises: catch and false-positive at ≥ flag', () => {
    const m = metricsAt(corpus, EMPTY_RULESET, 40, 70);

    expect(m.recall).toBe(0);
    expect(m.falsePositiveRate).toBe(0);
    // No positives caught and no false positives, so precision is the vacuous 1.
    expect(m.precision).toBe(1);
  });

  it('sweeps the whole primary axis', () => {
    const grid = sweep(corpus, EMPTY_RULESET);

    expect(grid[0]?.flagAt).toBe(20);
    expect(grid[grid.length - 1]?.flagAt).toBe(80);
  });
});

describe('partition', () => {
  it('covers the corpus with two disjoint halves', () => {
    const { calibration, validation } = partition(corpus);

    expect(calibration.length + validation.length).toBe(corpus.length);
    const ids = new Set([...calibration, ...validation].map((i) => i.id));
    expect(ids.size).toBe(corpus.length);
  });
});
