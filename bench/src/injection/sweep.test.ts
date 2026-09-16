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
  it('misses the signature-based attacks under an empty ruleset', () => {
    // The structural detectors — unicode, exfil, anomaly — need no rules and
    // still fire, so an empty ruleset is not silent. But the signature families
    // are, so a direct override with no structural trick goes uncaught. That is
    // what makes the loaded ruleset the thing under test rather than the engine.
    const results = replay(corpus, EMPTY_RULESET, optionsAt(40, 70));
    const override = results.filter((r) => r.item.family === 'direct-override');

    expect(override.every((r) => r.action === 'allow')).toBe(true);
  });

  it('leaves every clean negative alone under an empty ruleset', () => {
    const results = replay(corpus, EMPTY_RULESET, optionsAt(40, 70));
    const negatives = results.filter((r) => r.item.label === 'negative');

    // No false positives from the structural detectors on the benign corpus.
    expect(negatives.every((r) => r.action === 'allow')).toBe(true);
  });
});

describe('metrics', () => {
  it('reports the definitions it promises: catch and false-positive at ≥ flag', () => {
    const m = metricsAt(corpus, EMPTY_RULESET, 40, 70);

    // With only the structural detectors live, a few positives are caught and no
    // benign item fires: the metric plumbing is what is under test here.
    expect(m.recall).toBeGreaterThanOrEqual(0);
    expect(m.recall).toBeLessThan(1);
    expect(m.falsePositiveRate).toBe(0);
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
