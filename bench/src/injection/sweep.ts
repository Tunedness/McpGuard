/**
 * Metrics and the operating-point sweep.
 *
 * The definitions are stated here, once, so they cannot drift between the sweep
 * and the report: **catch** is a positive whose action is at least `flag`;
 * **false positive** is a negative whose action is at least `flag`. Blocking is
 * measured on its own axis — conflating the two lets someone quote recall at one
 * threshold and false positives at another, which is exactly the sleight the
 * sibling tool refused.
 */
import type { CompiledRuleset } from '@mcpguard/detect';
import { splitOf } from './corpus.js';
import { optionsAt, replay } from './replay.js';
import type { CorpusItem, Split } from './types.js';

export interface Metrics {
  readonly flagAt: number;
  readonly blockAt: number;
  readonly recall: number;
  readonly falsePositiveRate: number;
  readonly precision: number;
  readonly f1: number;
  /** Distance, in score points, to the nearest item that would flip. */
  readonly margin: number;
}

/** Computes metrics for one operating point over one set of items. */
export function metricsAt(
  items: readonly CorpusItem[],
  ruleset: CompiledRuleset,
  flagAt: number,
  blockAt: number,
): Metrics {
  const results = replay(items, ruleset, optionsAt(flagAt, blockAt));
  let tp = 0;
  let fp = 0;
  let positives = 0;
  let negatives = 0;
  let nearestNegative = -Infinity;
  let nearestPositive = Infinity;

  for (const result of results) {
    const caught = result.action !== 'allow';
    if (result.item.label === 'positive') {
      positives++;
      if (caught) tp++;
      nearestPositive = Math.min(nearestPositive, result.score);
    } else {
      negatives++;
      if (caught) fp++;
      nearestNegative = Math.max(nearestNegative, result.score);
    }
  }

  const recall = positives === 0 ? 0 : tp / positives;
  const falsePositiveRate = negatives === 0 ? 0 : fp / negatives;
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  // How far the threshold sits from the closest item on either side. A margin
  // below a couple of points is a line drawn through the corpus, not a
  // calibration — the same reasoning the sibling tool records.
  const margin = Math.min(flagAt - nearestNegative, nearestPositive - flagAt + 1);

  return { flagAt, blockAt, recall, falsePositiveRate, precision, f1, margin };
}

/** Every candidate operating point over the primary axis. */
export function sweep(items: readonly CorpusItem[], ruleset: CompiledRuleset): Metrics[] {
  const out: Metrics[] = [];
  for (let flagAt = 20; flagAt <= 80; flagAt += 2) {
    out.push(metricsAt(items, ruleset, flagAt, 70));
  }
  return out;
}

/** Splits a corpus into its two halves. */
export function partition(items: readonly CorpusItem[]): Record<Split, CorpusItem[]> {
  const out: Record<Split, CorpusItem[]> = { calibration: [], validation: [] };
  for (const item of items) out[splitOf(item)].push(item);
  return out;
}
