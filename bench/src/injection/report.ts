/**
 * Per-family breakdowns for the results file.
 *
 * The headline number hides where the engine is strong and where it is
 * guessing. These tables are what a reader checks it against — and what makes an
 * in-sample result honest rather than triumphant.
 */
import type { CompiledRuleset } from '@mcpguard/detect';
import { optionsAt, replay } from './replay.js';
import type { CorpusItem } from './types.js';

/** Recall per attack family, and false-positive rate per benign family. */
export interface FamilyBreakdown {
  readonly positives: Record<string, { caught: number; total: number }>;
  readonly negatives: Record<string, { fired: number; total: number }>;
}

export function familyBreakdown(
  items: readonly CorpusItem[],
  ruleset: CompiledRuleset,
  flagAt: number,
  blockAt: number,
): FamilyBreakdown {
  const results = replay(items, ruleset, optionsAt(flagAt, blockAt));
  const positives: Record<string, { caught: number; total: number }> = {};
  const negatives: Record<string, { fired: number; total: number }> = {};
  for (const result of results) {
    const caught = result.action !== 'allow';
    if (result.item.label === 'positive') {
      positives[result.item.family] ??= { caught: 0, total: 0 };
      const bucket = positives[result.item.family];
      if (bucket === undefined) continue;
      bucket.total += 1;
      if (caught) bucket.caught += 1;
    } else {
      negatives[result.item.family] ??= { fired: 0, total: 0 };
      const bucket = negatives[result.item.family];
      if (bucket === undefined) continue;
      bucket.total += 1;
      if (caught) bucket.fired += 1;
    }
  }
  return { positives, negatives };
}
