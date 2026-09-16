/**
 * The end-to-end benchmark: sweep, choose an operating point, verify it against
 * the real engine, and write `results.json` and `results.md`.
 *
 * The selection rule is written here **before the numbers are seen**, and it is
 * the record of a decision rather than a knob:
 *
 *   1. false positives under 2% — PRD §6, and never traded for recall, because
 *      PRD §8 lists false positives as the first risk;
 *   2. a margin of at least 4 score points to the nearest item that would flip;
 *   3. then the highest recall;
 *   4. then the more conservative shape (the higher flag threshold).
 *
 * The operating point is chosen on the calibration split and the headline
 * number is reported on the validation split. Both are printed. The corpus and
 * the ruleset share an author, so a number tuned and reported on the same data
 * would be a claim about nothing.
 */
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EMPTY_RULESET } from '@mcpguard/detect';
import { generateCorpus } from './corpus.js';
import { type Metrics, metricsAt, partition, sweep } from './sweep.js';

const FALSE_POSITIVE_CEILING = 0.02;
const RECALL_TARGET = 0.95;
const MIN_MARGIN = 4;

function choose(grid: readonly Metrics[]): Metrics | undefined {
  const eligible = grid
    .filter((m) => m.falsePositiveRate < FALSE_POSITIVE_CEILING && m.margin >= MIN_MARGIN)
    .sort((a, b) => b.recall - a.recall || b.flagAt - a.flagAt);
  return eligible[0];
}

function main(): void {
  const corpus = generateCorpus();
  const { calibration, validation } = partition(corpus);
  const ruleset = EMPTY_RULESET;

  const grid = sweep(calibration, ruleset);
  const chosen = choose(grid) ?? grid[grid.length - 1];
  if (chosen === undefined) throw new Error('empty sweep');

  // The headline is measured on data the point was not chosen on.
  const validated = metricsAt(validation, ruleset, chosen.flagAt, chosen.blockAt);

  const targetsMet = {
    recall: validated.recall >= RECALL_TARGET,
    falsePositive: validated.falsePositiveRate < FALSE_POSITIVE_CEILING,
  };

  const here = dirname(fileURLToPath(import.meta.url));
  const dir = join(here, '..', '..', 'injection');
  writeFileSync(
    join(dir, 'results.json'),
    `${JSON.stringify(
      {
        engineVersion: EMPTY_RULESET.rulesetVersion,
        rulesetVersion: ruleset.rulesetVersion,
        corpusSize: corpus.length,
        chosen,
        validation: validated,
        targets: { recall: RECALL_TARGET, falsePositive: FALSE_POSITIVE_CEILING },
        targetsMet,
      },
      null,
      2,
    )}\n`,
  );
  writeFileSync(
    join(dir, 'results.md'),
    renderMarkdown(corpus.length, chosen, validated, targetsMet),
  );
  console.log(
    `chosen flag_at=${chosen.flagAt}; validation recall=${pct(validated.recall)} fp=${pct(validated.falsePositiveRate)}`,
  );
}

function renderMarkdown(
  size: number,
  chosen: Metrics,
  validation: Metrics,
  met: { recall: boolean; falsePositive: boolean },
): string {
  return `# McpGuard — injection detection benchmark

Corpus: ${size} labelled content items. Operating point chosen on the
calibration split, headline measured on the validation split.

## Chosen operating point

| flag_at | block_at | recall | false positives | precision | F1 | margin |
| --- | --- | --- | --- | --- | --- | --- |
| ${chosen.flagAt} | ${chosen.blockAt} | ${pct(chosen.recall)} | ${pct(chosen.falsePositiveRate)} | ${chosen.precision.toFixed(3)} | ${chosen.f1.toFixed(3)} | ${chosen.margin} |

## Verdict against PRD §6

- catch ≥ 95%:          ${met.recall ? 'MET' : 'NOT MET'} (${pct(validation.recall)}) [validation split]
- false positives < 2%: ${met.falsePositive ? 'MET' : 'NOT MET'} (${pct(validation.falsePositiveRate)})

The detectors arrive in phases 4 and 5. This is the phase 3 baseline: the
ruleset is empty, so every verdict is \`allow\` and recall is 0%. The number is
real from the first run, which is the reason the corpus and this harness come
before the engine — the sibling tool froze a detection axis ahead of measuring
it and had to reopen the decision when no threshold on that axis could meet the
targets. Lowering a gate is never how a change is made to pass here; the gate is
the record of what was achieved.
`;
}

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

main();
