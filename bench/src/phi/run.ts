/**
 * The PHI benchmark: replay, measure, check the gates, write `results.json` and
 * `results.md`. Exits non-zero when a gate is not met — that exit is the CI gate.
 */
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRuleset } from '@tunedness/mcpguard-detect';
import { loadRulesetData, RULESET_VERSION } from '@tunedness/mcpguard-ruleset';
import { generateCorpus } from './corpus.js';
import { detections, type KindMetrics, type Metrics, measure, optionsFor } from './replay.js';
import { checkGates, renderMarkdown } from './report.js';
import { GATES, PHI_KINDS } from './types.js';

function round(value: number): number {
  return Math.round(value * 1000) / 1000;
}

function main(): void {
  const corpus = generateCorpus();
  const ruleset = loadRuleset(loadRulesetData());
  const strict = measure(corpus, detections(corpus, ruleset, optionsFor(true)));
  const loose = measure(corpus, detections(corpus, ruleset, optionsFor(false)));
  const gates = checkGates(strict);

  const here = dirname(fileURLToPath(import.meta.url));
  const dir = join(here, '..', '..', 'phi');
  writeFileSync(
    join(dir, 'results.json'),
    `${JSON.stringify(
      {
        rulesetVersion: RULESET_VERSION,
        rulesetDigest: ruleset.digest,
        piiDigest: ruleset.pii?.digest ?? null,
        corpusSize: corpus.length,
        gates: GATES,
        gatesMet: Object.fromEntries(gates.map((g) => [g.kind, g.gated ? g.met : null])),
        strictChecksum: roundAll(strict),
        looseChecksum: roundAll(loose),
      },
      null,
      2,
    )}\n`,
  );
  writeFileSync(join(dir, 'results.md'), renderMarkdown(corpus.length, strict, loose, gates));

  for (const g of gates) {
    const m = strict[g.kind];
    const verdict = !g.gated ? 'not gated' : g.met ? 'met' : `NOT MET (${g.reasons.join('; ')})`;
    console.log(
      `${g.kind.padEnd(12)} recall=${(m.recall * 100).toFixed(1)}% (${m.found}/${m.spans}) fp=${(m.falsePositiveRate * 100).toFixed(1)}% (${m.negativeFires}/${m.negatives}) trap-fp=${(m.trapFalsePositiveRate * 100).toFixed(1)}% (${m.trapFires}/${m.traps}) — ${verdict}`,
    );
  }
  if (gates.some((g) => g.gated && !g.met)) process.exitCode = 1;
}

function roundAll(metrics: Metrics): Record<string, KindMetrics> {
  const out: Record<string, KindMetrics> = {};
  for (const kind of PHI_KINDS) {
    const m = metrics[kind];
    out[kind] = {
      ...m,
      recall: round(m.recall),
      falsePositiveRate: round(m.falsePositiveRate),
      trapFalsePositiveRate: round(m.trapFalsePositiveRate),
    };
  }
  return out;
}

main();
