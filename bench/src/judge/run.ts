/**
 * `npm run bench:judge`: the measurements behind ADR-012's open questions.
 *
 * Always: where tier 1 scores wording it has no rule for, and what each
 * `band_from` costs in judge calls on benign traffic. Deterministic; written to
 * `bench/judge/distribution.md` and committed. Never run in CI.
 *
 *   --overhead                     the proxy's own cost per judged item, against a model that answers at once
 *   --endpoint <url> --model <m>   ask a real local model server (Ollama, llama-server, ...)
 *     [--revision <r>] [--timeout <ms>] [--concurrency 1,2,4] [--benign-limit <n>] [--allow-remote]
 *     [--reasoning-effort none|minimal|low|medium|high|omit] [--max-tokens <n>]
 *
 * `--allow-remote` sends the corpus to an endpoint that is not on this machine. What it
 * sends is synthetic, and always PII-masked: the bench scans with masking on whatever
 * a policy says, so the proxy's rule (a remote judge needs masking on) is met by
 * construction, and no raw identifier is in the corpus to begin with.
 *
 * Whatever a flag leaves out is the product's own default (the `judge` block of the
 * policy schema: timeout, one call at a time, `reasoning_effort: none`, max_tokens),
 * so a bare run measures what a default install does, not something else.
 *
 * A run in which no call was answered prints a warning, writes the reasons the calls
 * failed, and exits with code 2: there is no latency or accuracy to report, and a
 * table of zeros would read as a measurement.
 *
 * The model run writes `bench/judge/model-<slug>.md`. It is not committed: it is
 * about one model on one machine.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GuardPolicySchemaV1 } from '@tunedness/mcpguard-core';
import { loadRuleset } from '@tunedness/mcpguard-detect';
import { loadRulesetData, RULESET_VERSION } from '@tunedness/mcpguard-ruleset';
import { generateCorpus } from '../injection/corpus.js';
import {
  askJudge,
  BUCKETS,
  type Distribution,
  distribute,
  type ModelReport,
  overhead,
  report,
  type Scored,
  scoreAll,
} from './measure.js';
import { PARAPHRASES } from './paraphrases.js';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'judge');

function flag(argv: readonly string[], name: string): string | undefined {
  const at = argv.indexOf(`--${name}`);
  return at === -1 ? undefined : argv[at + 1];
}

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function isLoopback(endpoint: string): boolean {
  const host = new URL(endpoint).hostname;
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
}

/** The corpus's benign items and the paraphrases, scored by the real tier 1. */
export function prepare() {
  const ruleset = loadRuleset(loadRulesetData());
  const benignItems = generateCorpus().filter((item) => item.label === 'negative');
  const benign = scoreAll(
    benignItems.map((item) => ({
      id: item.id,
      group: item.family,
      locale: item.locale,
      text: item.text,
      kind: item.contentKind,
      mimeType: item.mimeType,
    })),
    ruleset,
  );
  const paraphrases = scoreAll(
    PARAPHRASES.map((p) => ({ id: p.id, group: p.family, locale: p.locale, text: p.text })),
    ruleset,
  );
  return { paraphrases, benign };
}

/** The V5 verdict, by the rule written before the numbers were seen. */
export function v5(distribution: Distribution): { held: boolean; line: string } {
  // ADR-012 V5: leaks mostly below flag_at and only partly at 0. It fails when
  // the majority of leaks score exactly 0, because then no band_from above 0
  // reaches them and only "judge everything" does.
  const held = distribution.pileAtZero <= 0.5;
  return {
    held,
    line: held
      ? `V5 HELD: ${pct(distribution.pileAtZero)} of the ${distribution.leaks} leaks score exactly 0 (limit 50%), so a band_from above 0 reaches the rest.`
      : `V5 REFUTED: ${pct(distribution.pileAtZero)} of the ${distribution.leaks} leaks score exactly 0 (limit 50%). No band_from above 0 reaches them; only band_from: 0 (judge every item) does.`,
  };
}

const EFFORTS = ['none', 'minimal', 'low', 'medium', 'high', 'omit'] as const;

/** The product's own judge defaults, read from the policy schema and not copied. */
export function judgeDefaults() {
  return GuardPolicySchemaV1.parse({ version: 1 }).judge;
}

/** What a model run uses: each flag, or else the product's default. */
export function modelRunOptions(argv: readonly string[]) {
  const defaults = judgeDefaults();
  const effort = (flag(argv, 'reasoning-effort') ??
    defaults.reasoning_effort) as (typeof EFFORTS)[number];
  if (!EFFORTS.includes(effort)) {
    throw new Error(`--reasoning-effort must be one of ${EFFORTS.join(', ')}`);
  }
  const concurrency = flag(argv, 'concurrency');
  return {
    timeoutMs: Number(flag(argv, 'timeout') ?? defaults.timeout),
    effort,
    maxTokens: Number(flag(argv, 'max-tokens') ?? defaults.max_tokens),
    // One call at a time, as `max_inflight` defaults: a server that queues turns more into timeouts.
    levels: (concurrency ?? String(defaults.max_inflight)).split(',').map(Number),
  };
}

function distributionMarkdown(distribution: Distribution): string {
  const verdict = v5(distribution);
  const rows = (items: Array<{ label: string; count: number }>) =>
    items
      .map((b) => `| ${b.label} | ${b.count} | ${pct(b.count / distribution.paraphrases)} |`)
      .join('\n');
  const group = (
    rows_: Array<{ n: number; leaks: number; atZero: number } & Record<string, unknown>>,
    key: string,
  ) => rows_.map((r) => `| ${String(r[key])} | ${r.n} | ${r.leaks} | ${r.atZero} |`).join('\n');
  const bands = distribution.bands
    .map(
      (b) =>
        `| ${b.bandFrom === 40 ? '40 (default: flag_at)' : b.bandFrom} | ${b.leaksInBand}/${distribution.leaks} | ${b.paraphrasesInBand}/${distribution.paraphrases} | ${b.benignInBand}/${b.benignTotal} (${pct(b.benignInBand / b.benignTotal)}) |`,
    )
    .join('\n');
  return `# McpGuard — tier-1 scores of paraphrased injections, and what each \`band_from\` costs

Ruleset ${RULESET_VERSION}, scan defaults (\`flag_at\` 40, \`block_at\` 70). ${distribution.paraphrases} hand-written
paraphrases of the corpus's attack intents, English and Turkish (\`bench/src/judge/paraphrases.ts\`),
scored by the real engine. Reproduce with \`npm run bench:judge\`; no model is needed.

## ${verdict.line}

A *leak* is a paraphrase tier 1 does not flag, a score below \`flag_at\`. Those are the items a judge is
for. The default \`band_from\` is \`flag_at\`, so by construction **the default band reaches no leak**: it
covers \`[flag_at, block_at)\` and the unconfirmed scores above it. Reaching leaks takes a lower
\`band_from\`, which is a choice about how many model calls to spend on benign traffic.

## Where the paraphrases score

| tier-1 score | paraphrases | share |
| --- | --- | --- |
${rows(distribution.paraphraseHistogram)}

${distribution.leaks} of ${distribution.paraphrases} score below \`flag_at\` (leaks); ${Math.round(distribution.pileAtZero * distribution.leaks)} of those score exactly 0.

| family | n | leaks | at 0 |
| --- | --- | --- | --- |
${group(distribution.byFamily as never, 'family')}

| locale | n | leaks | at 0 |
| --- | --- | --- | --- |
${group(distribution.byLocale as never, 'locale')}

## What each \`band_from\` costs

Judge calls are made for the items in the band. "Benign in band" is the share of the corpus's ${distribution.bands[0]?.benignTotal ?? 0} benign
items that would be sent to the model: the price of reaching the leaks column.

| band_from | leaks reached | paraphrases in band | benign items in band |
| --- | --- | --- | --- |
${bands}

## How far to trust this

One author wrote the ${distribution.paraphrases} paraphrases, after reading the ruleset's family names, and the corpus's benign
items are the ones the ruleset was calibrated against. This measures a *shape*: whether paraphrases pile
at zero or spread below \`flag_at\`. It does not measure a rate in the wild, and ${distribution.paraphrases} items do not support one.
Whether a model catches what tier 1 misses is a different measurement (\`--endpoint\`), and is not made here.
`;
}

function modelMarkdown(
  model: string,
  runs: Array<{ concurrency: number; maxInflight: number; timeoutMs: number; r: ModelReport }>,
): string {
  const sections = runs
    .map(({ concurrency, maxInflight, timeoutMs, r }) => {
      const outcomes = Object.entries(r.outcomes)
        .map(([k, v]) => `${k} ${v}`)
        .join(', ');
      const reasons = Object.entries(r.errorReasons)
        .sort((a, b) => b[1] - a[1])
        .map(([k, v]) => `${k} ${v}`)
        .join(', ');
      const head = `### concurrency ${concurrency}, max_inflight ${maxInflight}, timeout ${timeoutMs} ms

- ${r.n} calls in ${(r.wallMs / 1000).toFixed(1)} s (${r.callsPerSecond.toFixed(2)} calls/s). Outcomes: ${outcomes}.
- Why calls failed: ${reasons === '' ? 'no call returned an error' : reasons}.`;
      if (r.latency === undefined) {
        return `${head}
- **NO CALL WAS ANSWERED.** There is no latency, recall or false-positive figure for this run, and none is shown. Fix the failure above (the reason codes say which) and run again.`;
      }
      const curve = r.slowerThan.map((s) => `${s.ms} ms: ${pct(s.share)}`).join(' · ');
      return `${head}
- ${r.answered} of ${r.n} calls answered.${r.answered < r.n / 2 ? ' **Under half were answered: the figures below describe only the calls that got through.**' : ''} Answered-call latency: p50 ${r.latency.p50.toFixed(0)} ms, p95 ${r.latency.p95.toFixed(0)} ms, p99 ${r.latency.p99.toFixed(0)} ms, max ${r.latency.max.toFixed(0)} ms.
- Share of answered calls slower than: ${curve}
- Paraphrases called injection: ${r.paraphraseRecall === undefined ? 'n/a' : pct(r.paraphraseRecall)}; benign items called injection: ${r.benignInjectionRate === undefined ? 'n/a' : pct(r.benignInjectionRate)}. Calls that were not answered count as "not injection" here.
- By locale: ${r.byLocale.map((l) => `${l.locale} ${l.flagged}/${l.n}`).join(', ')}.`;
    })
    .join('\n\n');
  return `# McpGuard — tier-2 judge against ${model}

Not committed: this describes one model on one machine. Items are the paraphrase set and a sample of
benign corpus items, as tier 1 hands them over (PII masked).

${sections}
`;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const { paraphrases, benign } = prepare();
  const distribution = distribute(paraphrases, benign);
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, 'distribution.md'), distributionMarkdown(distribution));
  writeFileSync(join(OUT, 'distribution.json'), `${JSON.stringify(distribution, null, 2)}\n`);
  console.log(v5(distribution).line);
  console.log(`wrote ${join(OUT, 'distribution.md')}`);
  console.log(
    `buckets: ${BUCKETS.map((b, i) => `${b.label}=${distribution.paraphraseHistogram[i]?.count}`).join(', ')}`,
  );

  if (argv.includes('--overhead')) {
    const result = await overhead(500, 1);
    console.log(
      `overhead, instant model, loopback, sequential: p50 ${result.latency.p50.toFixed(2)} ms, p95 ${result.latency.p95.toFixed(2)} ms, p99 ${result.latency.p99.toFixed(2)} ms (n=${result.latency.n})`,
    );
  }

  const endpoint = flag(argv, 'endpoint');
  const model = flag(argv, 'model');
  if (endpoint === undefined) return;
  if (model === undefined) throw new Error('--endpoint needs --model');
  if (!isLoopback(endpoint) && !argv.includes('--allow-remote')) {
    throw new Error(
      'the endpoint is not on this machine; pass --allow-remote to send it masked corpus text',
    );
  }
  const limit = Number(flag(argv, 'benign-limit') ?? 60);
  const step = Math.max(1, Math.floor(benign.length / limit));
  const sampleBenign = benign.filter((_, i) => i % step === 0).slice(0, limit);
  const items: Array<Scored & { positive: boolean }> = [
    ...paraphrases.map((p) => ({ ...p, positive: true })),
    ...sampleBenign.map((b) => ({ ...b, positive: false })),
  ];
  const { timeoutMs, effort, maxTokens, levels } = modelRunOptions(argv);
  const runs: Array<{
    concurrency: number;
    maxInflight: number;
    timeoutMs: number;
    r: ModelReport;
  }> = [];
  for (const concurrency of levels) {
    const { judged, wallMs } = await askJudge(items, {
      endpoint,
      model,
      modelRevision: flag(argv, 'revision'),
      timeoutMs,
      concurrency,
      maxInflight: concurrency,
      reasoningEffort: effort,
      maxTokens,
    });
    runs.push({ concurrency, maxInflight: concurrency, timeoutMs, r: report(judged, wallMs) });
  }
  const slug = model.replace(/[^\w.-]+/g, '_');
  writeFileSync(join(OUT, `model-${slug}.md`), modelMarkdown(model, runs));
  console.log(`wrote ${join(OUT, `model-${slug}.md`)}`);
  for (const { concurrency, r } of runs) {
    const why = Object.entries(r.errorReasons)
      .map(([k, v]) => `${k} ${v}`)
      .join(', ');
    console.log(
      `concurrency ${concurrency}: ${r.answered}/${r.n} answered${why === '' ? '' : `; errors: ${why}`}${r.outcomes.timeout ? `; timeouts: ${r.outcomes.timeout}` : ''}`,
    );
  }
  const mostly = runs.filter(({ r }) => r.answered > 0 && r.answered < r.n / 2);
  if (mostly.length > 0) {
    console.error(
      `WARNING: under half the calls were answered at concurrency ${mostly.map(({ concurrency }) => concurrency).join(', ')}; its latency figures describe only the calls that got through. A server that handles one request at a time only queues the rest: lower the concurrency or raise the timeout.`,
    );
  }
  const silent = runs.filter(({ r }) => r.answered === 0);
  if (silent.length > 0) {
    console.error(
      `WARNING: no call was answered at concurrency ${silent.map(({ concurrency }) => concurrency).join(', ')}. There is nothing to report about this model's speed or answers; see the failure reasons above.`,
    );
    process.exitCode = 2;
  }
}

// Not `main()` at import time: the test imports `prepare` and `v5`.
if (
  process.argv[1] !== undefined &&
  import.meta.url === new URL(`file://${process.argv[1]}`).href
) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
