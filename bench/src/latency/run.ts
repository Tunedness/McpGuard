/**
 * The latency benchmark: how much the scanner costs, as a curve over content
 * size.
 *
 * "p95 < 20 ms" is meaningless without a payload size, so this measures the cost
 * at a range of sizes and states where the budget is crossed rather than
 * quoting one number. The scan is pure and synchronous, so this measures it
 * directly; the proxy's framing is small and constant on top.
 */
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { type CompiledRuleset, loadRuleset, type ScanOptions, scanContent } from '@mcpguard/detect';
import { loadRulesetData } from '@mcpguard/ruleset';
import { generateCorpus } from '../injection/corpus.js';
import { type Stats, summarize } from './stats.js';

const OPTIONS: ScanOptions = {
  action: 'flag',
  flagAt: 40,
  blockAt: 70,
  maxBytes: 262_144,
  onDegraded: 'flag',
  pii: { recognizers: [], strictChecksum: true, keepLast: 0, correlationTags: false },
};

const ITERATIONS = 500;
const WARMUP = 50;
const TARGET_MS = 20;

function measure(ruleset: CompiledRuleset, text: string): Stats {
  const item = { id: 'x', text, kind: 'tool_result' as const, mimeType: 'text/plain' };
  for (let i = 0; i < WARMUP; i++) scanContent(item, ruleset, OPTIONS);
  const samples: number[] = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const start = performance.now();
    scanContent(item, ruleset, OPTIONS);
    samples.push(performance.now() - start);
  }
  return summarize(samples);
}

function main(): void {
  const ruleset = loadRuleset(loadRulesetData());
  const corpus = generateCorpus();
  const sample = corpus.map((item) => item.text).join('\n');
  const grow = (bytes: number): string => {
    let out = sample;
    while (out.length < bytes) out += sample;
    return out.slice(0, bytes);
  };

  const buckets = [1_000, 4_000, 16_000, 32_000, 64_000, 128_000, 262_144];
  const rows = buckets.map((bytes) => ({ bytes, stats: measure(ruleset, grow(bytes)) }));

  const sizes = corpus.map((i) => new TextEncoder().encode(i.text).length).sort((a, b) => a - b);
  const p95size = sizes[Math.floor(sizes.length * 0.95)] ?? 0;
  const median = sizes[Math.floor(sizes.length / 2)] ?? 0;

  // The largest bucket whose p95 is still under the budget.
  const crossover = [...rows].reverse().find((r) => r.stats.p95 < TARGET_MS)?.bytes ?? 0;
  const referenceMet = measure(ruleset, grow(Math.max(p95size, 1_000))).p95 < TARGET_MS;

  const here = dirname(fileURLToPath(import.meta.url));
  const dir = join(here, '..', '..', 'latency');
  writeFileSync(
    join(dir, 'results.json'),
    `${JSON.stringify(
      { reference: { median, p95size }, target: TARGET_MS, crossover, referenceMet, rows },
      null,
      2,
    )}\n`,
  );
  writeFileSync(join(dir, 'results.md'), render(rows, median, p95size, crossover, referenceMet));
  console.log(
    `reference workload p95 < ${TARGET_MS}ms: ${referenceMet}; budget holds up to ~${crossover} bytes`,
  );
}

function render(
  rows: readonly { bytes: number; stats: Stats }[],
  median: number,
  p95size: number,
  crossover: number,
  referenceMet: boolean,
): string {
  const table = rows
    .map(
      (r) =>
        `| ${r.bytes.toLocaleString()} | ${r.stats.mean.toFixed(3)} | ${r.stats.p50.toFixed(3)} | ${r.stats.p95.toFixed(3)} | ${r.stats.max.toFixed(3)} |`,
    )
    .join('\n');
  return `# McpGuard — scan latency benchmark

${ITERATIONS.toLocaleString()} scans per size, ${WARMUP} discarded first. The scan is
pure and synchronous; the proxy adds a small constant framing cost on top.

## Reference workload

The committed corpus has a **median item of ${median} bytes** and a **95th
percentile of ${p95size} bytes** — tool results are mostly small. The budget of
PRD §6 (added latency p95 < 20 ms) is a claim about that distribution.

## Cost by size

| bytes | mean | p50 | p95 | max |
| --- | --- | --- | --- | --- |
${table}

## Verdict against PRD §6

- p95 < 20 ms on the reference workload: ${referenceMet ? 'MET' : 'NOT MET'}
- the budget holds up to roughly **${crossover.toLocaleString()} bytes** per item

This is stated as a curve, not a single number, because "p95 < 20 ms" without a
size is a number that can be made true by choosing a small enough payload. The
scan is single-pass — one normalization walk, one Aho-Corasick pass, prefiltered
regexes only where a literal hit — so cost grows with **size**, not with the
number of rules: a ruleset twice as large scans in the same time. A result
larger than the crossover costs more than the budget; above 256 KiB it is
sampled (head, tail, interior windows) and marked degraded rather than scanned
in full, so the cost is bounded even for an unbounded input. Shrinking
\`scan.max_bytes\` is the lever an operator pulls to trade coverage for a tighter
tail on very large results.
`;
}

main();
