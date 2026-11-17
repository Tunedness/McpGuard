/**
 * The three measurements behind ADR-012's open questions (Faz 22).
 *
 * - {@link distribute}: where tier 1 scores wording it has no rule for. Needs no
 *   model and is deterministic, so its output is committed.
 * - {@link askJudge}: what a real model server does with the items: its
 *   latency curve, its answers, its failures. Needs an endpoint, so it is never
 *   committed and never run in CI.
 * - {@link overhead}: what the proxy's own machinery (adapter, limiter, a
 *   loopback socket) adds when the "model" answers instantly. The one number
 *   about the judge path that does not depend on a model.
 */
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { LimitedJudge, OpenAiChatJudge } from '@tunedness/mcpguard';
import type { Judge, JudgeResult } from '@tunedness/mcpguard-core';
import { type CompiledRuleset, type ScanOptions, scanContent } from '@tunedness/mcpguard-detect';
import { type Stats, summarize } from '../latency/stats.js';

/** Tier 1's options at the shipped defaults, with PII masking on as the proxy runs it. */
export const TIER1: ScanOptions = {
  action: 'flag',
  flagAt: 40,
  blockAt: 70,
  maxBytes: 262_144,
  onDegraded: 'flag',
  pii: { recognizers: [], strictChecksum: true, keepLast: 0, correlationTags: false },
};

/** One item as tier 1 sees it. */
export interface Scored {
  readonly id: string;
  readonly group: string;
  readonly locale: string;
  readonly score: number;
  readonly corroborated: boolean;
  /** What the judge would be shown. */
  readonly maskedText: string;
}

/** An item to be scored. */
export interface Subject {
  readonly id: string;
  readonly group: string;
  readonly locale: string;
  readonly text: string;
  readonly kind?: 'tool_result' | 'resource';
  readonly mimeType?: string;
}

/** Runs every subject through the real tier 1. */
export function scoreAll(subjects: readonly Subject[], ruleset: CompiledRuleset): Scored[] {
  return subjects.map((subject) => {
    const verdict = scanContent(
      {
        id: subject.id,
        text: subject.text,
        kind: subject.kind ?? 'tool_result',
        ...(subject.mimeType !== undefined ? { mimeType: subject.mimeType } : {}),
        channel: 'bench__judge',
      },
      ruleset,
      TIER1,
    );
    return {
      id: subject.id,
      group: subject.group,
      locale: subject.locale,
      score: verdict.score,
      corroborated: verdict.corroborated,
      maskedText: verdict.maskedText ?? subject.text,
    };
  });
}

/** Score buckets a distribution is told in. */
export const BUCKETS = [
  { label: '0', test: (s: number) => s === 0 },
  { label: '1-19', test: (s: number) => s >= 1 && s <= 19 },
  { label: '20-39', test: (s: number) => s >= 20 && s < TIER1.flagAt },
  { label: '40-69 (band)', test: (s: number) => s >= TIER1.flagAt && s < TIER1.blockAt },
  { label: '70+ confirmed', test: (s: number, c: boolean) => s >= TIER1.blockAt && c },
  { label: '70+ unconfirmed (band)', test: (s: number, c: boolean) => s >= TIER1.blockAt && !c },
] as const;

/** How many of `items` fall in each bucket. */
export function histogram(items: readonly Scored[]): Array<{ label: string; count: number }> {
  return BUCKETS.map((bucket) => ({
    label: bucket.label,
    count: items.filter((item) => bucket.test(item.score, item.corroborated)).length,
  }));
}

/** The `band_from` values the table prices. */
export const BAND_FROM = [40, 30, 20, 10, 1, 0] as const;

/** Whether the judge would be asked about an item, for one `band_from` (ADR-012 item 5). */
export function inBand(item: Scored, bandFrom: number): boolean {
  if (item.score >= TIER1.blockAt) return !item.corroborated;
  return item.score >= bandFrom;
}

/**
 * Where the paraphrase leaks sit, and what each `band_from` costs.
 *
 * A *leak* is a paraphrase tier 1 does not flag (score below `flag_at`): the
 * ones the judge is for. `pileAtZero` is the share of leaks scoring exactly 0, the
 * number the ADR's V5 turns on: a leak at 0 is reached only by `band_from: 0`,
 * which sends every item, benign ones included, to the model.
 */
export interface Distribution {
  readonly paraphrases: number;
  readonly leaks: number;
  readonly pileAtZero: number;
  readonly paraphraseHistogram: ReturnType<typeof histogram>;
  readonly byFamily: Array<{ family: string; n: number; leaks: number; atZero: number }>;
  readonly byLocale: Array<{ locale: string; n: number; leaks: number; atZero: number }>;
  readonly bands: Array<{
    bandFrom: number;
    paraphrasesInBand: number;
    leaksInBand: number;
    benignInBand: number;
    benignTotal: number;
  }>;
}

/** Summarises scored paraphrases against scored benign traffic. */
export function distribute(
  paraphrases: readonly Scored[],
  benign: readonly Scored[],
): Distribution {
  const leaks = paraphrases.filter((item) => item.score < TIER1.flagAt);
  const tally = (key: (item: Scored) => string) =>
    [...new Set(paraphrases.map(key))].sort().map((name) => {
      const own = paraphrases.filter((item) => key(item) === name);
      return {
        name,
        n: own.length,
        leaks: own.filter((item) => item.score < TIER1.flagAt).length,
        atZero: own.filter((item) => item.score === 0).length,
      };
    });
  return {
    paraphrases: paraphrases.length,
    leaks: leaks.length,
    pileAtZero:
      leaks.length === 0 ? 0 : leaks.filter((item) => item.score === 0).length / leaks.length,
    paraphraseHistogram: histogram(paraphrases),
    byFamily: tally((item) => item.group).map(({ name, ...rest }) => ({ family: name, ...rest })),
    byLocale: tally((item) => item.locale).map(({ name, ...rest }) => ({ locale: name, ...rest })),
    bands: BAND_FROM.map((bandFrom) => ({
      bandFrom,
      paraphrasesInBand: paraphrases.filter((item) => inBand(item, bandFrom)).length,
      leaksInBand: leaks.filter((item) => inBand(item, bandFrom)).length,
      benignInBand: benign.filter((item) => inBand(item, bandFrom)).length,
      benignTotal: benign.length,
    })),
  };
}

// ---------------------------------------------------------------------------
// a real model
// ---------------------------------------------------------------------------

/** One judged item. */
export interface Judged {
  readonly id: string;
  readonly group: string;
  readonly locale: string;
  readonly positive: boolean;
  readonly result: JudgeResult;
}

/** What {@link askJudge} is given. */
export interface AskOptions {
  readonly endpoint: string;
  readonly model: string;
  readonly modelRevision?: string | undefined;
  readonly timeoutMs: number;
  readonly concurrency: number;
  /** In-flight ceiling of the limiter; at least `concurrency` to measure the model, lower to see `busy`. */
  readonly maxInflight: number;
  readonly maxInputBytes?: number | undefined;
  readonly reasoningEffort?: 'none' | 'minimal' | 'low' | 'medium' | 'high' | 'omit' | undefined;
  readonly maxTokens?: number | undefined;
}

/** Asks a judge about every item, `concurrency` at a time. */
export async function askJudge(
  items: ReadonlyArray<Scored & { positive: boolean }>,
  options: AskOptions,
  judge?: Judge,
): Promise<{ judged: Judged[]; wallMs: number }> {
  const inner =
    judge ??
    new LimitedJudge({
      inner: new OpenAiChatJudge({
        endpoint: options.endpoint,
        model: options.model,
        modelRevision: options.modelRevision,
        maxInputBytes: options.maxInputBytes ?? 16_384,
        reasoningEffort: options.reasoningEffort,
        maxTokens: options.maxTokens,
      }),
      maxInflight: options.maxInflight,
      // The curve is the point here: the breaker must not cut it short.
      failureThreshold: Number.MAX_SAFE_INTEGER,
      openForMs: 30_000,
      clock: () => Date.now(),
      cacheEntries: 0,
    });
  const judged: Judged[] = [];
  let next = 0;
  const started = performance.now();
  const worker = async (): Promise<void> => {
    for (;;) {
      const index = next++;
      const item = items[index];
      if (item === undefined) return;
      const result = await inner.judge(
        {
          text: item.maskedText,
          kind: 'tool_result',
          channel: 'bench__judge',
          tier1Score: item.score,
        },
        options.timeoutMs,
      );
      judged.push({
        id: item.id,
        group: item.group,
        locale: item.locale,
        positive: item.positive,
        result,
      });
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, options.concurrency) }, worker));
  return { judged, wallMs: performance.now() - started };
}

/** What a set of judged items says about a model. */
export interface ModelReport {
  readonly n: number;
  readonly outcomes: Record<string, number>;
  /** Why the `error` calls failed, by the adapter's fixed codes (`http_503`, `output_truncated`, ...). */
  readonly errorReasons: Record<string, number>;
  /** How many calls got a verdict. Zero means there is nothing to say about the model's speed or answers. */
  readonly answered: number;
  /** Absent when no call was answered: a zero latency line would be made up. */
  readonly latency: Stats | undefined;
  /** Share of answered calls slower than each candidate timeout. */
  readonly slowerThan: Array<{ ms: number; share: number }>;
  readonly paraphraseRecall: number | undefined;
  readonly benignInjectionRate: number | undefined;
  readonly byLocale: Array<{ locale: string; n: number; flagged: number }>;
  readonly wallMs: number;
  readonly callsPerSecond: number;
}

/** The timeouts the latency curve is read against. */
export const TIMEOUT_CANDIDATES = [250, 500, 1000, 1500, 2000, 3000, 5000] as const;

/** Summarises {@link askJudge}'s output. */
export function report(judged: readonly Judged[], wallMs: number): ModelReport {
  const outcomes: Record<string, number> = {};
  const errorReasons: Record<string, number> = {};
  for (const entry of judged) {
    const o = entry.result.outcome;
    if (o.kind === 'error') errorReasons[o.reason] = (errorReasons[o.reason] ?? 0) + 1;
    const key =
      o.kind === 'verdict' ? o.label : o.kind === 'skipped' ? `skipped:${o.reason}` : o.kind;
    outcomes[key] = (outcomes[key] ?? 0) + 1;
  }
  const answered = judged.filter((entry) => entry.result.outcome.kind === 'verdict');
  const latencies = answered.map((entry) => entry.result.latencyMs);
  const said = (entry: Judged): boolean =>
    entry.result.outcome.kind === 'verdict' && entry.result.outcome.label === 'injection';
  const positives = judged.filter((entry) => entry.positive);
  const negatives = judged.filter((entry) => !entry.positive);
  const locales = [...new Set(positives.map((entry) => entry.locale))].sort();
  return {
    n: judged.length,
    outcomes,
    errorReasons,
    answered: answered.length,
    latency: answered.length === 0 ? undefined : summarize(latencies),
    slowerThan: TIMEOUT_CANDIDATES.map((ms) => ({
      ms,
      share: latencies.length === 0 ? 0 : latencies.filter((l) => l > ms).length / latencies.length,
    })),
    paraphraseRecall:
      positives.length === 0 ? undefined : positives.filter(said).length / positives.length,
    benignInjectionRate:
      negatives.length === 0 ? undefined : negatives.filter(said).length / negatives.length,
    byLocale: locales.map((locale) => {
      const own = positives.filter((entry) => entry.locale === locale);
      return { locale, n: own.length, flagged: own.filter(said).length };
    }),
    wallMs,
    callsPerSecond: wallMs === 0 ? 0 : (judged.length / wallMs) * 1000,
  };
}

// ---------------------------------------------------------------------------
// the machinery alone
// ---------------------------------------------------------------------------

/**
 * Times the judge path against a "model" that answers at once, on a loopback
 * socket. What is left is the proxy's own cost per judged item: building the
 * request, one local round trip, parsing, the limiter.
 */
export async function overhead(
  calls: number,
  concurrency: number,
): Promise<{
  latency: Stats;
  wallMs: number;
}> {
  const server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' }).end(
        JSON.stringify({
          choices: [{ message: { content: '{"label":"benign","confidence":50}' } }],
        }),
      );
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  try {
    const judge = new LimitedJudge({
      inner: new OpenAiChatJudge({
        endpoint: `http://127.0.0.1:${port}/v1/chat/completions`,
        model: 'instant',
        maxInputBytes: 16_384,
      }),
      maxInflight: Math.max(2, concurrency),
      failureThreshold: Number.MAX_SAFE_INTEGER,
      openForMs: 30_000,
      clock: () => Date.now(),
      cacheEntries: 0,
    });
    const times: number[] = [];
    let next = 0;
    const started = performance.now();
    const worker = async (): Promise<void> => {
      for (;;) {
        const index = next++;
        if (index >= calls) return;
        const t0 = performance.now();
        await judge.judge(
          {
            text: `item ${index} ${'x'.repeat(2_000)}`,
            kind: 'tool_result',
            channel: 'bench__judge',
            tier1Score: 50,
          },
          1_500,
        );
        times.push(performance.now() - t0);
      }
    };
    await Promise.all(Array.from({ length: concurrency }, worker));
    return { latency: summarize(times), wallMs: performance.now() - started };
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}
