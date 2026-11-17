import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  askJudge,
  BAND_FROM,
  distribute,
  histogram,
  inBand,
  overhead,
  report,
  type Scored,
} from './measure.js';
import { PARAPHRASES } from './paraphrases.js';
import { judgeDefaults, modelRunOptions, prepare, v5 } from './run.js';

const HERE = dirname(fileURLToPath(import.meta.url));

function scored(score: number, corroborated = true, id = `i${score}`): Scored {
  return { id, group: 'g', locale: 'en', score, corroborated, maskedText: `text ${id}` };
}

describe('the paraphrase set', () => {
  it('is balanced: eight families, four English and four Turkish each, unique ids', () => {
    expect(PARAPHRASES).toHaveLength(64);
    expect(new Set(PARAPHRASES.map((p) => p.id)).size).toBe(64);
    const families = new Set(PARAPHRASES.map((p) => p.family));
    expect(families.size).toBe(8);
    for (const family of families) {
      const own = PARAPHRASES.filter((p) => p.family === family);
      expect(own.filter((p) => p.locale === 'en')).toHaveLength(4);
      expect(own.filter((p) => p.locale === 'tr')).toHaveLength(4);
    }
  });
});

describe('what a model run uses when a flag is left out', () => {
  it('is the product default, read from the schema', () => {
    const defaults = judgeDefaults();
    expect(modelRunOptions([])).toEqual({
      timeoutMs: defaults.timeout,
      effort: defaults.reasoning_effort,
      maxTokens: defaults.max_tokens,
      levels: [defaults.max_inflight],
    });
    expect(modelRunOptions([])).toMatchObject({ timeoutMs: 5_000, effort: 'none', levels: [1] });
  });

  it('takes a flag over the default, including `omit`', () => {
    expect(
      modelRunOptions(['--timeout', '800', '--reasoning-effort', 'omit', '--concurrency', '1,2']),
    ).toMatchObject({ timeoutMs: 800, effort: 'omit', levels: [1, 2] });
    expect(() => modelRunOptions(['--reasoning-effort', 'extreme'])).toThrow(/must be one of/);
  });
});

describe('the distribution', () => {
  it('puts every score in exactly one bucket', () => {
    const items = [0, 5, 25, 45, 80].flatMap((s) => [scored(s, true), scored(s, false)]);
    expect(histogram(items).reduce((sum, b) => sum + b.count, 0)).toBe(items.length);
  });

  it('prices a band_from by the benign items it would send, and reaches a leak only below flag_at', () => {
    const paraphrases = [scored(0), scored(0), scored(25), scored(50)];
    const benign = [scored(0), scored(15), scored(30), scored(45), scored(90, false)];
    const d = distribute(paraphrases, benign);
    expect(d.leaks).toBe(3);
    expect(d.pileAtZero).toBeCloseTo(2 / 3);
    const at = (bandFrom: number) => d.bands.find((b) => b.bandFrom === bandFrom);
    expect(at(40)?.leaksInBand).toBe(0);
    expect(at(40)?.benignInBand).toBe(2);
    expect(at(20)?.leaksInBand).toBe(1);
    expect(at(20)?.benignInBand).toBe(3);
    expect(at(0)?.leaksInBand).toBe(3);
    expect(at(0)?.benignInBand).toBe(5);
    expect(BAND_FROM).toContain(0);
  });

  it('agrees with the runtime about who is in the band', () => {
    expect(inBand(scored(90, false), 40)).toBe(true);
    expect(inBand(scored(90, true), 0)).toBe(false);
    expect(inBand(scored(39), 40)).toBe(false);
  });

  it('calls V5 refuted exactly when the majority of leaks score 0', () => {
    const verdict = (zeros: number, others: number) =>
      v5(
        distribute(
          [
            ...Array.from({ length: zeros }, () => scored(0)),
            ...Array.from({ length: others }, () => scored(20)),
          ],
          [],
        ),
      ).held;
    expect(verdict(5, 5)).toBe(true);
    expect(verdict(6, 4)).toBe(false);
    expect(verdict(0, 3)).toBe(true);
  });

  it('is the one committed in bench/judge, so a change in what tier 1 scores is seen', () => {
    // If this fails after a ruleset change, regenerate with `npm run bench:judge`
    // and read the V5 line before committing: ADR-012's band default rests on it.
    const { paraphrases, benign } = prepare();
    const committed = JSON.parse(
      readFileSync(join(HERE, '..', '..', 'judge', 'distribution.json'), 'utf8'),
    );
    expect(JSON.parse(JSON.stringify(distribute(paraphrases, benign)))).toEqual(committed);
  });
});

describe('the model measurement, against a stand-in server', () => {
  it('counts outcomes, reads the latency curve and the answers', async () => {
    let n = 0;
    const server = createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        const index = n++;
        const answer = (label: string) =>
          res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({
              choices: [{ message: { content: `{"label":"${label}","confidence":80}` } }],
            }),
          );
        // The fourth call is slow and the fifth is garbage; the rest answer at once.
        if (index === 3) return void setTimeout(() => answer('benign'), 60);
        if (index === 4) return void res.writeHead(500).end('{}');
        answer(index % 2 === 0 ? 'injection' : 'benign');
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    try {
      const items = [
        ...[0, 1, 2].map((i) => ({ ...scored(0, true, `p${i}`), positive: true })),
        ...[0, 1, 2].map((i) => ({ ...scored(0, true, `n${i}`), positive: false, locale: 'tr' })),
      ];
      const { judged, wallMs } = await askJudge(items, {
        endpoint: `http://127.0.0.1:${port}/v1/chat/completions`,
        model: 'stand-in',
        timeoutMs: 2_000,
        concurrency: 1,
        maxInflight: 1,
      });
      const r = report(judged, wallMs);
      expect(r.n).toBe(6);
      expect(r.outcomes.error).toBe(1);
      expect((r.outcomes.injection ?? 0) + (r.outcomes.benign ?? 0)).toBe(5);
      expect(r.latency?.n).toBe(5);
      expect(r.slowerThan.find((s) => s.ms === 250)?.share).toBe(0);
      expect(r.paraphraseRecall).toBeCloseTo(2 / 3);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('says why calls failed, and reports no latency when none was answered', async () => {
    const server = createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        // A thinking model that spent its budget thinking: empty content, cut off by length.
        res
          .writeHead(200, { 'content-type': 'application/json' })
          .end(
            '{"choices":[{"finish_reason":"length","message":{"content":"","reasoning":"..."}}]}',
          );
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    try {
      const { judged, wallMs } = await askJudge(
        [0, 1, 2].map((i) => ({ ...scored(0, true, `p${i}`), positive: true })),
        {
          endpoint: `http://127.0.0.1:${port}/v1/chat/completions`,
          model: 'thinker',
          timeoutMs: 2_000,
          concurrency: 1,
          maxInflight: 1,
        },
      );
      const r = report(judged, wallMs);
      expect(r.answered).toBe(0);
      expect(r.errorReasons).toEqual({ output_truncated: 3 });
      expect(r.latency).toBeUndefined();
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('times the machinery on its own', async () => {
    const result = await overhead(30, 2);
    expect(result.latency.n).toBe(30);
    expect(result.latency.p50).toBeGreaterThan(0);
    expect(result.latency.p50).toBeLessThan(500);
  });
});
