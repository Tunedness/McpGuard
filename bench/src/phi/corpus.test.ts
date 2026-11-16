import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRuleset } from '@tunedness/mcpguard-detect';
import { loadRulesetData } from '@tunedness/mcpguard-ruleset';
import { describe, expect, it } from 'vitest';
import { generateCorpus, toJsonl } from './corpus.js';
import { detections, measure, optionsFor } from './replay.js';
import { checkGates } from './report.js';
import { NEGATIVE_FAMILIES, PHI_KINDS, POSITIVE_FAMILIES } from './types.js';

/**
 * The PHI corpus is committed, and these tests are what let it be trusted: that
 * it regenerates byte for byte, that every label points at what it says, that
 * its traps are present — and that the recognisers meet ADR-012's gates on it.
 */

const CORPUS_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'phi',
  'corpus.jsonl',
);

/** Pinned. If the generator changes what it emits, this is where it shows. */
const CORPUS_SHA256 = 'ab457b6b9f26553afa3ca0b46d6af12b0c5e355b9b85fb44419cf803c14476da';

const sha256 = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

describe('PHI corpus', () => {
  it('regenerates byte-for-byte, so the committed file is reproducible', () => {
    expect(sha256(toJsonl(generateCorpus()))).toBe(CORPUS_SHA256);
  });

  it('matches the file that is committed', () => {
    expect(sha256(readFileSync(CORPUS_PATH, 'utf8'))).toBe(CORPUS_SHA256);
  });

  it('covers every positive and negative family', () => {
    const families = new Set(generateCorpus().map((item) => item.family));
    for (const family of [...POSITIVE_FAMILIES, ...NEGATIVE_FAMILIES]) {
      expect(families.has(family)).toBe(true);
    }
  });

  it('labels spans that sit inside the text and carry a recogniser kind', () => {
    for (const item of generateCorpus()) {
      for (const span of item.spans) {
        expect(PHI_KINDS).toContain(span.kind);
        expect(span.start).toBeGreaterThanOrEqual(0);
        expect(span.end).toBeGreaterThan(span.start);
        expect(span.end).toBeLessThanOrEqual(item.text.length);
      }
      if (item.label === 'negative') expect(item.spans).toEqual([]);
      else expect(item.spans.length).toBeGreaterThan(0);
    }
  });

  it('has enough of each kind to measure its gate', () => {
    // A recall gate of 0.99 needs at least a hundred labelled spans to have a
    // resolution finer than a single miss.
    const items = generateCorpus();
    for (const kind of PHI_KINDS) {
      const spans = items.flatMap((item) => item.spans).filter((span) => span.kind === kind);
      expect(spans.length).toBeGreaterThanOrEqual(100);
    }
  });

  it('keeps the traps in: bare retail barcodes and context-free codes are negatives', () => {
    const items = generateCorpus();
    expect(
      items.some((i) => i.family === 'retail-barcodes' && /Barkod: 869\d{10}/.test(i.text)),
    ).toBe(true);
    expect(
      items.some((i) => i.family === 'anchor-without-number' && i.text.includes('numaranızı')),
    ).toBe(true);
    expect(items.some((i) => i.family === 'product-codes' && i.text.includes('B12'))).toBe(true);
  });

  it('gates the keyword collisions and keeps only the holdout out of the gate', () => {
    // An anchor word used outside medicine is a false positive like any other, so
    // the family counts. Only the holdout is exempt, because it exists to measure
    // the exclusion lists and must not be what they are tuned on.
    const items = generateCorpus();
    const collisions = items.filter((i) => i.family === 'keyword-collisions');
    const holdout = items.filter((i) => i.family === 'keyword-collisions-holdout');

    expect(collisions.length).toBeGreaterThan(0);
    expect(collisions.every((i) => i.gated)).toBe(true);
    expect(holdout.length).toBeGreaterThan(0);
    expect(holdout.every((i) => !i.gated)).toBe(true);
    // The only items outside the gates: the holdout, and the ambiguous-anchor
    // positives whose recall is reported on its own.
    expect(
      items
        .filter((i) => !i.gated)
        .every(
          (i) => i.family === 'keyword-collisions-holdout' || i.family === 'ambiguous-anchor-mixed',
        ),
    ).toBe(true);
  });

  it('writes the holdout in wording the exclusion lists do not carry', () => {
    const data = readFileSync(
      join(
        dirname(fileURLToPath(import.meta.url)),
        '..',
        '..',
        '..',
        'packages',
        'ruleset',
        'pii',
        'context.en.json',
      ),
      'utf8',
    ).toLowerCase();
    const holdout = generateCorpus().filter((i) => i.family === 'keyword-collisions-holdout');

    // None of the words the holdout hinges on is in an exclusion list.
    for (const word of ['gönderisi', 'office fire', 'warehouse flood', 'denetim', 'kek tarifi']) {
      expect(data).not.toContain(word);
    }
    expect(holdout.some((i) => i.text.includes('PTT'))).toBe(true);
  });

  it('holds an exclusion-mixed positive for every exclusion word in the ruleset', () => {
    // A word added to an exclusion list without a positive that sits beside it is
    // recall nobody measured. This keeps the table and the lists the same size.
    const fold = (text: string): string =>
      text
        .toLowerCase()
        .replace(/[çğıöşü]/g, (c) => ({ ç: 'c', ğ: 'g', ı: 'i', ö: 'o', ş: 's', ü: 'u' })[c] ?? c)
        .replace(/[^a-z0-9]+/g, ' ');
    const root = join(
      dirname(fileURLToPath(import.meta.url)),
      '..',
      '..',
      '..',
      'packages',
      'ruleset',
      'pii',
    );
    const words = new Set<string>();
    for (const locale of ['tr', 'en']) {
      const data = JSON.parse(readFileSync(join(root, `context.${locale}.json`), 'utf8')) as {
        exclude: Record<string, string[]>;
      };
      for (const list of Object.values(data.exclude)) for (const word of list) words.add(word);
    }
    const mixed = generateCorpus().filter((i) => i.family === 'exclusion-mixed');
    const texts = mixed.map((i) => ` ${fold(i.text)} `);

    expect(words.size).toBeGreaterThan(20);
    for (const word of words) {
      expect(
        texts.some((t) => t.includes(` ${fold(word).trim()} `)),
        word,
      ).toBe(true);
    }
    expect(mixed.every((i) => i.spans.length === 1)).toBe(true);
  });

  it('holds a mixed positive for every strong reference word in the ruleset', () => {
    const fold = (text: string): string =>
      text
        .toLowerCase()
        .replace(/[çğıöşü]/g, (c) => ({ ç: 'c', ğ: 'g', ı: 'i', ö: 'o', ş: 's', ü: 'u' })[c] ?? c)
        .replace(/[^a-z0-9]+/g, ' ');
    const root = join(
      dirname(fileURLToPath(import.meta.url)),
      '..',
      '..',
      '..',
      'packages',
      'ruleset',
      'pii',
    );
    const words = new Set<string>();
    for (const locale of ['tr', 'en']) {
      const data = JSON.parse(readFileSync(join(root, `context.${locale}.json`), 'utf8')) as {
        strong: { health_ref: string[] };
      };
      for (const word of data.strong.health_ref) words.add(word);
    }
    const texts = generateCorpus()
      .filter((i) => i.family === 'exclusion-mixed')
      .map((i) => ` ${fold(i.text)} `);

    for (const word of words) {
      expect(
        texts.some((t) => t.includes(` ${fold(word).trim()} `)),
        word,
      ).toBe(true);
    }
  });

  it('keeps the accepted false positive in the corpus as a negative, and counts it', () => {
    const accepted = generateCorpus().filter((i) => i.accepted !== undefined);
    const metrics = measure(
      generateCorpus(),
      detections(generateCorpus(), loadRuleset(loadRulesetData()), optionsFor(true)),
    );

    expect(accepted.length).toBeGreaterThan(0);
    expect(accepted.every((i) => i.label === 'negative' && i.gated)).toBe(true);
    expect(accepted.every((i) => i.text.includes('claim number'))).toBe(true);
    // They fire, and the fires are inside the rate over all negatives.
    expect(metrics.health_ref.acceptedFires).toBe(accepted.length);
    expect(metrics.health_ref.negativeFires).toBeGreaterThanOrEqual(accepted.length);
    expect(metrics.health_ref.falsePositiveRate).toBeLessThan(0.01);
  });

  it("gates the rate over all negatives, and reports the rate over a kind's own traps without gating it", () => {
    const items = generateCorpus();
    const metrics = measure(
      items,
      detections(items, loadRuleset(loadRulesetData()), optionsFor(true)),
    );
    const gate = checkGates(metrics).find((g) => g.kind === 'health_ref');

    // The accepted `claim ... courier` template makes the trap rate exceed 1%; the
    // gate is the rate over all negatives, which includes those same items.
    expect(metrics.health_ref.trapFalsePositiveRate).toBeGreaterThan(0.01);
    expect(metrics.health_ref.falsePositiveRate).toBeLessThanOrEqual(0.01);
    expect(metrics.health_ref.negativeFires).toBeGreaterThanOrEqual(
      metrics.health_ref.acceptedFires,
    );
    expect(gate?.met).toBe(true);
    expect(gate?.reasons).toEqual([]);
  });

  it('measures the recall the exclusion lists cost, outside the recall gate', () => {
    const items = generateCorpus();
    const ambiguous = items.filter((i) => i.family === 'ambiguous-anchor-mixed');
    const metrics = measure(
      items,
      detections(items, loadRuleset(loadRulesetData()), optionsFor(true)),
    );

    expect(ambiguous.length).toBeGreaterThan(0);
    expect(ambiguous.every((i) => i.label === 'positive' && !i.gated)).toBe(true);
    expect(metrics.health_ref.ambiguousSpans).toBeGreaterThan(0);
    expect(metrics.health_date.ambiguousSpans).toBeGreaterThan(0);
    // They are not in the recall denominator.
    expect(metrics.health_ref.spans).not.toBe(
      metrics.health_ref.spans + metrics.health_ref.ambiguousSpans,
    );
  });

  it('puts a slash, dot and underscore reference and a symbology-prefixed GS1 run in the positives', () => {
    const positives = generateCorpus().filter((i) => i.label === 'positive');

    expect(
      positives.some((i) => i.spans.some((s) => /\d{4}\/\d+/.test(i.text.slice(s.start, s.end)))),
    ).toBe(true);
    expect(positives.some((i) => /\]d2|\]C1|\]Q3/.test(i.text))).toBe(true);
    expect(positives.some((i) => i.text.includes('(01) '))).toBe(true);
  });
});

describe('PHI recognisers against the corpus (ADR-012 gates, no tolerance)', () => {
  const corpus = generateCorpus();
  const ruleset = loadRuleset(loadRulesetData());
  const metrics = measure(corpus, detections(corpus, ruleset, optionsFor(true)));

  it.each(checkGates(metrics).filter((g) => g.gated))(
    '$kind meets its recall and false-positive gate',
    (gate) => {
      expect(gate.reasons).toEqual([]);
      expect(gate.met).toBe(true);
    },
  );

  it('never fires a checksum-gated recogniser on a negative at the default setting', () => {
    expect(metrics.gs1_serial.negativeFires).toBe(0);
    expect(metrics.mbi_us.negativeFires).toBe(0);
  });

  it('measures the loose operating point too, where a wrong GTIN needs a keyword to be masked', () => {
    const loose = measure(corpus, detections(corpus, ruleset, optionsFor(false)));

    // The broken-GTIN traps carry no GS1 keyword, so loosening the checksum does
    // not make them fire. (The rescue itself is pinned in gs1.test.ts.)
    expect(loose.gs1_serial.negativeFires).toBe(0);
    expect(loose.gs1_serial.recall).toBeGreaterThanOrEqual(0.99);
  });
});
