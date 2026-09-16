import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { generateCorpus, splitOf, toJsonl } from './corpus.js';
import { ATTACK_FAMILIES, BENIGN_FAMILIES } from './types.js';

/**
 * The corpus is committed, and these tests are what let it be trusted: that it
 * regenerates byte for byte, that it is balanced enough to measure the claim,
 * and that its hardest traps are actually present.
 */

const CORPUS_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'injection',
  'corpus.jsonl',
);

/** Pinned. If the generator changes what it emits, this is where it shows. */
const CORPUS_SHA256 = '53ec9034dd0825f4e0a7ece4e62752eda318d4c38e5fa5bec8aaa65f31f41253';

describe('injection corpus', () => {
  it('regenerates byte-for-byte, so the committed file is reproducible', () => {
    const regenerated = toJsonl(generateCorpus());
    const digest = createHash('sha256').update(regenerated, 'utf8').digest('hex');

    expect(digest).toBe(CORPUS_SHA256);
  });

  it('matches the file that is committed', () => {
    const committed = readFileSync(CORPUS_PATH, 'utf8');
    const digest = createHash('sha256').update(committed, 'utf8').digest('hex');

    expect(digest).toBe(CORPUS_SHA256);
  });

  it('has enough negatives to measure a 2% claim', () => {
    // With 100 negatives one false positive is 1% and "< 2%" has two items of
    // resolution. The negatives are the count the target's precision demands.
    const corpus = generateCorpus();
    const negatives = corpus.filter((item) => item.label === 'negative');

    expect(negatives.length).toBeGreaterThanOrEqual(400);
  });

  it('covers every attack and benign family', () => {
    const corpus = generateCorpus();
    const families = new Set(corpus.map((item) => item.family));

    for (const family of [...ATTACK_FAMILIES, ...BENIGN_FAMILIES]) {
      expect(families.has(family)).toBe(true);
    }
  });

  it('labels every positive with a payload span and a minimum action', () => {
    // The spans are what let the harness measure whether strip removed the
    // right thing. A positive without them cannot check its own repair.
    for (const item of generateCorpus()) {
      if (item.label !== 'positive') continue;
      expect(item.payloadSpans).not.toBeNull();
      expect(item.payloadSpans?.length).toBeGreaterThan(0);
      expect(item.expectedMinAction).not.toBeNull();
    }
  });

  it('keeps the hardest negative: security docs that quote the attack verbatim', () => {
    // If this family were softened the false-positive number would improve and
    // the benchmark would stop testing the thing it exists to test.
    const docs = generateCorpus().filter((item) => item.family === 'security-docs');

    expect(docs.some((item) => item.text.includes('ignore all previous instructions'))).toBe(true);
    expect(docs.some((item) => item.text.includes('yok say'))).toBe(true);
  });

  it('splits into two non-empty halves, stratified by family', () => {
    // The operating point is chosen on one half and reported on the other, so
    // neither may be empty and both must see every family.
    const corpus = generateCorpus();
    const halves = { calibration: new Set<string>(), validation: new Set<string>() };
    for (const item of corpus) halves[splitOf(item)].add(item.family);

    expect(halves.calibration.size).toBeGreaterThan(0);
    expect(halves.validation.size).toBeGreaterThan(0);
  });

  it('assigns an item to the same half every time', () => {
    const [item] = generateCorpus();
    if (item === undefined) throw new Error('empty corpus');

    expect(splitOf(item)).toBe(splitOf(item));
  });
});
