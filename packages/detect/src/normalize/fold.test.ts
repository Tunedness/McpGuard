import { describe, expect, it } from 'vitest';
import { caseFold, rawSpan, skeletonFold } from './fold.js';

/**
 * The fold is where Turkish determinism is won or lost. Every case here is a
 * spelling the platform's own `toLowerCase` would get wrong.
 */

describe('caseFold', () => {
  it('folds the dotted capital I to a single i, not i plus a combining dot', () => {
    // `'İ'.toLowerCase()` is two code points, which shifts every later offset.
    const folded = caseFold('İZMİR');

    expect(folded.text).toBe('izmir');
    expect(folded.text.length).toBe(5);
    expect(folded.offsets).toHaveLength(5);
  });

  it('folds a dotless capital I the Turkish way', () => {
    expect(caseFold('IRMAK').text).toBe('ırmak');
  });

  it('keeps an offset back to the raw character for each folded unit', () => {
    const folded = caseFold('AB');

    expect(folded.offsets).toEqual([0, 1]);
  });
});

describe('skeletonFold', () => {
  it('strips Turkish diacritics so a deasciified spelling still matches', () => {
    expect(skeletonFold('önceki talimatları')).toBe('onceki talimatlari');
  });

  it('folds Cyrillic homoglyphs to their Latin look-alikes', () => {
    // The attacker swapping `o` for a Cyrillic `о` is hiding a word, not writing
    // Russian; the skeleton fold is where that is undone.
    expect(skeletonFold('іgnоrе')).toBe('ignore');
  });
});

describe('rawSpan', () => {
  it('maps a folded span back to the raw offsets it came from', () => {
    const folded = caseFold('the cat');
    const span = rawSpan(folded.offsets, 4, 7);

    expect(span).toEqual({ start: 4, end: 7 });
  });

  it('survives an empty offset map', () => {
    expect(rawSpan([], 0, 5)).toEqual({ start: 0, end: 0 });
  });
});
