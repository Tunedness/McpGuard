import { describe, expect, it } from 'vitest';
import { buildAutomaton, search } from './aho-corasick.js';

/**
 * The automaton is what lets the ruleset grow without the scan slowing down, so
 * it has to find every term in one pass — overlaps, suffixes and repeats
 * included.
 */

describe('aho-corasick', () => {
  it('finds a single term where it occurs', () => {
    const a = buildAutomaton([{ id: 'r1', value: 'ignore' }]);
    const matches = search(a, 'please ignore this');

    expect(matches).toHaveLength(1);
    expect(matches[0]?.id).toBe('r1');
    expect(matches[0]?.start).toBe(7);
    expect(matches[0]?.end).toBe(13);
  });

  it('finds overlapping terms in one pass', () => {
    // `he`, `she` and `hers` all end inside `hers`: the classic output-link case.
    const a = buildAutomaton([
      { id: 'he', value: 'he' },
      { id: 'she', value: 'she' },
      { id: 'hers', value: 'hers' },
    ]);
    const ids = search(a, 'hers')
      .map((m) => m.id)
      .sort();

    expect(ids).toEqual(['he', 'hers']);
  });

  it('finds every occurrence of a repeated term', () => {
    const a = buildAutomaton([{ id: 'ab', value: 'ab' }]);

    expect(search(a, 'ababab')).toHaveLength(3);
  });

  it('drops empty terms rather than looping on them', () => {
    const a = buildAutomaton([{ id: 'empty', value: '' }]);

    expect(search(a, 'anything')).toEqual([]);
  });

  it('handles non-ASCII terms', () => {
    const a = buildAutomaton([{ id: 'tr', value: 'talimat' }]);

    expect(search(a, 'onceki talimat yok').map((m) => m.id)).toEqual(['tr']);
  });
});
