import { describe, expect, it } from 'vitest';
import type { Family, Finding, ScanOptions, Severity } from '../types.js';
import { combine, familyCap, WEIGHT_SCALE } from './combine.js';
import { decide } from './decide.js';

/**
 * The arithmetic ADR-009 promises is reproducible. Every case here is either a
 * property of that promise or one of the shapes the cap table exists to stop.
 */

let counter = 0;
function finding(
  family: Family,
  weight: number,
  options: { ruleId?: string; severity?: Severity } = {},
): Finding {
  const at = counter++;
  return {
    ruleId: options.ruleId ?? `${family}.${at}`,
    family,
    severity: options.severity ?? 'medium',
    weight,
    span: { start: at, end: at + 1 },
    evidence: '',
  };
}

const NONE: ReadonlySet<string> = new Set();

describe('combine', () => {
  it('scores nothing as nothing', () => {
    expect(combine({ findings: [], standalone: NONE }).score).toBe(0);
  });

  it('saturates: twenty copies of one rule do not outscore a diverse pair', () => {
    // A document that says "ignore previous instructions" twenty times is not
    // twenty times more suspicious than one that says it once and also hides a
    // beacon. Additive scoring gets this backwards.
    const repeated = Array.from({ length: 20 }, () =>
      finding('signature', 300, { ruleId: 'signature.same' }),
    );
    const diverse = [finding('signature', 300), finding('exfil', 300)];

    expect(combine({ findings: repeated, standalone: NONE }).score).toBeLessThan(
      combine({ findings: diverse, standalone: NONE }).score,
    );
  });

  it('never exceeds 100, whatever it is given', () => {
    const many = Array.from({ length: 50 }, (_, i) =>
      finding('signature', WEIGHT_SCALE, { ruleId: `r${i}` }),
    );

    expect(combine({ findings: many, standalone: NONE }).score).toBeLessThanOrEqual(100);
  });

  it('is order-independent, because the fold sorts first', () => {
    const findings = [finding('exfil', 500), finding('signature', 400), finding('unicode', 300)];
    const forwards = combine({ findings, standalone: NONE }).score;
    const backwards = combine({ findings: [...findings].reverse(), standalone: NONE }).score;

    expect(forwards).toBe(backwards);
  });

  it('damps a verdict that rests on one family with nothing decisive in it', () => {
    // One signature hit is a reason to look, not a reason to stop traffic:
    // security documentation quoting an attack verbatim is that shape far more
    // often than an attack is.
    const alone = combine({ findings: [finding('signature', 800)], standalone: NONE });
    const corroborated = combine({
      findings: [finding('signature', 800), finding('exfil', 100)],
      standalone: NONE,
    });

    expect(alone.corroborated).toBe(false);
    expect(corroborated.corroborated).toBe(true);
    expect(alone.score).toBeLessThan(corroborated.score);
  });

  it('lets a critical standalone rule carry a verdict without a second family', () => {
    const result = combine({
      findings: [finding('unicode', 900, { ruleId: 'uni.tag-block', severity: 'critical' })],
      standalone: new Set(['uni.tag-block']),
    });

    expect(result.corroborated).toBe(true);
  });

  it('caps the imperative family below every other family', () => {
    // The cap is what makes imperative mood a corroborator by construction: it
    // can reach `flag` on its own and never `block`. That is deliberate, because
    // it is the family that fires on README files, CLI help, error messages and
    // Turkish support prose.
    const others: Family[] = ['signature', 'unicode', 'encoding', 'exfil', 'frame'];
    for (const family of others) {
      expect(familyCap('imperative')).toBeLessThan(familyCap(family));
    }
  });

  it('holds a family to its cap however many findings it produces', () => {
    const many = Array.from({ length: 30 }, (_, i) =>
      finding('imperative', 900, { ruleId: `imp.${i}` }),
    );
    const result = combine({ findings: many, standalone: NONE });

    expect(result.families.get('imperative')).toBe(familyCap('imperative'));
  });

  it('produces an integer, never a fraction', () => {
    // ADR-009: a float here is a verdict whose last bit differs between two
    // machines, which is a verdict that cannot be gated without a tolerance.
    for (const weight of [1, 7, 333, 499, 501, 999]) {
      const { score } = combine({ findings: [finding('signature', weight)], standalone: NONE });
      expect(Number.isInteger(score)).toBe(true);
    }
  });

  it('clamps a weight outside the scale instead of letting it through', () => {
    const over = combine({ findings: [finding('signature', 5_000)], standalone: NONE }).score;
    const under = combine({ findings: [finding('signature', -100)], standalone: NONE }).score;

    expect(over).toBeLessThanOrEqual(100);
    expect(under).toBe(0);
  });
});

describe('decide', () => {
  const base: ScanOptions = {
    action: 'flag',
    flagAt: 40,
    blockAt: 70,
    maxBytes: 1_000,
    onDegraded: 'flag',
  };

  it('allows anything below the flag line', () => {
    expect(decide(39, base, false)).toBe('allow');
  });

  it('flags at and above the flag line', () => {
    expect(decide(40, base, false)).toBe('flag');
    expect(decide(69, base, false)).toBe('flag');
  });

  it('still only flags above the block line when the tool is on the default', () => {
    // PRD §8: `block` is opt-in and per-tool. A tool nobody configured gets
    // `flag` however high the score went — the engine decides what it found,
    // the operator decides what enforcement means.
    expect(decide(100, base, false)).toBe('flag');
  });

  it('blocks above the block line when the tool asked for blocking', () => {
    const blocking: ScanOptions = { ...base, action: 'block' };

    expect(decide(70, blocking, false)).toBe('block');
  });

  it('flags rather than blocks between the two lines, even when blocking is on', () => {
    // The band between `flag_at` and `block_at` is the band where the engine is
    // unsure. Blocking there would spend the operator's trust on its weakest
    // evidence.
    const blocking: ScanOptions = { ...base, action: 'block' };

    expect(decide(50, blocking, false)).toBe('flag');
  });

  it('strips from the flag line up when the tool asked for stripping', () => {
    const stripping: ScanOptions = { ...base, action: 'strip' };

    expect(decide(45, stripping, false)).toBe('strip');
    expect(decide(90, stripping, false)).toBe('strip');
  });

  it('never lets a partially scanned item pass as clean', () => {
    // An item too large for full evaluation is not a clean one, and silence is
    // the wrong answer either way.
    expect(decide(0, base, true)).toBe('flag');
    expect(decide(0, { ...base, onDegraded: 'block' }, true)).toBe('block');
  });

  it('honours an explicit decision to let large items through', () => {
    expect(decide(0, { ...base, onDegraded: 'allow' }, true)).toBe('allow');
  });
});
