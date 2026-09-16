import { describe, expect, it } from 'vitest';
import { engineSatisfies, loadRuleset, RulesetLintError, RulesetValidationError } from './index.js';

/**
 * The loader is the trust boundary for data the operator ships to themselves.
 * A bad ruleset is a self-inflicted outage, so these cases are about what it
 * refuses.
 */

const validRule = {
  id: 'inj.test.override',
  category: 'instruction-override',
  family: 'signature',
  pattern: { kind: 'phrase', tokens: ['ignore', 'previous'], maxGap: 2 },
  severity: 'high',
  weight: 600,
  description: 'A test override rule with enough description.',
  testVectors: { match: ['ignore previous'], noMatch: ['nothing here'] },
};

function ruleset(rules: unknown[], engineRange = '^0.0.0'): unknown {
  return { schemaVersion: 1, rulesetVersion: '1.0.0', engineRange, locales: ['en'], rules };
}

describe('loadRuleset', () => {
  it('loads a valid ruleset and digests its rules', () => {
    const loaded = loadRuleset(ruleset([validRule]));

    expect(loaded.ruleCount).toBe(1);
    expect(loaded.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(loaded.rulesetVersion).toBe('1.0.0');
  });

  it('gives the same digest for the same rules and a different one otherwise', () => {
    const a = loadRuleset(ruleset([validRule]));
    const b = loadRuleset(ruleset([{ ...validRule, weight: 601 }]));

    expect(loadRuleset(ruleset([validRule])).digest).toBe(a.digest);
    expect(b.digest).not.toBe(a.digest);
  });

  it('rejects a document that is not a ruleset', () => {
    expect(() => loadRuleset({ nope: true })).toThrow(RulesetValidationError);
  });

  it('rejects a ruleset built for a different engine', () => {
    expect(() => loadRuleset(ruleset([validRule], '^9.0.0'))).toThrow();
  });

  it('refuses a regex rule with an unbounded quantifier', () => {
    // A ruleset is data loaded at runtime; a backtracking pattern is a denial of
    // service the operator ships to themselves.
    const bad = {
      ...validRule,
      id: 'inj.test.redos',
      pattern: { kind: 'regex', source: '(a+)+b', flags: 'i' },
    };

    expect(() => loadRuleset(ruleset([bad]))).toThrow(RulesetLintError);
  });

  it('refuses a regex rule with no usable prefilter', () => {
    const bad = {
      ...validRule,
      id: 'inj.test.noprefilter',
      pattern: { kind: 'regex', source: '\\d{2,4}', flags: 'i' },
    };

    expect(() => loadRuleset(ruleset([bad]))).toThrow(RulesetLintError);
  });
});

describe('engineSatisfies', () => {
  it('accepts an exact match', () => {
    expect(engineSatisfies('0.1.0', '0.1.0')).toBe(true);
    expect(engineSatisfies('0.1.0', '0.1.1')).toBe(false);
  });

  it('treats a pre-1.0 caret as pinning the minor', () => {
    // A 0.x engine can break compatibility on a minor bump, so `^0.1.0` must not
    // be satisfied by 0.2.0.
    expect(engineSatisfies('^0.1.0', '0.1.5')).toBe(true);
    expect(engineSatisfies('^0.1.0', '0.2.0')).toBe(false);
  });

  it('treats a >=1.0 caret as pinning the major', () => {
    expect(engineSatisfies('^1.2.0', '1.9.0')).toBe(true);
    expect(engineSatisfies('^1.2.0', '2.0.0')).toBe(false);
  });
});
