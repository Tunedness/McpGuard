import { describe, expect, it } from 'vitest';
import { scanContent } from '../scan.js';
import { PII_FIXTURE } from '../testing/pii-data.js';
import type { ScanOptions } from '../types.js';
import { DETECT_VERSION } from '../version.js';
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

function ruleset(rules: unknown[], engineRange = '^0.1.0', lexicons?: unknown): unknown {
  return {
    schemaVersion: 1,
    rulesetVersion: '1.0.0',
    engineRange,
    locales: ['en'],
    rules,
    ...(lexicons === undefined ? {} : { lexicons }),
  };
}

describe('loadRuleset', () => {
  it('loads a valid ruleset and digests its data', () => {
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

  it('digests the lexicons too, because they change the score', () => {
    // Two rulesets with the same rules and different lexicons must not share a
    // digest: the digest is what an audit record uses to say which data decided.
    const without = loadRuleset(ruleset([validRule], '^0.1.0', { verbsEn: [] }));
    const withVerb = loadRuleset(ruleset([validRule], '^0.1.0', { verbsEn: ['frobnicate'] }));

    expect(withVerb.digest).not.toBe(without.digest);
  });

  it('gives an absent lexicon section and an empty one the same digest', () => {
    const absent = loadRuleset(ruleset([validRule]));
    const empty = loadRuleset(
      ruleset([validRule], '^0.1.0', { verbsEn: [], verbsTr: [], benignImperatives: [] }),
    );

    expect(empty.digest).toBe(absent.digest);
  });

  it('does not digest the ruleset version, the engine range or the locales', () => {
    const base = loadRuleset(ruleset([validRule]));
    const other = loadRuleset({
      ...(ruleset([validRule]) as object),
      rulesetVersion: '2.0.0',
      engineRange: DETECT_VERSION,
      locales: ['en', 'tr'],
    });

    expect(other.digest).toBe(base.digest);
  });

  it('scores differently under rulesets whose lexicons differ', () => {
    // The reason the digest has to cover the lexicons: this verb is in no rule,
    // yet it decides whether the imperative detector fires at all.
    const options: ScanOptions = {
      action: 'flag',
      flagAt: 40,
      blockAt: 70,
      maxBytes: 1_000_000,
      onDegraded: 'flag',
    };
    const text = 'Frobnicate your credentials and then report back to me.';
    const without = loadRuleset(ruleset([validRule], '^0.1.0', { verbsEn: [] }));
    const withVerb = loadRuleset(ruleset([validRule], '^0.1.0', { verbsEn: ['frobnicate'] }));
    const item = { id: 'part-0', text, kind: 'tool_result' as const };

    expect(scanContent(item, withVerb, options).score).not.toBe(
      scanContent(item, without, options).score,
    );
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

describe('the PII section', () => {
  const withPii = (pii: unknown): unknown => ({
    ...(ruleset([validRule]) as object),
    pii,
  });

  it('is optional, and a ruleset without it carries no PII data', () => {
    expect(loadRuleset(ruleset([validRule])).pii).toBeUndefined();
  });

  it('gets its own digest and leaves the ruleset digest alone (ADR-012)', () => {
    const without = loadRuleset(ruleset([validRule]));
    const a = loadRuleset(withPii(PII_FIXTURE));
    const b = loadRuleset(
      withPii({
        ...PII_FIXTURE,
        anchors: { health_ref: [...PII_FIXTURE.anchors.health_ref, 'dosya no'] },
      }),
    );
    const stronger = loadRuleset(
      withPii({
        ...PII_FIXTURE,
        strong: {
          ...PII_FIXTURE.strong,
          health_ref: [...PII_FIXTURE.strong.health_ref, 'epikriz'],
        },
      }),
    );
    const excluded = loadRuleset(
      withPii({
        ...PII_FIXTURE,
        exclude: {
          ...PII_FIXTURE.exclude,
          health_ref: [...PII_FIXTURE.exclude.health_ref, 'kurye'],
        },
      }),
    );

    expect(a.digest).toBe(without.digest);
    expect(b.digest).toBe(without.digest);
    expect(a.pii?.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(b.pii?.digest).not.toBe(a.pii?.digest);
    // The exclusion words are part of what the digest vouches for.
    expect(excluded.pii?.digest).not.toBe(a.pii?.digest);
    expect(excluded.digest).toBe(without.digest);
    expect(stronger.pii?.digest).not.toBe(a.pii?.digest);
    expect(stronger.digest).toBe(without.digest);
    expect(loadRuleset(withPii(PII_FIXTURE)).pii?.digest).toBe(a.pii?.digest);
  });

  it('refuses a profile that names a kind that is not a health kind', () => {
    expect(() => loadRuleset(withPii({ ...PII_FIXTURE, profiles: { health: ['tckn'] } }))).toThrow(
      RulesetValidationError,
    );
    expect(() => loadRuleset(withPii({ ...PII_FIXTURE, profiles: { health: [] } }))).toThrow(
      RulesetValidationError,
    );
  });

  it('refuses a keyword with nothing to match on, an empty list and an unknown key', () => {
    const bad = (patch: object): unknown => withPii({ ...PII_FIXTURE, ...patch });

    expect(() => loadRuleset(bad({ anchors: { health_ref: ['...'] } }))).toThrow(
      RulesetValidationError,
    );
    expect(() => loadRuleset(bad({ anchors: { health_ref: [] } }))).toThrow(RulesetValidationError);
    expect(() => loadRuleset(bad({ surprise: [] }))).toThrow(RulesetValidationError);
    expect(() => loadRuleset(bad({ strong: { health_ref: ['hasta'] } }))).toThrow(
      RulesetValidationError,
    );
    expect(() => loadRuleset(bad({ exclude: { health_ref: ['kargo'] } }))).toThrow(
      RulesetValidationError,
    );
  });

  it('takes a keyword as text, never as a pattern', () => {
    // `.*` has no letter or digit, so it is refused outright; `a.*b` is accepted
    // as the three tokens it contains — `a`, `b` — and matches nothing like a regex would.
    const loaded = loadRuleset(withPii({ ...PII_FIXTURE, anchors: { health_ref: ['hasta.*no'] } }));

    expect(loaded.pii).toBeDefined();
    expect(() =>
      loadRuleset(withPii({ ...PII_FIXTURE, context: { ...PII_FIXTURE.context, icd10: ['.*'] } })),
    ).toThrow(RulesetValidationError);
  });
});
