import { loadRuleset, scanContent } from '@mcpguard/detect';
import { loadRulesetData } from '@mcpguard/ruleset';
import { describe, expect, it } from 'vitest';

/**
 * Every rule ships the strings that must and must not match it, and this is
 * where that promise is kept. It tests the **pattern**, not the verdict: a
 * `match` vector must make the rule fire, a `noMatch` vector must not. Whether a
 * document quoting an attack gets blocked is the corpus's job — conflating the
 * two would make a rule impossible to write.
 */

const data = loadRulesetData() as {
  rules: {
    id: string;
    contentKinds?: string[];
    testVectors: { match: string[]; noMatch: string[] };
  }[];
};
const ruleset = loadRuleset(data);

/** Whether scanning `text` produces a finding from `ruleId`. */
function fires(ruleId: string, text: string, kind: 'tool_result'): boolean {
  const verdict = scanContent({ id: 't', text, kind }, ruleset, {
    action: 'flag',
    flagAt: 40,
    blockAt: 70,
    maxBytes: 262_144,
    onDegraded: 'flag',
  });
  // Signature findings carry the rule id verbatim; a rule fires if its id shows
  // up, or (for the base64 re-scan path) as the tail of a via-decode finding.
  return verdict.findings.some((f) => f.ruleId === ruleId || f.evidence.includes(ruleId));
}

describe('ruleset test vectors', () => {
  it('ships at least the injection rules the engine was built against', () => {
    expect(data.rules.length).toBeGreaterThanOrEqual(12);
  });

  for (const rule of data.rules) {
    describe(rule.id, () => {
      for (const text of rule.testVectors.match) {
        it(`matches: ${text.slice(0, 40)}`, () => {
          expect(fires(rule.id, text, 'tool_result')).toBe(true);
        });
      }
      for (const text of rule.testVectors.noMatch) {
        it(`does not match: ${text.slice(0, 40)}`, () => {
          expect(fires(rule.id, text, 'tool_result')).toBe(false);
        });
      }
    });
  }
});
