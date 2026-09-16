/**
 * Regex-dialect checks for `regex` rules, run at load and fail-closed.
 *
 * A ruleset is data loaded at runtime, so a pattern with catastrophic
 * backtracking is a denial of service the operator ships to themselves. Three
 * of these checks make the pathological shapes unrepresentable; the fourth
 * derives the prefilter that keeps the regex off the hot path.
 */

/** What is wrong with a pattern, if anything. */
export interface LintProblem {
  readonly ruleId: string;
  readonly message: string;
}

/**
 * Rejects the shapes that backtrack. Returns a problem, or `undefined` if clean.
 *
 * - unbounded quantifiers (`*`, `+`, `{n,}`) — bounded matching cannot blow up,
 *   and a ruleset almost never needs "one or more" that a `{1,64}` would not
 *   serve;
 * - a quantifier applied to a group that itself contains a quantifier — the
 *   `(a+)+` shape, the textbook catastrophe;
 * - backreferences — which force the backtracking engine.
 */
export function lintRegexSource(ruleId: string, source: string): LintProblem | undefined {
  if (/\\[1-9]/.test(source)) {
    return { ruleId, message: 'backreferences are not allowed in a ruleset regex' };
  }
  if (/(?<!\\)[*+]/.test(source) || /\{\d+,\}/.test(source)) {
    return {
      ruleId,
      message: 'unbounded quantifiers (* + {n,}) are not allowed; use a bounded {n,m}',
    };
  }
  if (/\)[*+?]|\)\{\d/.test(source) && /[*+]\)|\{\d[^}]*\}\)/.test(source)) {
    return { ruleId, message: 'a quantified group containing a quantifier can backtrack' };
  }
  return undefined;
}

/**
 * The longest literal run in a regex source, to use as a prefilter.
 *
 * A regex only runs on the segment its prefilter hit, so every regex rule needs
 * a literal ≥ 3 chars. This pulls the longest run of plain characters out of the
 * source; a rule with none is rejected at load rather than allowed to scan every
 * byte.
 */
export function derivePrefilter(source: string): string | undefined {
  const runs = source.match(/[a-z0-9şğıöçü ]{3,}/gi) ?? [];
  let best = '';
  for (const run of runs) {
    const trimmed = run.trim();
    if (trimmed.length > best.length) best = trimmed;
  }
  return best.length >= 3 ? best : undefined;
}
