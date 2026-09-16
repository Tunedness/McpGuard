/**
 * Turning ruleset data into something a scan can run against, once.
 *
 * The only place in the package allowed to build a `RegExp` — `purity.test.ts`
 * pins that — because compilation happens here, at load, and never on the hot
 * path.
 */
import { type Automaton, buildAutomaton, type Term } from '../ac/aho-corasick.js';
import { skeletonFold } from '../normalize/fold.js';
import { derivePrefilter, type LintProblem, lintRegexSource } from './lint.js';
import type { Rule } from './schema.js';

/** A phrase rule, compiled to the token list the matcher walks. */
export interface CompiledPhrase {
  readonly rule: Rule;
  readonly tokens: readonly string[];
  readonly maxGap: number;
  readonly prefix: boolean;
}

/** A regex rule, compiled with the prefilter that keeps it off the whole text. */
export interface CompiledRegex {
  readonly rule: Rule;
  readonly regex: RegExp;
  readonly prefilter: string;
}

/** Everything a scan needs, built once. */
export interface CompiledRules {
  readonly automaton: Automaton;
  /** Literal term id → the rule that owns it. */
  readonly literalRules: ReadonlyMap<string, Rule>;
  /** Prefilter literal → the regex rules it gates. */
  readonly regexRules: ReadonlyMap<string, CompiledRegex[]>;
  readonly phrases: readonly CompiledPhrase[];
  /** Prefilter and phrase-token terms that also live in the automaton. */
  readonly standalone: ReadonlySet<string>;
}

/** Folds a pattern string to the surface it will be matched on. */
function fold(value: string, kind: 'case' | 'skeleton'): string {
  const lowered = value.toLowerCase();
  return kind === 'skeleton' ? skeletonFold(lowered) : lowered;
}

/**
 * Compiles the rules. Throws {@link RulesetLintError} on a bad pattern.
 *
 * Every literal and every phrase token and every regex prefilter goes into one
 * automaton, so a single pass over the text finds all of them and the regexes
 * run only where their prefilter hit.
 */
export function compileRules(rules: readonly Rule[]): CompiledRules {
  const problems: LintProblem[] = [];
  const terms: Term[] = [];
  const literalRules = new Map<string, Rule>();
  const regexRules = new Map<string, CompiledRegex[]>();
  const phrases: CompiledPhrase[] = [];
  const standalone = new Set<string>();

  for (const rule of rules) {
    if (rule.standalone) standalone.add(rule.id);
    const pattern = rule.pattern;
    switch (pattern.kind) {
      case 'literal': {
        const value = fold(pattern.value, pattern.fold);
        terms.push({ id: `lit:${rule.id}`, value });
        literalRules.set(`lit:${rule.id}`, rule);
        break;
      }
      case 'phrase': {
        const tokens = pattern.tokens.map((token) => fold(token, pattern.fold));
        // Each token is an automaton term too, so the phrase matcher works off
        // the same single pass rather than scanning the text again.
        for (const token of tokens) {
          terms.push({ id: `tok:${rule.id}:${token}`, value: token });
        }
        phrases.push({
          rule,
          tokens,
          maxGap: pattern.maxGap,
          prefix: pattern.tokenMatch === 'prefix',
        });
        break;
      }
      case 'regex': {
        const problem = lintRegexSource(rule.id, pattern.source);
        if (problem !== undefined) {
          problems.push(problem);
          break;
        }
        const prefilter = pattern.prefilter ?? derivePrefilter(pattern.source);
        if (prefilter === undefined) {
          problems.push({ ruleId: rule.id, message: 'regex rule has no usable prefilter literal' });
          break;
        }
        const folded = fold(prefilter, 'case');
        const compiled: CompiledRegex = {
          rule,
          // Built here, once, with any global/sticky flag stripped so `exec` is
          // stateless and the scan never has to rebuild it or reset lastIndex.
          regex: new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, '')),
          prefilter: folded,
        };
        const bucket = regexRules.get(folded);
        if (bucket === undefined) regexRules.set(folded, [compiled]);
        else bucket.push(compiled);
        terms.push({ id: `pre:${rule.id}`, value: folded });
        break;
      }
    }
  }

  if (problems.length > 0) throw new RulesetLintError(problems);

  return {
    automaton: buildAutomaton(terms),
    literalRules,
    regexRules,
    phrases,
    standalone,
  };
}

/** A ruleset that carried a pattern the loader refuses to run. */
export class RulesetLintError extends Error {
  readonly problems: readonly LintProblem[];

  constructor(problems: readonly LintProblem[]) {
    super(
      `ruleset has ${problems.length} unsafe pattern(s): ${problems
        .map((p) => `${p.ruleId} (${p.message})`)
        .join('; ')}`,
    );
    this.name = 'RulesetLintError';
    this.problems = problems;
  }
}
