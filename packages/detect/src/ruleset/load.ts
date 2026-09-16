/**
 * Validating, digesting and compiling a ruleset, fail-closed.
 *
 * The ruleset arrives as an already-parsed object — this package reads no
 * files, the CLI and the bench do. Load validates it, checks it targets this
 * engine, computes a digest so any decision can be reproduced against the exact
 * rules that made it, and compiles the patterns once.
 */
import type { z } from 'zod';
import { sha256 } from '../util/hash.js';
import { stableStringify, toJsonValue } from '../util/json.js';
import { DETECT_VERSION } from '../version.js';
import { type CompiledRules, compileRules } from './compile.js';
import { type Lexicons, type Rule, RulesetSchema } from './schema.js';

/** A ruleset that has been validated, digested and compiled. */
export interface LoadedRuleset {
  readonly rulesetVersion: string;
  readonly digest: string;
  readonly ruleCount: number;
  readonly rules: readonly Rule[];
  readonly compiled: CompiledRules;
  readonly standalone: ReadonlySet<string>;
  readonly lexicons: CompiledLexicons;
}

/** Lexicons with the string lists turned into the sets the detectors use. */
export interface CompiledLexicons {
  readonly verbsEn: ReadonlySet<string>;
  readonly verbsTr: ReadonlySet<string>;
  readonly benignImperatives: readonly string[];
}

/** A ruleset document that did not validate. */
export class RulesetValidationError extends Error {
  readonly issues: readonly z.core.$ZodIssue[];

  constructor(issues: readonly z.core.$ZodIssue[]) {
    super(
      `the ruleset is not valid — ${issues
        .slice(0, 5)
        .map((i) => i.message)
        .join('; ')}`,
    );
    this.name = 'RulesetValidationError';
    this.issues = issues;
  }
}

/** A ruleset built for an engine this one cannot promise to match. */
export class RulesetEngineError extends Error {
  constructor(range: string) {
    super(`the ruleset targets engine ${range}, but this is @mcpguard/detect ${DETECT_VERSION}`);
    this.name = 'RulesetEngineError';
  }
}

/**
 * Loads a ruleset.
 *
 * @throws {RulesetValidationError} when the document is not a valid ruleset.
 * @throws {RulesetEngineError} when it targets a different engine.
 * @throws {RulesetLintError} when a pattern is unsafe to run.
 */
export function loadRuleset(document: unknown): LoadedRuleset {
  const result = RulesetSchema.safeParse(document);
  if (!result.success) throw new RulesetValidationError(result.error.issues);
  const data = result.data;

  if (!engineSatisfies(data.engineRange, DETECT_VERSION)) {
    throw new RulesetEngineError(data.engineRange);
  }

  // Digest over the canonical form of the rules only: the version and the
  // engine range describe the package, the rules are what made the decision.
  const digest = sha256(stableStringify(toJsonValue(data.rules)));
  const compiled = compileRules(data.rules);

  return {
    rulesetVersion: data.rulesetVersion,
    digest,
    ruleCount: data.rules.length,
    rules: data.rules,
    compiled,
    standalone: compiled.standalone,
    lexicons: compileLexicons(data.lexicons),
  };
}

/** Turns the lexicon string lists into the sets the detectors read. */
function compileLexicons(lexicons: Lexicons): CompiledLexicons {
  return {
    verbsEn: new Set(lexicons.verbsEn.map((v) => v.toLowerCase())),
    verbsTr: new Set(lexicons.verbsTr.map((v) => v.toLowerCase())),
    benignImperatives: lexicons.benignImperatives.map((v) => v.toLowerCase()),
  };
}

/**
 * A deliberately small semver-range check, so `zod` stays the only dependency.
 *
 * Handles the two forms a ruleset actually uses: a caret range (`^0.1.0`) and a
 * bare version. `0.x` is treated the way semver does — a caret on a `0.y.z`
 * pins the minor — because a pre-1.0 engine can and will break compatibility on
 * a minor bump.
 */
export function engineSatisfies(range: string, version: string): boolean {
  const target = parseVersion(version);
  if (target === undefined) return false;
  const caret = range.startsWith('^');
  const base = parseVersion(caret ? range.slice(1) : range);
  if (base === undefined) return false;
  if (!caret) {
    return base[0] === target[0] && base[1] === target[1] && base[2] === target[2];
  }
  if (target[0] !== base[0]) return false;
  if (base[0] === 0) {
    // Pre-1.0: the minor is the compatibility line.
    if (target[1] !== base[1]) return false;
    return atLeast(target, base);
  }
  return atLeast(target, base);
}

function parseVersion(value: string): [number, number, number] | undefined {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(value);
  if (match === null) return undefined;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function atLeast(
  a: readonly [number, number, number],
  b: readonly [number, number, number],
): boolean {
  if (a[0] !== b[0]) return a[0] > b[0];
  if (a[1] !== b[1]) return a[1] > b[1];
  return a[2] >= b[2];
}
