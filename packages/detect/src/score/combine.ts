/**
 * Turning a bag of findings into one number, reproducibly.
 *
 * Two rules govern the arithmetic and both exist so the number is the same on
 * every machine that computes it (ADR-009).
 *
 * **Saturating, and over distinct rules rather than occurrences.** Findings
 * fold by noisy-OR, and each rule contributes once however often it matched. A
 * document that says "ignore previous instructions" twenty times is not twenty
 * times more suspicious than one that says it once and also hides a beacon —
 * and without the first of those two rules it scores higher, which was measured
 * rather than imagined.
 *
 * **Integer throughout.** Weights are 0–1000, the fold is integer division, and
 * findings are sorted before folding so the order is fixed. The sibling tool
 * had to give its CI gate a tolerance because int8 kernels are not bit-identical
 * across architectures; this tier carries no model, so it can promise the same
 * verdict everywhere and gate on exactly that.
 */
import type { Family, Finding } from '../types.js';

/** The scale weights live on. */
export const WEIGHT_SCALE = 1000;

/** Per-family ceilings, so no single family can carry a verdict on its own. */
const FAMILY_CAP: Record<Family, number> = {
  signature: 900,
  /**
   * The lowest cap in the table, and the most deliberate.
   *
   * Imperative mood is the highest-false-positive family there is: README
   * files, CLI help, error messages telling you which command to run, and — in
   * the primary market — Turkish support and administrative prose, which is
   * saturated with polite imperatives. Capping it here makes it a corroborator
   * by construction: it can reach `flag` alone and never `block`.
   */
  imperative: 550,
  unicode: 950,
  encoding: 900,
  exfil: 850,
  frame: 800,
  /** Cheap structural hints. Never enough on their own. */
  anomaly: 400,
};

/** Findings that may carry a verdict without corroboration. */
export interface CombineInput {
  readonly findings: readonly Finding[];
  /** Rule ids the ruleset marked `standalone`. */
  readonly standalone: ReadonlySet<string>;
}

/** The score, plus the working an operator can check it against. */
export interface CombinedScore {
  /** 0–100, integer. */
  readonly score: number;
  /** Per-family subtotals on the 0–1000 scale, for the report. */
  readonly families: ReadonlyMap<Family, number>;
  /** False when a single family produced everything and none of it was decisive. */
  readonly corroborated: boolean;
}

/**
 * Noisy-OR over integers: `1000 − Π(1000 − wᵢ) / 1000^(n−1)`.
 *
 * Written as a running fold so the division happens once per term and the
 * intermediate never leaves the safe-integer range.
 */
function noisyOr(weights: readonly number[]): number {
  let remaining = WEIGHT_SCALE;
  for (const weight of weights) {
    const clamped = weight < 0 ? 0 : weight > WEIGHT_SCALE ? WEIGHT_SCALE : weight;
    remaining = Math.floor((remaining * (WEIGHT_SCALE - clamped)) / WEIGHT_SCALE);
    if (remaining === 0) break;
  }
  return WEIGHT_SCALE - remaining;
}

/** Sorts findings into the one order the fold is defined over. */
function ordered(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      a.family.localeCompare(b.family) ||
      a.ruleId.localeCompare(b.ruleId) ||
      a.span.start - b.span.start ||
      a.span.end - b.span.end,
  );
}

/**
 * Combines findings into a 0–100 score.
 *
 * A verdict built from one family, with nothing in it the ruleset called
 * decisive, is damped: one signature hit is a reason to look, not a reason to
 * stop traffic, and security documentation quoting an attack verbatim is the
 * shape that hit looks like far more often than an attack is.
 */
export function combine(input: CombineInput): CombinedScore {
  // Distinct rules, not distinct findings. One rule matching twenty times is
  // one piece of evidence that happens to appear twenty times, and folding each
  // occurrence separately makes repetition the cheapest way to raise a score —
  // which is backwards, because the thing that actually raises suspicion is a
  // *second kind* of evidence. A measured version of this: twenty copies of one
  // signature used to outscore a signature plus a beacon, which is the exact
  // pair a reader would rank the other way round.
  //
  // The occurrences are all still reported as findings; they just do not each
  // buy score.
  const byFamily = new Map<Family, Map<string, number>>();
  for (const finding of ordered(input.findings)) {
    let rules = byFamily.get(finding.family);
    if (rules === undefined) {
      rules = new Map();
      byFamily.set(finding.family, rules);
    }
    const current = rules.get(finding.ruleId);
    rules.set(
      finding.ruleId,
      current === undefined ? finding.weight : Math.max(current, finding.weight),
    );
  }

  const families = new Map<Family, number>();
  for (const [family, rules] of byFamily) {
    families.set(family, Math.min(FAMILY_CAP[family], noisyOr([...rules.values()])));
  }

  const decisive = input.findings.some(
    (finding) => finding.severity === 'critical' && input.standalone.has(finding.ruleId),
  );
  const corroborated = families.size >= 2 || decisive;

  const base = noisyOr([...families.values()]);
  const factor = corroborated ? WEIGHT_SCALE : 700;
  const scaled = Math.floor((base * factor) / WEIGHT_SCALE);

  return {
    // One rounding, at the very end, from the 0–1000 working scale to the 0–100
    // scale every threshold and report speaks in.
    score: Math.round(scaled / 10),
    families,
    corroborated,
  };
}

/** The cap applied to one family, exposed so the benchmark can ablate it. */
export function familyCap(family: Family): number {
  return FAMILY_CAP[family];
}
