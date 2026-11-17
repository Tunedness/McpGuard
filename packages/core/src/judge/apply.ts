/**
 * What the tier-2 judge's answer does to a decision (ADR-012, item 6).
 *
 * One rule governs everything here: **the judge can only raise.** A tier-1
 * decision is never lowered, never rewritten and never replaced, so the best an
 * attacker gains by talking the judge round is nothing, and the worst the judge
 * can be talked into is flagging the attacker's own content. A function that can
 * only raise is also one that a record can reproduce: given the tier-1 verdict
 * and the recorded outcome, the final decision falls out, byte for byte, with no
 * model in the loop.
 *
 * Pure. No float enters: the confidence is an integer and is not read here at
 * all, because the decision turns on the label.
 */
import type { JudgeEffect } from '../domain/events.js';
import type { JudgeOutcome } from '../ports/index.js';

/** The four things a guarded item can end up as. */
export type JudgedAction = 'allow' | 'flag' | 'strip' | 'block';

/** What {@link applyJudge} reads. */
export interface ApplyJudgeInput {
  /** What tier 1 decided for this item, before observe-mode downgrades. */
  readonly tier1: JudgedAction;
  /** The tier-1 score, 0–100. */
  readonly score: number;
  readonly flagAt: number;
  /** The action the policy configured for this tool. */
  readonly configured: 'flag' | 'strip' | 'block';
  readonly outcome: JudgeOutcome;
}

/** The final action and what the judge did to it. */
export interface AppliedJudge {
  readonly action: JudgedAction;
  readonly effect: JudgeEffect;
}

const RANK: Record<JudgedAction, number> = { allow: 0, flag: 1, strip: 2, block: 3 };

/**
 * Raises a tier-1 decision by a judge's answer, or leaves it alone.
 *
 * - Anything but a verdict of `injection` (benign, timeout, error, skipped):
 *   tier 1 stands.
 * - Tier 1 already blocked: it stands.
 * - Below `flagAt`: `flag`. The judge is a single signal, and a single signal is
 *   not enough to block on (the corroboration rule of `decide`), so it never
 *   blocks by itself.
 * - At or above `flagAt` on a tool configured to `block`: `block`. Tier 1 held
 *   back for want of a second family, and the judge is that second opinion.
 * - Otherwise (a tool configured to `flag` or `strip`): tier 1 stands. The judge
 *   brings no span to strip and the tool was not asked to block.
 */
export function applyJudge(input: ApplyJudgeInput): AppliedJudge {
  const { tier1, outcome } = input;
  const unchanged: AppliedJudge = { action: tier1, effect: 'none' };
  if (outcome.kind !== 'verdict' || outcome.label !== 'injection') return unchanged;
  if (tier1 === 'block') return unchanged;
  if (input.score < input.flagAt) {
    // A decision already at or above `flag` (a degraded item can be) is not lowered.
    return RANK[tier1] >= RANK.flag ? unchanged : { action: 'flag', effect: 'raised_to_flag' };
  }
  if (input.configured === 'block') return { action: 'block', effect: 'raised_to_block' };
  return unchanged;
}
