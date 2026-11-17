/**
 * Where the judge meets a guarded call (ADR-012, items 5 to 8).
 *
 * Tier 1 has already scanned and decided by the time this runs, and its result,
 * the very object that would be forwarded, is not an argument: nothing here can
 * touch the bytes. What this decides is the *action*. For each scanned text that
 * lies in the judge's band, the judge is asked in parallel (each ask bounded by
 * the timeout, none queued), `applyJudge` turns each answer into a decision that
 * is never lower than tier 1's, and the call takes the worst of them.
 */
import {
  applyJudge,
  inJudgeBand,
  type Judge,
  type JudgeItemRecord,
  type JudgeRecord,
  type JudgeResult,
} from '@tunedness/mcpguard-core';
import type { ScanOptions, ScanVerdict } from '@tunedness/mcpguard-detect';

type Action = 'allow' | 'flag' | 'strip' | 'block';

const RANK: Record<Action, number> = { allow: 0, flag: 1, strip: 2, block: 3 };

/** What {@link applyTier2} needs. */
export interface Tier2Input {
  readonly judge: Judge;
  readonly timeoutMs: number;
  /** `judge.band_from`; absent, the tool's own `flag_at`. */
  readonly bandFrom: number | undefined;
  readonly enforce: boolean;
  readonly kind: 'tool_result' | 'resource';
  readonly channel: string;
  /** The thresholds and configured action this tool's scan ran under. */
  readonly scan: Pick<ScanOptions, 'action' | 'flagAt' | 'blockAt'>;
  readonly verdicts: readonly ScanVerdict[];
  /** What tier 1 decided for the whole call, observe-mode downgrade included. */
  readonly tier1: Action;
}

/** The call's final action, and the judge's part in it when it had one. */
export interface Tier2Outcome {
  readonly action: Action;
  /**
   * Present when the judge was asked, or could not be (busy, breaker open,
   * degraded item). Absent when every item was outside the band, so a judge that
   * had nothing to say leaves the record exactly as tier 1 wrote it.
   */
  readonly record?: JudgeRecord | undefined;
  /** Tier 1's decision, for the record. */
  readonly tier1: Action;
  /** True when the judge's answers made the call's action worse than tier 1's. */
  readonly escalated: boolean;
}

function itemOf(
  entry: { verdict: ScanVerdict; result: JudgeResult },
  effect: JudgeRecord['effect'],
): JudgeItemRecord {
  const { outcome } = entry.result;
  return {
    score: entry.verdict.score,
    tier1Action: entry.verdict.action,
    outcome: outcome.kind === 'verdict' ? outcome.label : outcome.kind,
    ...(outcome.kind === 'error' || outcome.kind === 'skipped' ? { reason: outcome.reason } : {}),
    ...(outcome.kind === 'verdict' ? { confidence: outcome.confidence } : {}),
    effect,
  };
}

function recordOf(
  judge: Judge,
  entry: { verdict: ScanVerdict; result: JudgeResult },
  effect: JudgeRecord['effect'],
  items: readonly JudgeItemRecord[] | undefined,
): JudgeRecord {
  const { result } = entry;
  return {
    adapter: judge.adapter,
    model: result.model,
    ...(result.modelRevision !== undefined ? { modelRevision: result.modelRevision } : {}),
    ...itemOf(entry, effect),
    latencyMs: result.latencyMs,
    truncated: result.truncated,
    cached: result.cached,
    ...(items !== undefined ? { items } : {}),
  };
}

/**
 * Asks the judge about what tier 1 could not settle, and raises the decision
 * where the answer warrants it.
 */
export async function applyTier2(input: Tier2Input): Promise<Tier2Outcome> {
  const { judge, scan } = input;

  const asked = await Promise.all(
    input.verdicts.map(async (verdict) => {
      if (verdict.degraded || verdict.maskedText === undefined) {
        const skipped: JudgeResult = {
          outcome: { kind: 'skipped', reason: 'degraded' },
          model: judge.model,
          ...(judge.modelRevision !== undefined ? { modelRevision: judge.modelRevision } : {}),
          latencyMs: 0,
          truncated: false,
          cached: false,
        };
        return { verdict, result: skipped };
      }
      const inBand = inJudgeBand({
        score: verdict.score,
        corroborated: verdict.corroborated,
        degraded: verdict.degraded,
        flagAt: scan.flagAt,
        blockAt: scan.blockAt,
        bandFrom: input.bandFrom,
      });
      if (!inBand) return undefined;
      let result: JudgeResult;
      try {
        result = await judge.judge(
          {
            text: verdict.maskedText,
            kind: input.kind,
            channel: input.channel,
            tier1Score: verdict.score,
          },
          input.timeoutMs,
        );
      } catch {
        // A judge that throws is a defect in the judge. It must not become the agent's error.
        result = {
          outcome: { kind: 'error', reason: 'internal' },
          model: judge.model,
          latencyMs: 0,
          truncated: false,
          cached: false,
        };
      }
      return { verdict, result };
    }),
  );

  const judgedEntries = asked.filter(
    (entry): entry is NonNullable<typeof entry> => entry !== undefined,
  );
  const applied = judgedEntries.map((entry) => {
    const result = applyJudge({
      tier1: entry.verdict.action,
      score: entry.verdict.score,
      flagAt: scan.flagAt,
      configured: scan.action,
      outcome: entry.result.outcome,
    });
    // Observe mode withholds nothing: a block is a flag, and the record keeps
    // `raised_to_block` so an operator can see what enforcement would have done.
    const effective: Action = input.enforce
      ? result.action
      : result.action === 'block'
        ? 'flag'
        : result.action;
    return { entry, effect: result.effect, effective };
  });

  let action = input.tier1;
  for (const item of applied) if (RANK[item.effective] > RANK[action]) action = item.effective;
  const escalated = RANK[action] > RANK[input.tier1];

  // The record speaks for one item, and says which by carrying that item's own
  // score and action: the one whose answer set the call's action if the judge did;
  // failing that one the judge moved, then one it answered.
  let best: (typeof applied)[number] | undefined;
  let bestKey = -1;
  for (const item of applied) {
    const key =
      (escalated && item.effect !== 'none' && item.effective === action ? 1000 : 0) +
      (item.effect === 'none' ? 0 : 100) +
      RANK[item.effective] * 10 +
      (item.entry.result.outcome.kind === 'verdict' ? 1 : 0);
    if (key > bestKey) {
      best = item;
      bestKey = key;
    }
  }
  // Every judged item is listed when there is more than one, so none is lost.
  const items =
    applied.length > 1 ? applied.map((item) => itemOf(item.entry, item.effect)) : undefined;

  return {
    action,
    tier1: input.tier1,
    escalated,
    ...(best !== undefined ? { record: recordOf(judge, best.entry, best.effect, items) } : {}),
  };
}
