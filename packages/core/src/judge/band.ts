/**
 * Which items are worth asking the judge about (ADR-012, item 5).
 *
 * A model call costs a round trip, so the judge sees only what tier 1 could not
 * settle: scores in `[bandFrom, blockAt)`, and a score at or above `blockAt` that
 * tier 1 could not confirm with a second signal. A degraded item never goes: its
 * text was sampled, so what the judge would read is not the item.
 */

/** What decides whether one item is judged. */
export interface BandInput {
  readonly score: number;
  /** Whether tier 1 saw two independent families or a critical standalone finding. */
  readonly corroborated: boolean;
  readonly degraded: boolean;
  readonly flagAt: number;
  readonly blockAt: number;
  /** The policy's `judge.band_from`. Absent, the tool's own `flagAt`. */
  readonly bandFrom?: number | undefined;
}

/** True when the judge should be asked about this item. */
export function inJudgeBand(input: BandInput): boolean {
  if (input.degraded) return false;
  const from = input.bandFrom ?? input.flagAt;
  if (input.score >= input.blockAt) return !input.corroborated;
  return input.score >= from;
}
