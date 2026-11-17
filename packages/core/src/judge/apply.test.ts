import { describe, expect, it } from 'vitest';
import { type JudgeOutcome, NULL_JUDGE } from '../ports/index.js';
import { type ApplyJudgeInput, applyJudge, type JudgedAction } from './apply.js';
import { inJudgeBand } from './band.js';

const injection: JudgeOutcome = { kind: 'verdict', label: 'injection', confidence: 90 };
const benign: JudgeOutcome = { kind: 'verdict', label: 'benign', confidence: 90 };
const others: JudgeOutcome[] = [
  benign,
  { kind: 'timeout' },
  { kind: 'error', reason: 'network' },
  { kind: 'skipped', reason: 'busy' },
  { kind: 'skipped', reason: 'circuit_open' },
  { kind: 'skipped', reason: 'degraded' },
  { kind: 'skipped', reason: 'out_of_band' },
];

function input(over: Partial<ApplyJudgeInput>): ApplyJudgeInput {
  return { tier1: 'flag', score: 64, flagAt: 40, configured: 'block', outcome: injection, ...over };
}

describe('applyJudge, the E-A rule table', () => {
  it('leaves tier 1 alone for anything that is not an injection verdict', () => {
    for (const outcome of others) {
      for (const tier1 of ['allow', 'flag', 'strip', 'block'] as JudgedAction[]) {
        for (const configured of ['flag', 'strip', 'block'] as const) {
          for (const score of [0, 39, 40, 69, 70, 100]) {
            expect(applyJudge(input({ tier1, configured, score, outcome }))).toEqual({
              action: tier1,
              effect: 'none',
            });
          }
        }
      }
    }
  });

  it('leaves a block a block', () => {
    expect(applyJudge(input({ tier1: 'block', score: 90 }))).toEqual({
      action: 'block',
      effect: 'none',
    });
  });

  it('flags, and only flags, below flag_at', () => {
    for (const configured of ['flag', 'strip', 'block'] as const) {
      expect(applyJudge(input({ tier1: 'allow', score: 20, configured }))).toEqual({
        action: 'flag',
        effect: 'raised_to_flag',
      });
    }
  });

  it('does not lower a decision that is already above a flag, below flag_at', () => {
    expect(applyJudge(input({ tier1: 'strip', score: 20 }))).toEqual({
      action: 'strip',
      effect: 'none',
    });
  });

  it('makes the judge the second family on a block tool at or above flag_at', () => {
    for (const score of [40, 64, 69, 70, 83, 100]) {
      expect(applyJudge(input({ tier1: 'flag', score, configured: 'block' }))).toEqual({
        action: 'block',
        effect: 'raised_to_block',
      });
    }
  });

  it('cannot strip, and cannot block a tool that was not asked to', () => {
    for (const configured of ['flag', 'strip'] as const) {
      expect(applyJudge(input({ tier1: configured, score: 64, configured }))).toEqual({
        action: configured,
        effect: 'none',
      });
    }
  });

  it('never lowers an action, over every input', () => {
    const rank: Record<JudgedAction, number> = { allow: 0, flag: 1, strip: 2, block: 3 };
    for (const outcome of [injection, ...others]) {
      for (const tier1 of ['allow', 'flag', 'strip', 'block'] as JudgedAction[]) {
        for (const configured of ['flag', 'strip', 'block'] as const) {
          for (const score of [0, 10, 39, 40, 41, 69, 70, 71, 100]) {
            const result = applyJudge(input({ tier1, configured, score, outcome }));
            expect(rank[result.action]).toBeGreaterThanOrEqual(rank[tier1]);
          }
        }
      }
    }
  });
});

describe('inJudgeBand', () => {
  const base = { corroborated: true, degraded: false, flagAt: 40, blockAt: 70 };

  it('takes [flag_at, block_at) by default', () => {
    expect(inJudgeBand({ ...base, score: 39 })).toBe(false);
    expect(inJudgeBand({ ...base, score: 40 })).toBe(true);
    expect(inJudgeBand({ ...base, score: 69 })).toBe(true);
    expect(inJudgeBand({ ...base, score: 70 })).toBe(false);
  });

  it('takes a score at or above block_at only when tier 1 could not confirm it', () => {
    expect(inJudgeBand({ ...base, score: 70, corroborated: false })).toBe(true);
    expect(inJudgeBand({ ...base, score: 100, corroborated: false })).toBe(true);
    expect(inJudgeBand({ ...base, score: 100, corroborated: true })).toBe(false);
  });

  it('starts at band_from when it is given', () => {
    expect(inJudgeBand({ ...base, score: 10, bandFrom: 10 })).toBe(true);
    expect(inJudgeBand({ ...base, score: 9, bandFrom: 10 })).toBe(false);
    expect(inJudgeBand({ ...base, score: 0, bandFrom: 0 })).toBe(true);
    expect(inJudgeBand({ ...base, score: 50, bandFrom: 60 })).toBe(false);
  });

  it('never takes a degraded item', () => {
    expect(inJudgeBand({ ...base, score: 50, degraded: true })).toBe(false);
    expect(inJudgeBand({ ...base, score: 90, corroborated: false, degraded: true })).toBe(false);
  });
});

describe('NULL_JUDGE', () => {
  it('is always out of band and asks nothing of anyone', async () => {
    const result = await NULL_JUDGE.judge(
      { text: 'x', kind: 'tool_result', channel: 'a__b', tier1Score: 50 },
      1_000,
    );
    expect(NULL_JUDGE.adapter).toBe('null');
    expect(result.outcome).toEqual({ kind: 'skipped', reason: 'out_of_band' });
    expect(result.cached).toBe(false);
  });
});
