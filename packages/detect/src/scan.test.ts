import { describe, expect, it } from 'vitest';
import { byteLength, EMPTY_RULESET, scanContent } from './scan.js';
import type { ContentItem, ScanOptions } from './types.js';

/**
 * The scanner's contract, fixed before the detectors that will fill it in.
 *
 * Phase 3 measures 0% recall on purpose: the corpus and the harness come before
 * the engine, so the number is real from the first run and the design is
 * calibrated against it rather than frozen ahead of it.
 */

const options: ScanOptions = {
  action: 'flag',
  flagAt: 40,
  blockAt: 70,
  maxBytes: 32,
  onDegraded: 'flag',
};

function item(text: string): ContentItem {
  return { id: 'part-0', text, kind: 'tool_result' };
}

describe('scanContent', () => {
  it('forwards the text unchanged when nothing is found', () => {
    const verdict = scanContent(item('nothing to see'), EMPTY_RULESET, options);

    expect(verdict.text).toBe('nothing to see');
    expect(verdict.action).toBe('allow');
    expect(verdict.score).toBe(0);
    expect(verdict.edits).toEqual([]);
  });

  it('records what decided the verdict, so it can be reproduced later', () => {
    // An audit record that says `flag` without saying which ruleset said so is
    // a record nobody can check.
    const verdict = scanContent(item('x'), EMPTY_RULESET, options);

    expect(verdict.engineVersion).toMatch(/^\d+\.\d+\.\d+$/);
    expect(verdict.rulesetVersion).toBe(EMPTY_RULESET.rulesetVersion);
    expect(verdict.rulesetDigest).toBe(EMPTY_RULESET.digest);
  });

  it('marks an oversized item degraded rather than passing it as clean', () => {
    const verdict = scanContent(item('x'.repeat(200)), EMPTY_RULESET, options);

    expect(verdict.degraded).toBe(true);
    expect(verdict.action).toBe('flag');
    // The sampler takes the head and tail, so the scanned size is at most the
    // cap — never the whole thing, and never silently zero.
    expect(verdict.scannedBytes).toBeLessThanOrEqual(32);
    expect(verdict.scannedBytes).toBeGreaterThan(0);
    expect(verdict.totalBytes).toBe(200);
  });

  it('measures the cap in bytes, not in code units', () => {
    // `String.length` counts UTF-16 code units, so a Turkish result would be
    // reported smaller than it is on the wire and the byte budget written in
    // the policy would not be the budget that applied.
    const turkish = 'ğüşöçİ';

    expect(turkish.length).toBe(6);
    expect(byteLength(turkish)).toBe(12);
    expect(scanContent(item(turkish), EMPTY_RULESET, options).totalBytes).toBe(12);
  });

  it('is deterministic: the same input scans to the same verdict', () => {
    const first = scanContent(item('repeatable'), EMPTY_RULESET, options);
    const second = scanContent(item('repeatable'), EMPTY_RULESET, options);

    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});
