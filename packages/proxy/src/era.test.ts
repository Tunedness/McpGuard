import { describe, expect, it } from 'vitest';
import { assertSameEra, EraMismatchError, eraOf, FIRST_MODERN_PROTOCOL_VERSION } from './era.js';

describe('eraOf', () => {
  it('classifies a legacy revision', () => {
    expect(eraOf('2025-11-25')).toBe('legacy');
    expect(eraOf('2024-10-07')).toBe('legacy');
  });

  it('classifies the first modern revision and later', () => {
    expect(eraOf(FIRST_MODERN_PROTOCOL_VERSION)).toBe('modern');
    expect(eraOf('2027-01-01')).toBe('modern');
  });

  it('sorts an unknown future revision into modern rather than rejecting it', () => {
    expect(eraOf('2099-12-31')).toBe('modern');
  });
});

describe('assertSameEra', () => {
  it('passes when both ends agree', () => {
    expect(() => assertSameEra('modern', 'modern')).not.toThrow();
  });

  it('throws rather than translate when they disagree', () => {
    // A proxy that translated would have to invent the facts the other era
    // deleted; refusing is the honest answer.
    expect(() => assertSameEra('modern', 'legacy')).toThrow(EraMismatchError);
  });
});
