import { describe, expect, it } from 'vitest';
import { digestsEqual, hmacSha256, sha256 } from './hash.js';

describe('sha256', () => {
  it('matches the published digest of the empty string', () => {
    expect(sha256('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('is stable for the same input', () => {
    expect(sha256('mcpguard')).toBe(sha256('mcpguard'));
  });
});

describe('hmacSha256', () => {
  it('differs from the plain digest of the same input', () => {
    // This is the whole point of ADR-004's amendment: a plain digest of a
    // low-entropy value is a lookup table away from being the value.
    expect(hmacSha256('k', '12345678901')).not.toBe(sha256('12345678901'));
  });

  it('differs under a different key, so one deployment cannot read another', () => {
    expect(hmacSha256('k1', 'x')).not.toBe(hmacSha256('k2', 'x'));
  });

  it('is stable, so two records holding the same value still match', () => {
    expect(hmacSha256('k', 'x')).toBe(hmacSha256('k', 'x'));
  });
});

describe('digestsEqual', () => {
  it('is true for identical digests', () => {
    expect(digestsEqual(sha256('a'), sha256('a'))).toBe(true);
  });

  it('is false for different digests of the same length', () => {
    expect(digestsEqual(sha256('a'), sha256('b'))).toBe(false);
  });

  it('is false for different lengths without reaching the comparison', () => {
    // `timingSafeEqual` throws on a length mismatch, so the guard is load-bearing.
    expect(digestsEqual('abc', sha256('a'))).toBe(false);
  });
});
