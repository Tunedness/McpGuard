import { describe, expect, it } from 'vitest';
import { sha256 } from './hash.js';

describe('sha256', () => {
  it('matches the published digest of the empty string', () => {
    // The digest is what pins a decision to the exact ruleset that made it, so
    // it has to be the real SHA-256, not a lookalike.
    expect(sha256('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('is stable for the same input', () => {
    expect(sha256('mcpguard')).toBe(sha256('mcpguard'));
  });

  it('differs for different inputs', () => {
    expect(sha256('a')).not.toBe(sha256('b'));
  });
});
