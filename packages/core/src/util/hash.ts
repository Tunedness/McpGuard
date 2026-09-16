import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Hex-encoded SHA-256.
 *
 * `node:crypto` is the one Node builtin this package imports. It performs no
 * I/O and reads no ambient state, so it does not compromise the purity
 * invariant the rest of the package is built on.
 */
export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Hex-encoded HMAC-SHA-256.
 *
 * This is how an audit record fingerprints the **raw** content it is not
 * allowed to store. A plain SHA-256 would not do: ADR-004's 2026-09-16
 * amendment records why. A tool result that is one Turkish national ID number
 * has about a billion candidates, so a plain digest of it is a lookup table
 * away from being the number itself, and the masking it sits next to would be
 * theatre. Keyed, it is still a fingerprint — two records with the same value
 * still match, and a tampered record still fails — but it is not a recovery
 * path for whoever ends up holding the log file.
 *
 * The key is a deployment secret supplied by the caller; this package generates
 * no randomness of its own.
 */
export function hmacSha256(key: string, input: string): string {
  return createHmac('sha256', key).update(input, 'utf8').digest('hex');
}

/**
 * Constant-time comparison of two hex digests.
 *
 * Audit verification compares a recomputed chain link against a stored one. The
 * comparison is not obviously attacker-timed, but a verifier that leaks where
 * two digests first differ is a verifier somebody will eventually feed one byte
 * at a time, and the constant-time version costs nothing.
 */
export function digestsEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  // `TextEncoder` rather than `Buffer`: both are globals, but one of them is a
  // web standard and the other is a Node namespace this package would rather
  // not reach into at all.
  const encoder = new TextEncoder();
  return timingSafeEqual(encoder.encode(a), encoder.encode(b));
}
