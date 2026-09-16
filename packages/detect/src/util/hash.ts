import { createHash } from 'node:crypto';

/**
 * Hex-encoded SHA-256.
 *
 * `node:crypto` is the one Node builtin this package imports, and it earns its
 * place: a ruleset's digest is what lets a decision be reproduced against the
 * exact rules that made it. It performs no I/O and reads no ambient state, so
 * it does not compromise the purity invariant.
 */
export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}
