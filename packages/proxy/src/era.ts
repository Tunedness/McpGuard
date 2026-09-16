/**
 * Protocol eras, and the rule that the proxy never translates between them.
 *
 * The wire protocol splits in two. `legacy` negotiates with `initialize` and
 * has sessions; `modern` (2026-07-28 and later) dropped both and gives every
 * request its own `_meta` envelope. McpGuard supports both and translates
 * neither: a proxy that rewrote one era into the other would have to invent the
 * facts the other era deleted — a session id where there is none — and every
 * such invention is a lie the operator only finds during an incident.
 *
 * This module imports neither engine package. See `boundary.test.ts`.
 */

/** The first modern revision. Anything at or after it is `modern`. */
export const FIRST_MODERN_PROTOCOL_VERSION = '2026-07-28';

export type Era = 'legacy' | 'modern';

/**
 * The era of a protocol revision.
 *
 * Revisions are ISO dates, so a string comparison is chronological: an unknown
 * future revision sorts into `modern` rather than being rejected.
 */
export function eraOf(version: string): Era {
  return version >= FIRST_MODERN_PROTOCOL_VERSION ? 'modern' : 'legacy';
}

/** A downstream/upstream era disagreement the proxy must not paper over. */
export class EraMismatchError extends Error {
  constructor(downstream: Era, upstream: Era) {
    super(
      `the downstream connection is ${downstream} but the upstream negotiated ${upstream}; ` +
        'McpGuard is era-transparent and does not translate between them',
    );
    this.name = 'EraMismatchError';
  }
}

/** Throws when the two ends disagree, rather than guessing which is right. */
export function assertSameEra(downstream: Era, upstream: Era): void {
  if (downstream !== upstream) throw new EraMismatchError(downstream, upstream);
}
