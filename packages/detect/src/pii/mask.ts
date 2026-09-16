/**
 * Masking a recognised value, and the keyed tag that lets it be correlated
 * without being recovered.
 *
 * The format is `[KIND:hint]`, ASCII only, so it survives a JSON round trip and
 * a terminal. The hint is asterisks, optionally a reconciliation tail the
 * recogniser allowed, and optionally a short correlation tag — a truncated HMAC
 * of the value under a deployment secret, so an operator can see the same
 * identity twice without a lookup key. The tag is deliberately short enough to
 * collide, which is what stops it being one.
 */

import type { Edit } from '../types.js';
import { hmacSha256 } from '../util/hash.js';
import type { PiiKind, PiiMatch } from './recognizers.js';

/** How masking is configured for one scan. */
export interface MaskConfig {
  /** Digits to reveal for reconciliation, capped by the recogniser's own tail. */
  readonly keepLast: number;
  /** Whether to attach a correlation tag. */
  readonly correlationTags: boolean;
  /** The HMAC key for the tag and the raw-content fingerprint. Absent → no tag. */
  readonly correlationKey?: string | undefined;
}

const LABEL: Record<PiiKind, string> = {
  tckn: 'TCKN',
  vkn: 'VKN',
  iban: 'IBAN',
  card: 'CARD',
  phone: 'PHONE',
  email: 'EMAIL',
};

/** The replacement string for one match. */
export function maskFor(match: PiiMatch, config: MaskConfig): string {
  const label = LABEL[match.kind];
  const keep = Math.min(config.keepLast, match.keepTail);
  const digits = match.value.replace(/\D/g, '');
  const tail = keep > 0 && digits.length >= keep ? digits.slice(-keep) : '';
  const tag =
    config.correlationTags && config.correlationKey !== undefined
      ? `#${hmacSha256(config.correlationKey, normalizeValue(match)).slice(0, 4)}`
      : '';
  const body = tail === '' ? '***' : `***${tail}`;
  return `[${label}:${body}${tag}]`;
}

/** One edit per match, left to right, for the audit trail and the stripper. */
export function maskEdits(matches: readonly PiiMatch[], config: MaskConfig): Edit[] {
  return matches.map((match) => ({
    span: { start: match.start, end: match.end },
    replacement: maskFor(match, config),
    reason: `pii:${match.kind}`,
  }));
}

/**
 * The value a correlation tag is computed over.
 *
 * Normalised so the same identity tags the same way however it was written —
 * spaces and separators dropped, letters upper-cased — but never so that the
 * normalisation itself narrows the space a tag is computed over.
 */
function normalizeValue(match: PiiMatch): string {
  return match.value.replace(/[\s-]/g, '').toUpperCase();
}
