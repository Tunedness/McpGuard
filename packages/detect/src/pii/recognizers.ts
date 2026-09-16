/**
 * The PII recognisers: bounded candidate, deterministic validator, context.
 *
 * Each recogniser is three stages. A cheap pattern finds a candidate, a
 * validator (a checksum where one exists) confirms it, and — for the recognisers
 * with no checksum — a keyword within a short window decides a borderline case.
 * The checksum is the gate that keeps an order number from being masked as a
 * national id; turning it off is a regulated-tenant setting that still masks a
 * checksum failure when a context keyword sits beside it.
 */
import {
  cardScheme,
  IBAN_LENGTHS,
  isValidIbanChecksum,
  isValidLuhn,
  isValidTckn,
  isValidVkn,
} from './checksums.js';

/** A recognised piece of PII in the raw text. */
export interface PiiMatch {
  readonly kind: PiiKind;
  readonly start: number;
  readonly end: number;
  /** The matched text, so the masker can compute a keyed tag from it. */
  readonly value: string;
  /** Digits to keep visible, if the recogniser exposes a reconciliation tail. */
  readonly keepTail: number;
}

export type PiiKind = 'tckn' | 'vkn' | 'iban' | 'card' | 'phone' | 'email';

/** How a recogniser is configured for one scan. */
export interface PiiConfig {
  /** Recognisers to run. Empty means all of them. */
  readonly recognizers: ReadonlySet<PiiKind>;
  /** Whether a checksum must pass, or only strengthens a keyworded match. */
  readonly strictChecksum: boolean;
}

const CONTEXT = {
  tckn: /\b(tc|t\.?c\.?|tckn|kimlik)\b/i,
  vkn: /\b(vkn|vergi)\b/i,
  iban: /\biban\b/i,
  card: /\b(kart|card|kredi)\b/i,
  phone: /\b(tel|telefon|gsm|cep|ara|phone|mobile)\b/i,
};

/** Finds every PII match in `raw`, honouring the config. */
export function recognize(raw: string, config: PiiConfig): PiiMatch[] {
  const wants = (kind: PiiKind): boolean =>
    config.recognizers.size === 0 || config.recognizers.has(kind);
  const matches: PiiMatch[] = [];

  if (wants('tckn')) findTckn(raw, config, matches);
  if (wants('iban')) findIban(raw, matches);
  if (wants('card')) findCard(raw, config, matches);
  if (wants('vkn')) findVkn(raw, config, matches);
  if (wants('phone')) findPhone(raw, config, matches);
  if (wants('email')) findEmail(raw, matches);

  return matches.sort((a, b) => a.start - b.start);
}

function near(raw: string, at: number, re: RegExp): boolean {
  const window = raw.slice(Math.max(0, at - 40), at + 40);
  return re.test(window);
}

function findTckn(raw: string, config: PiiConfig, out: PiiMatch[]): void {
  for (const m of raw.matchAll(/(?<!\d)[1-9]\d{10}(?!\d)/g)) {
    const value = m[0];
    const at = m.index ?? 0;
    const valid = isValidTckn(value);
    // Checksum passes → always a match. Checksum fails → only when the tenant
    // asked for the loose mode and a context keyword is beside it.
    if (valid || (!config.strictChecksum && near(raw, at, CONTEXT.tckn))) {
      out.push({ kind: 'tckn', start: at, end: at + value.length, value, keepTail: 0 });
    }
  }
}

function findVkn(raw: string, config: PiiConfig, out: PiiMatch[]): void {
  for (const m of raw.matchAll(/(?<!\d)\d{10}(?!\d)/g)) {
    const value = m[0];
    const at = m.index ?? 0;
    // A 10-digit run is a VKN only with the checksum or a keyword; without one it
    // is far too common to mask.
    if (isValidVkn(value) || (!config.strictChecksum && near(raw, at, CONTEXT.vkn))) {
      out.push({ kind: 'vkn', start: at, end: at + value.length, value, keepTail: 0 });
    }
  }
}

function findIban(raw: string, out: PiiMatch[]): void {
  for (const m of raw.matchAll(/\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{1,4}){2,8}\b/g)) {
    const value = m[0];
    const compact = value.replace(/\s+/g, '');
    const country = compact.slice(0, 2);
    const expected = IBAN_LENGTHS[country];
    if (expected !== undefined && compact.length !== expected) continue;
    if (!isValidIbanChecksum(compact)) continue;
    const at = m.index ?? 0;
    out.push({ kind: 'iban', start: at, end: at + value.length, value, keepTail: 4 });
  }
}

function findCard(raw: string, config: PiiConfig, out: PiiMatch[]): void {
  for (const m of raw.matchAll(/(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])/g)) {
    const value = m[0];
    const digits = value.replace(/[ -]/g, '');
    const at = m.index ?? 0;
    // A run of the wrong length for its own scheme, or a 13-digit EAN, is not a
    // card. Luhn plus a valid scheme prefix is the gate.
    if (/^(978|979)/.test(digits)) continue;
    const scheme = cardScheme(digits);
    if (scheme === undefined || !isValidLuhn(digits)) {
      if (config.strictChecksum || !near(raw, at, CONTEXT.card)) continue;
    }
    out.push({ kind: 'card', start: at, end: at + value.length, value, keepTail: 4 });
  }
}

function findPhone(raw: string, config: PiiConfig, out: PiiMatch[]): void {
  for (const m of raw.matchAll(
    /(?<!\d)(?:\+90|0090|0)?[ ]?\(?5\d{2}\)?[ ]?\d{3}[ ]?\d{2}[ ]?\d{2}(?!\d)/g,
  )) {
    const value = m[0].trim();
    const at = m.index ?? 0;
    const e164 = /^(\+90|0090)/.test(value);
    // A bare national-format mobile has no checksum, so it fires only with a
    // keyword nearby; an explicitly-prefixed number is unambiguous.
    if (e164 || near(raw, at, CONTEXT.phone) || !config.strictChecksum) {
      out.push({ kind: 'phone', start: at, end: at + value.length, value, keepTail: 0 });
    }
  }
}

const EMAIL = /\b[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,255}\.[a-z]{2,24}\b/gi;
const EMAIL_EXCLUDE = /@(example\.(com|org|net)|.*\.(invalid|test|localhost))$/i;

function findEmail(raw: string, out: PiiMatch[]): void {
  for (const m of raw.matchAll(EMAIL)) {
    const value = m[0];
    if (EMAIL_EXCLUDE.test(value)) continue;
    const at = m.index ?? 0;
    out.push({ kind: 'email', start: at, end: at + value.length, value, keepTail: 0 });
  }
}
