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
import { type CompiledPiiData, PiiDataMissingError, PiiText } from './context.js';
import { findGs1Serial } from './gs1.js';
import {
  findAtc,
  findHealthDate,
  findHealthRef,
  findIcd10,
  findMbiUs,
  findSsnUs,
} from './health.js';
import { BASE_KINDS, isBaseKind, type PiiKind, type PiiProfile } from './kinds.js';

export type { PiiKind, PiiProfile } from './kinds.js';

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

/** How a recogniser is configured for one scan. */
export interface PiiConfig {
  /**
   * Recognisers to run. Empty means the base set plus what the profile switches
   * on; a non-empty set is the complete list, and the profile adds no kind to it.
   * The profile's extra keywords for the national-id and phone recognisers still
   * apply when those two are in the list.
   */
  readonly recognizers: ReadonlySet<PiiKind>;
  /** Whether a checksum must pass, or only strengthens a keyworded match. */
  readonly strictChecksum: boolean;
  /** `health` switches on the health recognisers. Absent is `default`. */
  readonly profile?: PiiProfile | undefined;
  /** The ruleset's PII keyword data. Required by every recogniser that reads keywords. */
  readonly data?: CompiledPiiData | undefined;
}

const CONTEXT = {
  tckn: /\b(tc|t\.?c\.?|tckn|kimlik)\b/i,
  vkn: /\b(vkn|vergi)\b/i,
  iban: /\biban\b/i,
  card: /\b(kart|card|kredi)\b/i,
  phone: /\b(tel|telefon|gsm|cep|ara|phone|mobile)\b/i,
};

/**
 * The kinds one scan runs.
 *
 * @throws {PiiDataMissingError} when the profile needs keyword data that is absent.
 */
export function activeKinds(config: PiiConfig): ReadonlySet<PiiKind> {
  // The profile needs the data whatever the list says — its keywords reach the
  // base recognisers — so the check does not wait for a candidate to turn up.
  if (config.profile === 'health' && config.data === undefined) {
    throw new PiiDataMissingError('pii.profile: health');
  }
  if (config.recognizers.size > 0) return config.recognizers;
  const kinds = new Set<PiiKind>(BASE_KINDS);
  if (config.profile === 'health' && config.data !== undefined) {
    for (const kind of config.data.profiles.health) kinds.add(kind);
  }
  return kinds;
}

/** Finds every PII match in `raw`, honouring the config. */
export function recognize(raw: string, config: PiiConfig): PiiMatch[] {
  const active = activeKinds(config);
  const wants = (kind: PiiKind): boolean => active.has(kind);
  const matches: PiiMatch[] = [];

  if (wants('tckn')) findTckn(raw, config, matches);
  if (wants('iban')) findIban(raw, matches);
  if (wants('card')) findCard(raw, config, matches);
  if (wants('vkn')) findVkn(raw, config, matches);
  if (wants('phone')) findPhone(raw, config, matches);
  if (wants('email')) findEmail(raw, matches);

  // Everything above is the shipped base set and returns exactly what it always
  // did. The block below is the only code a health kind or the profile adds, and
  // it does not run unless one is on — so a default deployment's bytes cannot move.
  const extended = config.profile === 'health' || [...active].some((k) => !isBaseKind(k));
  if (!extended) return matches.sort((a, b) => a.start - b.start);

  const text = new PiiText(raw, config.data);
  if (wants('health_ref')) findHealthRef(text, matches);
  if (wants('health_date')) findHealthDate(text, matches);
  if (wants('gs1_serial')) findGs1Serial(text, config.strictChecksum, matches);
  if (wants('ssn_us')) findSsnUs(text, config.strictChecksum, matches);
  if (wants('mbi_us')) findMbiUs(raw, matches);
  if (wants('icd10')) findIcd10(text, matches);
  if (wants('atc')) findAtc(raw, matches);
  if (config.profile === 'health') findProfileContext(text, config, active, matches);

  return resolveOverlaps(matches);
}

/**
 * The order two matches over the same stretch are told apart in: base kinds
 * first, then the kinds a checksum or a strict grammar vouches for, then the
 * keyword-bound ones, and the anchor-bound reference last. A Medicare id after
 * `Medicare ID` is a reference number by its anchor and a `mbi_us` by its
 * grammar; the grammar is the stronger claim, so it names the mask.
 */
const TIE_ORDER: readonly PiiKind[] = [
  ...BASE_KINDS,
  'gs1_serial',
  'mbi_us',
  'ssn_us',
  'health_date',
  'icd10',
  'atc',
  'health_ref',
];
const KIND_RANK: ReadonlyMap<PiiKind, number> = new Map(TIE_ORDER.map((k, i) => [k, i]));

/**
 * One match per stretch of text: the longest wins, then the earlier kind in
 * the tie order below (base first, then grammar-bound, then keyword-bound), then the
 * earlier start.
 *
 * Without it a reference number that is also a national id would be masked
 * twice, and the second mask would land inside the first one's replacement.
 */
function resolveOverlaps(matches: PiiMatch[]): PiiMatch[] {
  const ranked = [...matches].sort(
    (a, b) =>
      b.end - b.start - (a.end - a.start) ||
      (KIND_RANK.get(a.kind) ?? 0) - (KIND_RANK.get(b.kind) ?? 0) ||
      a.start - b.start,
  );
  const kept: PiiMatch[] = [];
  for (const match of ranked) {
    // `kept` stays ordered by start; only its two neighbours can overlap.
    let lo = 0;
    let hi = kept.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if ((kept[mid]?.start ?? 0) < match.start) lo = mid + 1;
      else hi = mid;
    }
    const before = kept[lo - 1];
    const after = kept[lo];
    if (before !== undefined && before.end > match.start) continue;
    if (after !== undefined && after.start < match.end) continue;
    kept.splice(lo, 0, match);
  }
  return kept;
}

const TCKN_CANDIDATE = /(?<!\d)[1-9]\d{10}(?!\d)/g;
const PHONE_CANDIDATE = /(?<!\d)(?:\+90|0090|0)?[ ]?\(?5\d{2}\)?[ ]?\d{3}[ ]?\d{2}[ ]?\d{2}(?!\d)/g;

/**
 * The keywords a profile adds to a base recogniser's own context.
 *
 * The base recognisers keep their bodies; this pass finds the candidates the
 * profile's words rescue and adds them. A national id with a failed checksum is
 * rescued only in the loose mode, as for the base words; a bare mobile number
 * is rescued beside `faks` or `fax`.
 */
function findProfileContext(
  text: PiiText,
  config: PiiConfig,
  active: ReadonlySet<PiiKind>,
  out: PiiMatch[],
): void {
  const have = (kind: PiiKind, start: number): boolean =>
    out.some((m) => m.kind === kind && m.start === start);
  if (active.has('tckn') && !config.strictChecksum) {
    for (const m of text.raw.matchAll(TCKN_CANDIDATE)) {
      const value = m[0];
      const at = m.index ?? 0;
      if (!text.near('profile_tckn', at, at + value.length, 40, 40) || have('tckn', at)) continue;
      out.push({ kind: 'tckn', start: at, end: at + value.length, value, keepTail: 0 });
    }
  }
  if (active.has('phone')) {
    for (const m of text.raw.matchAll(PHONE_CANDIDATE)) {
      const value = m[0].trim();
      // The candidate may open with a space; the match starts at the number.
      const at = (m.index ?? 0) + (m[0].length - m[0].trimStart().length);
      if (!text.near('profile_phone', at, at + value.length, 40, 40) || have('phone', at)) continue;
      out.push({ kind: 'phone', start: at, end: at + value.length, value, keepTail: 0 });
    }
  }
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
