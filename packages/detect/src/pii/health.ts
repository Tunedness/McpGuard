/**
 * The health-data recognisers (ADR-012).
 *
 * Same three stages as the base recognisers — a bounded candidate, a
 * deterministic validator, keyword context where nothing else can decide — with
 * one difference: the keywords are ruleset data read through {@link PiiText},
 * and the candidate shapes are code. Nothing here builds a pattern from data.
 *
 * A bare number is never enough. A hospital protocol number has no standard
 * shape, a date of birth looks like every other date, a nine-digit run is
 * everything. Each of these therefore fires only beside a word that says what
 * it is, or — for the Medicare and ICD-style shapes — when the shape itself is
 * strict enough that an accident is rare.
 */
import { isPlausibleSsn, isValidCalendarDate, isValidMbiShape } from './checksums.js';
import type { PiiText } from './context.js';
import type { PiiMatch } from './recognizers.js';

/** How far ahead of a candidate its keyword may start, and how far behind it. */
const BEFORE = 40;
const AFTER = 16;

/** The window an exclusion word is looked for in: wider than the keyword's, on both sides. */
const EXCLUDE_BEFORE = 40;
const EXCLUDE_AFTER = 40;

function push(out: PiiMatch[], kind: PiiMatch['kind'], start: number, value: string): void {
  out.push({ kind, start, end: start + value.length, value, keepTail: 0 });
}

function isAlnum(ch: string | undefined): boolean {
  return ch !== undefined && /[\p{L}\p{N}]/u.test(ch);
}

/**
 * `health_ref`: a hospital or insurer reference number after an anchor word.
 *
 * The token is 4–20 characters of `[A-Za-z0-9-]` — and `/`, `.` or `_` between
 * them when a digit follows — with at least one digit, and starts within three separator characters of the anchor — a line break is not
 * a separator, so an anchor at the end of a line cannot reach the next one.
 * Without an anchor it never matches, and an exclusion word beside it (a courier,
 * an annual report) takes it out again — unless the anchor is itself a clinical word.
 */
export function findHealthRef(text: PiiText, out: PiiMatch[]): void {
  const raw = text.raw;
  for (const anchor of text.occurrences('health_ref')) {
    let i = anchor.end;
    let skipped = 0;
    while (skipped < 3 && i < raw.length) {
      const ch = raw[i];
      if (isAlnum(ch) || ch === '\n' || ch === '\r') break;
      i++;
      skipped++;
    }
    const start = i;
    while (i < raw.length) {
      const ch = raw[i] ?? '';
      if (/[A-Za-z0-9-]/.test(ch)) {
        i++;
        continue;
      }
      // A slash, dot or underscore belongs to the number when digits follow it
      // (`2024/123456`, `12.345.678`); otherwise it is the end of a sentence.
      if ((ch === '/' || ch === '.' || ch === '_') && /\d/.test(raw[i + 1] ?? '') && i > start) {
        i++;
        continue;
      }
      break;
    }
    // A token that runs into a letter or digit of another script is a word, not a number.
    if (isAlnum(raw[i])) continue;
    let end = i;
    while (end > start && raw[end - 1] === '-') end--;
    const value = raw.slice(start, end);
    if (value.length < 4 || value.length > 20 || value.startsWith('-')) continue;
    if (!/\d/.test(value)) continue;
    // A courier's tracking number or an annual report's number has the shape and
    // an anchor word; a word that says so beside it is what tells them apart. An
    // anchor that is itself clinical (`reçete no`, `MRN`) is not argued out of it:
    // a prescription that was sent by courier is still a prescription.
    if (
      !text.contains('strong_health_ref', anchor) &&
      text.near('exclude_health_ref', start, end, EXCLUDE_BEFORE, EXCLUDE_AFTER)
    ) {
      continue;
    }
    push(out, 'health_ref', start, value);
  }
}

const DATE =
  /(?<![\d./-])(?:(\d{1,2})([./])(\d{1,2})\2(\d{4})|(\d{4})-(\d{2})-(\d{2}))(?!\d|[./-]\d)/g;

/** The earliest year a date is taken as a date of anything. */
const MIN_YEAR = 1000;

/**
 * `health_date`: `dd.mm.yyyy`, `dd/mm/yyyy` or `yyyy-mm-dd`, a real calendar
 * date, with a clinical keyword beside it.
 *
 * Both day-first and month-first are accepted for the slash form — an American
 * claim line writes it the other way round — and the date only has to be valid
 * one way. There is no upper year: the detector has no clock (it is pure), and a
 * date in the future is still a date.
 */
export function findHealthDate(text: PiiText, out: PiiMatch[]): void {
  for (const m of text.raw.matchAll(DATE)) {
    const value = m[0];
    const at = m.index ?? 0;
    let valid: boolean;
    if (m[5] !== undefined) {
      valid =
        isValidCalendarDate(Number(m[5]), Number(m[6]), Number(m[7])) && Number(m[5]) >= MIN_YEAR;
    } else {
      const year = Number(m[4]);
      const first = Number(m[1]);
      const second = Number(m[3]);
      valid =
        year >= MIN_YEAR &&
        (isValidCalendarDate(year, second, first) ||
          (m[2] === '/' && isValidCalendarDate(year, first, second)));
    }
    if (!valid) continue;
    const contexts = text.nearOccurrences('health_date', at, at + value.length, BEFORE, AFTER);
    if (contexts.length === 0) continue;
    // The same rule as for references: a plainly clinical keyword (`doğum tarihi`,
    // `admission date`) is not overridden, a bare one (`admission`, `discharge`) is.
    const strong = contexts.some((context) => text.contains('strong_health_date', context));
    if (
      !strong &&
      text.near('exclude_health_date', at, at + value.length, EXCLUDE_BEFORE, EXCLUDE_AFTER)
    ) {
      continue;
    }
    push(out, 'health_date', at, value);
  }
}

const SSN_DASHED = /(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])/g;
const SSN_PLAIN = /(?<![\d-])\d{9}(?![\d-])/g;

/**
 * `ssn_us`: the dashed form, or nine digits beside an SSN keyword.
 *
 * The structural rules (no area 000/666/9xx, no group 00, no serial 0000) are the
 * gate. With `strictChecksum` off a number that breaks them still matches when a
 * keyword sits beside it, the same trade the base recognisers make.
 */
export function findSsnUs(text: PiiText, strict: boolean, out: PiiMatch[]): void {
  const raw = text.raw;
  for (const m of raw.matchAll(SSN_DASHED)) {
    const value = m[0];
    const at = m.index ?? 0;
    if (
      isPlausibleSsn(value.replaceAll('-', '')) ||
      (!strict && text.near('ssn_us', at, at + value.length, BEFORE, AFTER))
    ) {
      push(out, 'ssn_us', at, value);
    }
  }
  for (const m of raw.matchAll(SSN_PLAIN)) {
    const value = m[0];
    const at = m.index ?? 0;
    if (!text.near('ssn_us', at, at + value.length, BEFORE, AFTER)) continue;
    if (isPlausibleSsn(value) || !strict) push(out, 'ssn_us', at, value);
  }
}

// The permitted letters are A–Z without S, L, O, I, B and Z. The candidate is a
// literal pattern, not built at scan time: this package compiles no pattern
// outside the ruleset loader.
const MBI =
  /(?<![A-Za-z0-9])[1-9][ACDEFGHJKMNPQRTUVWXY](?:[ACDEFGHJKMNPQRTUVWXY]|\d)\d-?[ACDEFGHJKMNPQRTUVWXY](?:[ACDEFGHJKMNPQRTUVWXY]|\d)\d-?[ACDEFGHJKMNPQRTUVWXY]{2}\d{2}(?![A-Za-z0-9])/gi;

/**
 * `mbi_us`: a Medicare Beneficiary Identifier, by position grammar alone.
 *
 * Eleven characters, `C A AN N A AN N A A N N`, with the letters S L O I B Z
 * excluded, optionally hyphenated 4-3-4. The grammar is tight enough that no
 * keyword is needed.
 */
export function findMbiUs(raw: string, out: PiiMatch[]): void {
  for (const m of raw.matchAll(MBI)) {
    const value = m[0];
    if (!isValidMbiShape(value.replaceAll('-', ''))) continue;
    push(out, 'mbi_us', m.index ?? 0, value);
  }
}

const ICD10 = /(?<![A-Za-z0-9.])[A-Z]\d{2}(?:\.\d{1,4})?(?![A-Za-z0-9]|\.\d)/g;
const LIST_JOIN = /^(?:\s*[,;]\s*|\s+(?:ve|and)\s+)$/i;

/**
 * `icd10`: letter, two digits, an optional `.` and up to four more — beside a
 * diagnosis keyword.
 *
 * No code list is checked: WHO's list is licensed and does not ship. Shape and
 * context are the whole test, and the context is mandatory because `B12` and
 * `E10` are also vitamins and product codes. A code that directly follows an
 * accepted one in a list (`Tanı: E11.9, I10, J45`) inherits the keyword.
 */
export function findIcd10(text: PiiText, out: PiiMatch[]): void {
  let previousEnd = -1;
  for (const m of text.raw.matchAll(ICD10)) {
    const value = m[0];
    const at = m.index ?? 0;
    // The join between two codes is a few characters; a longer gap is not a list.
    const inList =
      previousEnd >= 0 && at - previousEnd <= 8 && LIST_JOIN.test(text.raw.slice(previousEnd, at));
    if (!inList && !text.near('icd10', at, at + value.length, BEFORE, AFTER)) continue;
    push(out, 'icd10', at, value);
    previousEnd = at + value.length;
  }
}

const ATC = /(?<![A-Za-z0-9])[ABCDGHJLMNPRSV]\d{2}[A-Z]{2}\d{2}(?![A-Za-z0-9])/g;

/**
 * `atc`: a seven-character WHO ATC code (`N02BE01`).
 *
 * Shape only: the first letter must be one of the fourteen anatomical groups,
 * which is what keeps a product code from matching.
 */
export function findAtc(raw: string, out: PiiMatch[]): void {
  for (const m of raw.matchAll(ATC)) push(out, 'atc', m.index ?? 0, m[0]);
}
