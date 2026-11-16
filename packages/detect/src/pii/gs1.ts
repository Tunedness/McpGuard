/**
 * `gs1_serial`: a medicine-pack or device identifier, GS1 application identifiers
 * `(01)` GTIN and `(21)` serial together.
 *
 * A GTIN alone names a product and is on every retail barcode, so it is never
 * masked; the serial is what makes the pack one individual box, and the box is
 * what an İTS record ties to a patient. The recogniser needs both, in one run,
 * and masks the whole run — the batch `(10)` and expiry `(17)` that ride along
 * would otherwise be left next to a mask.
 *
 * Two written forms are read: the human-readable one with parenthesised AIs
 * (a single space after a `)` or between groups is read through, as a document
 * or a screen dump sets it), and the raw data-carrier one, where a variable-length
 * field ends at the GS control character (`\x1D`) or at the end of the token and
 * a symbology identifier (`]d2`, `]C1`, `]Q3`) may come first.
 *
 * The GTIN check digit is the gate. With `strictChecksum` off a wrong one still
 * counts when a keyword (`karekod`, `lot`, `UDI`...) sits beside the run — the
 * same trade every checksummed recogniser makes.
 */
import { isValidGs1CheckDigit } from './checksums.js';
import type { PiiText } from './context.js';
import type { PiiMatch } from './recognizers.js';

const GS = '\x1D';
/** A defensive cap on how much of a token one chain may swallow. */
const MAX_CHAIN = 96;

const HRI_START = /\((01|10|11|15|17|21)\)/g;
// The symbology identifier ends in a digit, so it is let through the boundary test.
const RAW_START = /(?:(?<=\]d2|\]C1|\]Q3)|(?<![A-Za-z0-9]))01(\d{14})/g;

function isTokenChar(ch: string | undefined): boolean {
  return ch !== undefined && /[A-Za-z0-9]/.test(ch);
}

function digitsAt(raw: string, from: number, count: number): boolean {
  return raw.length >= from + count && /^\d+$/.test(raw.slice(from, from + count));
}

interface Chain {
  readonly end: number;
  readonly serial: boolean;
  readonly gtin: string | undefined;
}

/** Parses a run of `(AI)value` groups beginning at `from`. */
function parseHri(raw: string, from: number): Chain | undefined {
  let i = from;
  let end = from;
  let serial = false;
  let gtin: string | undefined;
  while (raw[i] === '(' && i - from < MAX_CHAIN) {
    const ai = raw.slice(i + 1, i + 3);
    if (raw[i + 3] !== ')') break;
    let valueAt = i + 4;
    if (raw[valueAt] === ' ') valueAt++;
    let valueEnd: number;
    if (ai === '01') {
      if (!digitsAt(raw, valueAt, 14)) break;
      gtin = raw.slice(valueAt, valueAt + 14);
      valueEnd = valueAt + 14;
    } else if (ai === '11' || ai === '15' || ai === '17') {
      if (!digitsAt(raw, valueAt, 6)) break;
      valueEnd = valueAt + 6;
    } else if (ai === '10' || ai === '21') {
      valueEnd = valueAt;
      while (valueEnd < raw.length && isTokenChar(raw[valueEnd])) valueEnd++;
      if (valueEnd === valueAt) break;
      if (ai === '21') serial = true;
    } else {
      break;
    }
    end = valueEnd;
    i = valueEnd;
    // One space may separate two groups; it is not part of the run.
    if (raw[i] === ' ' && raw[i + 1] === '(') i++;
  }
  return end === from ? undefined : { end, serial, gtin };
}

/** Parses the raw AI string that follows a GTIN starting at `from`. */
function parseRaw(raw: string, from: number): { end: number; serial: boolean } {
  let i = from;
  let end = from;
  let serial = false;
  // A scanner's output has none, a printed line may carry one space after the GTIN.
  if (raw[i] === ' ' && /^(?:10|21|11|15|17)[A-Za-z0-9]/.test(raw.slice(i + 1, i + 4))) i++;
  while (i < raw.length && i - from < MAX_CHAIN) {
    const ai = raw.slice(i, i + 2);
    if (ai === '11' || ai === '15' || ai === '17') {
      if (!digitsAt(raw, i + 2, 6)) break;
      i += 8;
      end = i;
      // A GS after a fixed-length field is not required, but a writer that
      // separates every field with one is common enough to read through.
      if (raw[i] === GS) i++;
      continue;
    }
    if (ai !== '10' && ai !== '21') break;
    let j = i + 2;
    while (j < raw.length && isTokenChar(raw[j])) j++;
    if (j === i + 2) break;
    if (ai === '21') serial = true;
    end = j;
    if (raw[j] === GS) {
      i = j + 1;
      continue;
    }
    // After a variable field a space counts only when a date AI follows it, which
    // is a shape no word of prose has.
    if (raw[j] === ' ' && /^(?:11|15|17)\d{6}(?!\d)/.test(raw.slice(j + 1, j + 9))) {
      i = j + 1;
      continue;
    }
    break;
  }
  return { end, serial };
}

/** Finds every GTIN-plus-serial run in `raw`. */
export function findGs1Serial(text: PiiText, strict: boolean, out: PiiMatch[]): void {
  const raw = text.raw;
  const accept = (start: number, end: number, gtin: string): void => {
    if (!isValidGs1CheckDigit(gtin)) {
      // The loose mode lets a keyword rescue a wrong check digit, as elsewhere.
      if (strict || !text.near('gs1_serial', start, end, 40, 16)) return;
    }
    out.push({ kind: 'gs1_serial', start, end, value: raw.slice(start, end), keepTail: 0 });
  };

  let hriEnd = -1;
  for (const m of raw.matchAll(HRI_START)) {
    const at = m.index ?? 0;
    if (at < hriEnd) continue;
    const chain = parseHri(raw, at);
    if (chain === undefined) continue;
    hriEnd = chain.end;
    // `(01)` and `(21)` together, or it is a product code or a batch label.
    if (!chain.serial || chain.gtin === undefined) continue;
    accept(at, chain.end, chain.gtin);
  }

  for (const m of raw.matchAll(RAW_START)) {
    const at = m.index ?? 0;
    const chain = parseRaw(raw, at + 16);
    if (!chain.serial) continue;
    accept(at, chain.end, m[1] ?? '');
  }
}
