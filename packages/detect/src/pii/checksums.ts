/**
 * The check digits that separate a real identifier from an eleven-digit order
 * number.
 *
 * Every recogniser that has a checksum uses it as a gate by default, and the
 * reason is arithmetic: eleven-digit numbers are everywhere, and the check
 * digit shrinks the accidental-match space by about a hundredfold. Turning the
 * gate off is a regulated-tenant choice, made with the false-positive numbers in
 * front of you, not a default.
 */

/** The Turkish national identity number checksum (T.C. Kimlik No). */
export function isValidTckn(value: string): boolean {
  if (!/^[1-9]\d{10}$/.test(value)) return false;
  const d = [...value].map(Number);
  const at = (i: number): number => d[i] ?? 0;
  const oddSum = at(0) + at(2) + at(4) + at(6) + at(8);
  const evenSum = at(1) + at(3) + at(5) + at(7);
  const tenth = (((oddSum * 7 - evenSum) % 10) + 10) % 10;
  if (tenth !== at(9)) return false;
  const eleventh = d.slice(0, 10).reduce((a, b) => a + b, 0) % 10;
  return eleventh === at(10);
}

/** The Turkish tax number checksum (Vergi Kimlik No), Maliye's mod-10 scheme. */
export function isValidVkn(value: string): boolean {
  if (!/^\d{10}$/.test(value)) return false;
  const d = [...value].map(Number);
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    const t = ((d[i] ?? 0) + (9 - i)) % 10;
    if (t === 0) continue;
    const q = (t * 2 ** (9 - i)) % 9;
    sum += q === 0 ? 9 : q;
  }
  const check = (10 - (sum % 10)) % 10;
  return check === d[9];
}

/** The Luhn (mod-10) checksum used by payment cards. */
export function isValidLuhn(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

/** ISO 7064 mod-97-10, used by IBAN, computed as a stream to avoid big integers. */
export function isValidIbanChecksum(iban: string): boolean {
  const compact = iban.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{1,30}$/.test(compact)) return false;
  // Move the first four characters to the end, then map letters to numbers.
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const char of rearranged) {
    const value = char >= 'A' && char <= 'Z' ? char.charCodeAt(0) - 55 : Number(char);
    if (Number.isNaN(value)) return false;
    // Feed one or two decimal digits at a time, keeping the running remainder
    // small — mod-97 of the whole number without ever forming it.
    remainder = value > 9 ? (remainder * 100 + value) % 97 : (remainder * 10 + value) % 97;
  }
  return remainder === 1;
}

/** Expected IBAN length per country, for the countries the recogniser knows. */
export const IBAN_LENGTHS: Record<string, number> = {
  TR: 26,
  DE: 22,
  GB: 22,
  FR: 27,
  NL: 18,
  CH: 21,
};

/** The card scheme an IIN prefix and length belong to, or `undefined`. */
export function cardScheme(digits: string): string | undefined {
  const len = digits.length;
  if (len < 12 || len > 19) return undefined;
  if (/^4/.test(digits) && (len === 13 || len === 16 || len === 19)) return 'visa';
  if (/^(5[1-5]|22[2-9]|2[3-6]\d|27[01]|2720)/.test(digits) && len === 16) return 'mastercard';
  if (/^3[47]/.test(digits) && len === 15) return 'amex';
  if (/^9792/.test(digits) && (len === 16 || len === 19)) return 'troy';
  if (/^62/.test(digits) && len >= 16) return 'unionpay';
  if (/^(6011|65|64[4-9])/.test(digits) && len === 16) return 'discover';
  return undefined;
}

/**
 * The GS1 check digit (mod 10, weights 3 and 1) over a GTIN of any length.
 *
 * The weights run from the right: the digit next to the check digit weighs 3,
 * the next 1, and so on. `digits` is the whole GTIN, check digit included.
 */
export function isValidGs1CheckDigit(digits: string): boolean {
  if (!/^\d{8,18}$/.test(digits)) return false;
  let sum = 0;
  let weight = 3;
  for (let i = digits.length - 2; i >= 0; i--) {
    sum += Number(digits[i]) * weight;
    weight = weight === 3 ? 1 : 3;
  }
  return (10 - (sum % 10)) % 10 === Number(digits[digits.length - 1]);
}

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/** Whether `year-month-day` is a real Gregorian calendar date. */
export function isValidCalendarDate(year: number, month: number, day: number): boolean {
  if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) return false;
  if (year < 1 || month < 1 || month > 12 || day < 1) return false;
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const limit = month === 2 && leap ? 29 : (DAYS_IN_MONTH[month - 1] ?? 0);
  return day <= limit;
}

/**
 * The structural rules the SSA publishes for a US Social Security number: the
 * area is not 000, 666 or 900–999, the group is not 00 and the serial is not
 * 0000. There is no check digit; this only rules out numbers that were never
 * issued. Takes the nine digits with the separators already removed.
 */
export function isPlausibleSsn(digits: string): boolean {
  if (!/^\d{9}$/.test(digits)) return false;
  const area = Number(digits.slice(0, 3));
  const group = Number(digits.slice(3, 5));
  const serial = Number(digits.slice(5));
  if (area === 0 || area === 666 || area >= 900) return false;
  return group !== 0 && serial !== 0;
}

/** The letters a Medicare Beneficiary Identifier may carry: A–Z without S L O I B Z. */
const MBI_LETTER = 'ACDEFGHJKMNPQRTUVWXY';

/**
 * The position grammar of a US Medicare Beneficiary Identifier (CMS), eleven
 * characters, `C A AN N A AN N A A N N`: C is 1–9, A a permitted letter, AN a
 * permitted letter or a digit, N a digit. Takes the characters with the
 * display hyphens already removed.
 */
export function isValidMbiShape(value: string): boolean {
  if (value.length !== 11) return false;
  const upper = value.toUpperCase();
  const letter = (i: number): boolean => MBI_LETTER.includes(upper[i] ?? '#');
  const digit = (i: number): boolean => /\d/.test(upper[i] ?? '#');
  return (
    /[1-9]/.test(upper[0] ?? '#') &&
    letter(1) &&
    (letter(2) || digit(2)) &&
    digit(3) &&
    letter(4) &&
    (letter(5) || digit(5)) &&
    digit(6) &&
    letter(7) &&
    letter(8) &&
    digit(9) &&
    digit(10)
  );
}
