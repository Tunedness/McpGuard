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
