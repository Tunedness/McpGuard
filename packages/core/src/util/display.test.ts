import { describe, expect, it } from 'vitest';
import { escapeUnsafeJson, quote } from './display.js';

/**
 * What `JSON.stringify` lets through is exactly what the helper exists for: the
 * cases below are the ones it prints raw.
 */

const UNSAFE = /[\p{Cc}\p{Cf}\u2028\u2029]/u;

const RAW_AFTER_STRINGIFY = [
  ['a right-to-left override', 'lookup\u202etxt.ecivres_efas'],
  ['a bidi isolate', 'a\u2066b\u2069c'],
  ['a zero-width space', 'a\u200bb'],
  ['a byte-order mark', 'a\ufeffb'],
  ['a C1 CSI', 'a\u009b2Kb'],
  ['a C1 next-line', 'a\u0085b'],
  ['a line separator', 'a\u2028b'],
  ['a paragraph separator', 'a\u2029b'],
  ['a supplementary tag character', 'a\u{e0041}b'],
] as const;

describe('quote', () => {
  it.each(RAW_AFTER_STRINGIFY)('writes out %s', (_label, text) => {
    // The premise: JSON.stringify alone leaves it in.
    expect(JSON.stringify(text)).toMatch(UNSAFE);

    const shown = quote(text);
    // Nothing left that a terminal or a bidi-aware viewer would act on.
    expect(shown).not.toMatch(UNSAFE);
    // Still JSON, and it round-trips to the original.
    expect(JSON.parse(shown)).toBe(text);
  });

  it('writes out an ESC, which JSON.stringify already escapes', () => {
    expect(quote('a\u001b[2Kb')).toBe('"a\\u001b[2Kb"');
  });

  it('shows the escape, so the reader can see what was there', () => {
    expect(quote('a\u202eb')).toBe('"a\\u202eb"');
    expect(quote('a\u009bb')).toBe('"a\\u009bb"');
    expect(quote('a\u{e0041}b')).toBe('"a\\udb40\\udc41b"');
  });

  it('leaves ordinary text, accents and emoji alone', () => {
    expect(quote('lookup_kayıt 🔎')).toBe('"lookup_kayıt 🔎"');
  });
});

describe('escapeUnsafeJson', () => {
  it('works on a whole serialised object', () => {
    const json = JSON.stringify({ name: 'a\u202eb', n: 1 });

    expect(escapeUnsafeJson(json)).toBe('{"name":"a\\u202eb","n":1}');
  });
});
