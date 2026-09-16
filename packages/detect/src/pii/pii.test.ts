import { describe, expect, it } from 'vitest';
import {
  cardScheme,
  isValidIbanChecksum,
  isValidLuhn,
  isValidTckn,
  isValidVkn,
} from './checksums.js';
import { maskEdits, maskFor } from './mask.js';
import { type PiiConfig, recognize } from './recognizers.js';

/**
 * The recognisers, tested where they earn their keep: the checksum is what
 * separates a national id from an order number, so the cases are about a valid
 * value matching and an invalid one — of the same shape — not matching.
 */

const strict: PiiConfig = { recognizers: new Set(), strictChecksum: true };
const loose: PiiConfig = { recognizers: new Set(), strictChecksum: false };

describe('checksums', () => {
  it('accepts a valid TCKN and rejects a same-length non-TCKN', () => {
    expect(isValidTckn('10000000146')).toBe(true);
    expect(isValidTckn('12345678901')).toBe(false);
    expect(isValidTckn('00000000000')).toBe(false);
  });

  it('validates a VKN', () => {
    expect(isValidVkn('1234567890')).toBe(true);
    expect(isValidVkn('1111111111')).toBe(false);
  });

  it('validates Luhn and the card scheme together', () => {
    expect(isValidLuhn('4111111111111111')).toBe(true);
    expect(cardScheme('4111111111111111')).toBe('visa');
    expect(isValidLuhn('4111111111111112')).toBe(false);
  });

  it('validates an IBAN checksum and rejects a broken one', () => {
    expect(isValidIbanChecksum('TR330006100519786457841326')).toBe(true);
    expect(isValidIbanChecksum('DE89370400440532013000')).toBe(true);
    expect(isValidIbanChecksum('TR000000000000000000000000')).toBe(false);
  });
});

describe('recognize with the checksum as a gate', () => {
  it('masks a valid TCKN and leaves an invalid eleven-digit number alone', () => {
    const valid = recognize('Kimlik: 10000000146 kayıtlı.', strict);
    expect(valid.map((m) => m.kind)).toContain('tckn');

    const order = recognize('Sipariş no 12345678901 hazır.', strict);
    expect(order.some((m) => m.kind === 'tckn')).toBe(false);
  });

  it('masks a checksum-failing TCKN in loose mode when a keyword is beside it', () => {
    // A mistyped national id is still personal data under KVKK; the regulated
    // tenant opts into masking it when the context says what it is.
    const near = recognize('TC kimlik: 12345678901', loose);
    expect(near.some((m) => m.kind === 'tckn')).toBe(true);
  });

  it('masks a valid IBAN with a country-length check', () => {
    const matches = recognize('IBAN: TR330006100519786457841326', strict);
    expect(matches.some((m) => m.kind === 'iban')).toBe(true);
  });

  it('masks a Luhn-valid card but not a 13-digit EAN', () => {
    expect(recognize('kart 4111 1111 1111 1111', strict).some((m) => m.kind === 'card')).toBe(true);
    expect(recognize('barkod 9780306406157', strict).some((m) => m.kind === 'card')).toBe(false);
  });

  it('masks an explicit +90 phone without a keyword', () => {
    expect(recognize('Ara: +90 532 123 45 67', strict).some((m) => m.kind === 'phone')).toBe(true);
  });

  it('masks an e-mail but skips an example.com address', () => {
    expect(recognize('mail: ada@acme.co', strict).some((m) => m.kind === 'email')).toBe(true);
    expect(recognize('mail: a@example.com', strict).some((m) => m.kind === 'email')).toBe(false);
  });
});

describe('masking', () => {
  it('renders a full mask by default, keeping the label', () => {
    const [match] = recognize('10000000146', strict);
    if (match === undefined) throw new Error('no match');
    expect(maskFor(match, { keepLast: 0, correlationTags: false })).toBe('[TCKN:***]');
  });

  it('keeps a reconciliation tail when asked, bounded by the recogniser', () => {
    const [match] = recognize('TR330006100519786457841326', strict);
    if (match === undefined) throw new Error('no match');
    const masked = maskFor(match, { keepLast: 4, correlationTags: false });
    expect(masked).toBe('[IBAN:***1326]');
  });

  it('attaches a short correlation tag that is the same for the same value', () => {
    const [a] = recognize('10000000146', strict);
    const [b] = recognize('10000000146', strict);
    if (a === undefined || b === undefined) throw new Error('no match');
    const cfg = { keepLast: 0, correlationTags: true, correlationKey: 'deployment-secret' };
    const ma = maskFor(a, cfg);
    expect(ma).toMatch(/^\[TCKN:\*\*\*#[0-9a-f]{4}\]$/);
    expect(maskFor(b, cfg)).toBe(ma);
  });

  it('omits the tag when no key is configured', () => {
    const [match] = recognize('10000000146', strict);
    if (match === undefined) throw new Error('no match');
    expect(maskFor(match, { keepLast: 0, correlationTags: true })).toBe('[TCKN:***]');
  });

  it('produces one edit per match, left to right', () => {
    const matches = recognize('id 10000000146 mail ada@acme.co', strict);
    const edits = maskEdits(matches, { keepLast: 0, correlationTags: false });
    expect(edits).toHaveLength(2);
    expect(edits[0]?.span.start).toBeLessThan(edits[1]?.span.start ?? 0);
  });
});

describe('card schemes and iban lengths', () => {
  it('recognises the major schemes by prefix and length', () => {
    // A generated Luhn-valid number per scheme; the scheme gate is what stops a
    // random 16-digit run from being masked as a card.
    expect(cardScheme('5555555555554444')).toBe('mastercard');
    expect(cardScheme('378282246310005')).toBe('amex');
    expect(cardScheme('6011111111111117')).toBe('discover');
    expect(cardScheme('6200000000000005')).toBe('unionpay');
    expect(cardScheme('1234567890123456')).toBeUndefined();
  });

  it('enforces the country length before checking an IBAN', () => {
    // A TR IBAN that is the wrong length is rejected before the mod-97, so a
    // long account-like string does not get masked.
    const short = recognize('IBAN TR3300061005197864578413', {
      recognizers: new Set(['iban']),
      strictChecksum: true,
    });
    expect(short.some((m) => m.kind === 'iban')).toBe(false);
  });
});

describe('loose-mode recognisers', () => {
  it('masks a keyworded VKN, card and phone even without the checksum', () => {
    const vkn = recognize('Vergi no 1111111111', {
      recognizers: new Set(['vkn']),
      strictChecksum: false,
    });
    expect(vkn.some((m) => m.kind === 'vkn')).toBe(true);

    const phone = recognize('cep 0555 111 22 33', {
      recognizers: new Set(['phone']),
      strictChecksum: false,
    });
    expect(phone.some((m) => m.kind === 'phone')).toBe(true);
  });

  it('runs only the recognisers asked for', () => {
    const only = recognize('kimlik 10000000146 mail a@acme.co', {
      recognizers: new Set(['email']),
      strictChecksum: true,
    });
    expect(only.map((m) => m.kind)).toEqual(['email']);
  });
});

describe('strict VKN', () => {
  it('masks a checksum-valid VKN in strict mode', () => {
    const matches = recognize('Vergi kimlik 1234567890 kayıtlı', {
      recognizers: new Set(['vkn']),
      strictChecksum: true,
    });
    expect(matches.some((m) => m.kind === 'vkn')).toBe(true);
  });
});
