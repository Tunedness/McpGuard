import { describe, expect, it } from 'vitest';
import { fixtureData } from '../testing/pii-data.js';
import {
  cardScheme,
  isPlausibleSsn,
  isValidCalendarDate,
  isValidIbanChecksum,
  isValidLuhn,
  isValidMbiShape,
  isValidTckn,
  isValidVkn,
} from './checksums.js';
import { PiiDataMissingError } from './context.js';
import { BASE_KINDS, PII_KINDS } from './kinds.js';
import { maskEdits, maskFor } from './mask.js';
import { activeKinds, type PiiConfig, type PiiKind, recognize } from './recognizers.js';

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

  it('validates the structural rules of the health identifiers', () => {
    expect(isValidCalendarDate(2024, 2, 29)).toBe(true);
    expect(isValidCalendarDate(2023, 2, 29)).toBe(false);
    expect(isValidCalendarDate(1900, 2, 29)).toBe(false);
    expect(isValidCalendarDate(2000, 2, 29)).toBe(true);
    expect(isValidCalendarDate(2024, 0, 1)).toBe(false);
    expect(isValidCalendarDate(2024, 1.5, 1)).toBe(false);
    expect(isPlausibleSsn('123456789')).toBe(true);
    expect(isPlausibleSsn('666121234')).toBe(false);
    expect(isPlausibleSsn('12345678')).toBe(false);
    expect(isValidMbiShape('1EG4TE5MK73')).toBe(true);
    expect(isValidMbiShape('1EG4TE5MK7')).toBe(false);
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

describe('profiles and the recogniser set', () => {
  const data = fixtureData();
  const config = (over: Partial<PiiConfig> = {}): PiiConfig => ({
    recognizers: new Set(),
    strictChecksum: true,
    data,
    ...over,
  });

  it('runs the base set when the list is empty and the profile is off', () => {
    expect([...activeKinds(config())]).toEqual([...BASE_KINDS]);
    expect([...activeKinds(config({ profile: 'default' }))]).toEqual([...BASE_KINDS]);
  });

  it('adds what the profile names to the base set, and never the attributes', () => {
    const kinds = activeKinds(config({ profile: 'health' }));

    expect([...kinds]).toEqual([...BASE_KINDS, ...data.profiles.health]);
    expect(kinds.has('icd10')).toBe(false);
    expect(kinds.has('atc')).toBe(false);
  });

  it('takes a non-empty list as the whole list, whatever the profile', () => {
    const kinds = activeKinds(
      config({ profile: 'health', recognizers: new Set<PiiKind>(['icd10']) }),
    );

    expect([...kinds]).toEqual(['icd10']);
  });

  it('names every kind once, base first', () => {
    expect(new Set(PII_KINDS).size).toBe(PII_KINDS.length);
    expect(PII_KINDS.slice(0, BASE_KINDS.length)).toEqual([...BASE_KINDS]);
  });

  it('refuses the profile when the ruleset has no PII data', () => {
    expect(() => recognize('x', config({ profile: 'health', data: undefined }))).toThrow(
      PiiDataMissingError,
    );
    // A recogniser that reads keywords says so too; the ones that do not still run.
    expect(() =>
      recognize('tanı E11', config({ recognizers: new Set<PiiKind>(['icd10']), data: undefined })),
    ).toThrow(PiiDataMissingError);
    expect(
      recognize(
        'id 1EG4TE5MK73',
        config({ recognizers: new Set<PiiKind>(['mbi_us']), data: undefined }),
      ),
    ).toHaveLength(1);
  });

  it('fails the profile on missing data whatever the list holds, not only when a candidate turns up', () => {
    const noData = config({
      profile: 'health',
      data: undefined,
      recognizers: new Set<PiiKind>(['phone']),
    });

    expect(() => activeKinds(noData)).toThrow(PiiDataMissingError);
    expect(() => recognize('merhaba', noData)).toThrow(PiiDataMissingError);
  });

  it('returns exactly what it always did when no profile and no health kind is on', () => {
    const text = 'kimlik 10000000146, IBAN TR330006100519786457841326, mail a@acme.co';
    const plain = recognize(text, { recognizers: new Set(), strictChecksum: true });
    const withData = recognize(text, config());

    expect(withData).toEqual(plain);
    expect(plain.map((m) => m.kind)).toEqual(['tckn', 'iban', 'email']);
  });

  it('keeps the longest span where two kinds cover the same stretch, base first on a tie', () => {
    // 11 digits after a reference anchor: a national id and a reference number.
    const tie = recognize('Hasta No: 10000000146', config({ profile: 'health' }));
    expect(tie.map((m) => m.kind)).toEqual(['tckn']);

    // A real calendar date after a reference anchor is one match, and the
    // calendar-validated kind names it.
    const nested = recognize('Protokol No: 2024-05-01 doğum tarihi', config({ profile: 'health' }));
    expect(nested.map((m) => m.kind)).toEqual(['health_date']);
    expect(nested[0]?.value).toBe('2024-05-01');
  });

  it('names an id that is both a reference by anchor and a Medicare id by grammar after the grammar', () => {
    const matches = recognize('Medicare ID 1EG4-TE5-MK73 eligible', config({ profile: 'health' }));

    expect(matches.map((m) => `${m.kind}:${m.value}`)).toEqual(['mbi_us:1EG4-TE5-MK73']);
  });

  it('masks the health kinds with their own labels', () => {
    const matches = recognize(
      'Hasta No: A1234567 tanı E11.9 SSN 123-45-6789 DOB 1980-03-14 1EG4TE5MK73 N02BE01',
      config({
        recognizers: new Set<PiiKind>(PII_KINDS.filter((k) => !BASE_KINDS.includes(k as never))),
      }),
    );
    const masked = maskEdits(matches, { keepLast: 0, correlationTags: false }).map(
      (e) => e.replacement,
    );

    expect(masked).toEqual([
      '[MRN:***]',
      '[ICD10:***]',
      '[SSN:***]',
      '[DATE:***]',
      '[MBI:***]',
      '[ATC:***]',
    ]);
  });
});
