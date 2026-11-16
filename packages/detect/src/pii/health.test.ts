import { describe, expect, it } from 'vitest';
import { fixtureData } from '../testing/pii-data.js';
import { type PiiConfig, type PiiKind, recognize } from './recognizers.js';

/**
 * The health recognisers, tested where each earns its keep: the shape alone must
 * not be enough for the ones that have no checksum, and the keyword must be what
 * decides — so every case is a value that matches with its keyword and the same
 * value that does not match without it.
 */

const data = fixtureData();

function config(kinds: PiiKind[], strictChecksum = true): PiiConfig {
  return { recognizers: new Set(kinds), strictChecksum, profile: 'health', data };
}

function found(text: string, kinds: PiiKind[], strict = true): string[] {
  return recognize(text, config(kinds, strict)).map((m) => `${m.kind}:${m.value}`);
}

describe('health_ref', () => {
  it('matches a token after an anchor and never without one', () => {
    expect(found('Hasta No: 8842019 kayıtlı.', ['health_ref'])).toEqual(['health_ref:8842019']);
    expect(found('Kayıt 8842019 kayıtlı.', ['health_ref'])).toEqual([]);
  });

  it('reads the Turkish case and diacritic variants of an anchor', () => {
    expect(found('HASTA NO 8842019', ['health_ref'])).toEqual(['health_ref:8842019']);
    expect(found('e-Reçete No - AB-123456', ['health_ref'])).toEqual(['health_ref:AB-123456']);
    expect(found('E-RECETE NO: 123456', ['health_ref'])).toEqual(['health_ref:123456']);
    expect(found('PROTOKOL NO #2024-0012345', ['health_ref'])).toEqual(['health_ref:2024-0012345']);
  });

  it('keeps a Turkish dotted capital from shifting the offsets after it', () => {
    const text = 'İİİ Hasta No: 8842019';
    const [match] = recognize(text, config(['health_ref']));

    expect(text.slice(match?.start, match?.end)).toBe('8842019');
  });

  it('needs a digit and four to twenty characters', () => {
    expect(found('Hasta No: yok', ['health_ref'])).toEqual([]);
    expect(found('Hasta No: 123', ['health_ref'])).toEqual([]);
    expect(found('Hasta No: A1B2C3D4E5F6G7H8I9J0K', ['health_ref'])).toEqual([]);
    expect(found('Hasta No: 1234567890123456789', ['health_ref'])).toHaveLength(1);
  });

  it('does not reach across a line break or past three separators', () => {
    expect(found('Hasta No:\n8842019', ['health_ref'])).toEqual([]);
    expect(found('Hasta No :::: 8842019', ['health_ref'])).toEqual([]);
  });

  it('drops a trailing hyphen from the token, and a word that continues is not a number', () => {
    expect(found('Hasta No: 8842019-.', ['health_ref'])).toEqual(['health_ref:8842019']);
    expect(found('Hasta No: 88420çalışan', ['health_ref'])).toEqual([]);
    expect(found('Hasta No -123456', ['health_ref'])).toEqual(['health_ref:123456']);
  });

  it('does not match an anchor sentence with no number', () => {
    expect(found('Protokol numaranızı getirmeyi unutmayın.', ['health_ref'])).toEqual([]);
    expect(found('Hasta no alanı boş bırakılamaz.', ['health_ref'])).toEqual([]);
  });

  it('matches an English anchor', () => {
    expect(found('MRN: 00481923', ['health_ref'])).toEqual(['health_ref:00481923']);
    expect(found('Medical Record Number 77310-22', ['health_ref'])).toEqual([
      'health_ref:77310-22',
    ]);
  });
});

describe('health_ref tokens that carry a separator', () => {
  it('keeps a slash, dot or underscore inside the number when digits follow it', () => {
    expect(found('Dosya No: 2024/123456', ['health_ref'])).toEqual([]); // not an anchor here
    expect(found('Hasta No: 2024/123456', ['health_ref'])).toEqual(['health_ref:2024/123456']);
    expect(found('Hasta No: 2024_99812', ['health_ref'])).toEqual(['health_ref:2024_99812']);
    expect(found('Protokol No: 12.345.678', ['health_ref'])).toEqual(['health_ref:12.345.678']);
  });

  it('stops at a separator that ends the sentence or starts a word', () => {
    expect(found('Hasta No: 8842019.', ['health_ref'])).toEqual(['health_ref:8842019']);
    expect(found('Hasta No: 8842019.Sonraki', ['health_ref'])).toEqual(['health_ref:8842019']);
    expect(found('Hasta No: 8842019/ ok', ['health_ref'])).toEqual(['health_ref:8842019']);
  });
});

describe('exclusion words', () => {
  it('keep a tracking number and a report number from being masked as a patient reference', () => {
    expect(found('Kargo takip no: 123456789012', ['health_ref'])).toEqual([]);
    expect(found('Rapor No: 123456 (yıllık Faaliyet Raporu)', ['health_ref'])).toEqual([]);
    expect(found('The Courier asked for Takip No 12345678', ['health_ref'])).toEqual([]);
    // The same anchors, no exclusion word.
    expect(found('Protokol No: 123456', ['health_ref'])).toEqual(['health_ref:123456']);
  });

  it('never override a plainly clinical anchor: a prescription sent by courier is still a prescription', () => {
    expect(
      found('Eczaneden ilacınız kargo ile gönderildi. Protokol no: 4471902', ['health_ref']),
    ).toEqual(['health_ref:4471902']);
    expect(found('Reçete yenileme talebi. Hasta no: 4471902', ['health_ref'])).toEqual([
      'health_ref:4471902',
    ]);
    expect(found('Specimen courier to lab. MRN: H849336', ['health_ref'])).toEqual([
      'health_ref:H849336',
    ]);
    // The same exclusion word beside an ambiguous anchor still wins.
    expect(found('Kargo takip no: 4471902', ['health_ref'], true).length).toBe(0);
  });

  it('treats a claim and a plan member anchor as clinical, whatever sits beside them', () => {
    expect(found('Claim number: 5512398 — DME wheelchair shipment.', ['health_ref'])).toEqual([
      'health_ref:5512398',
    ]);
    expect(
      found('Home infusion supplies, tracking pending. Claim # 5512398', ['health_ref']),
    ).toEqual(['health_ref:5512398']);
    expect(found('Claim #5512398 by courier', ['health_ref'])).toEqual(['health_ref:5512398']);
    expect(found('Member ID: W123456789 — shipping address on file.', ['health_ref'])).toEqual([
      'health_ref:W123456789',
    ]);
  });

  it('does not take a bare word `claim` for an anchor: a form type is not a number to mask', () => {
    expect(found('Claim 837P was submitted.', ['health_ref'])).toEqual([]);
    expect(found('Claim #: 3 of 4', ['health_ref'])).toEqual([]);
  });

  it('does not read a strong word outside the anchor as the anchor being strong', () => {
    // `hasta` is strong, but it is not in the anchor `takip no`.
    const data2 = fixtureData({
      anchors: { health_ref: ['hasta no', 'takip no'] },
    });
    const run = recognize('Hasta kargosu kargo ile geldi. Takip no: 4471902', {
      recognizers: new Set<PiiKind>(['health_ref']),
      strictChecksum: true,
      profile: 'health',
      data: data2,
    });

    expect(run).toEqual([]);
  });

  it('only reach as far as their window', () => {
    const far = `kargo ${'x '.repeat(30)}Protokol No: 123456`;

    expect(found(far, ['health_ref'])).toEqual(['health_ref:123456']);
  });

  it('keep an infrastructure date from being masked as a clinical one', () => {
    expect(found('Webhook admission discharge 2024-05-12', ['health_date'])).toEqual([]);
    expect(found('Battery discharge test 12/05/2024', ['health_date'])).toEqual([]);
    expect(found('Discharge 2024-05-12', ['health_date'])).toEqual(['health_date:2024-05-12']);
  });

  it('give way to a plainly clinical date keyword, and not to a bare one', () => {
    expect(found('Dx: battery fault. Admission date: 03/14/2024', ['health_date'])).toEqual([
      'health_date:03/14/2024',
    ]);
    expect(found('Webhook log, date of birth 1980-03-14', ['health_date'])).toEqual([
      'health_date:1980-03-14',
    ]);
    expect(found('Battery check, discharge 2024-05-12', ['health_date'])).toEqual([]);
  });
});

describe('health_date', () => {
  it('matches a valid date beside a keyword and not without one', () => {
    expect(found('Doğum tarihi: 14.03.1980', ['health_date'])).toEqual(['health_date:14.03.1980']);
    expect(found('Toplantı 14.03.1980 günü', ['health_date'])).toEqual([]);
  });

  it('reads the three formats', () => {
    expect(found('DOB 14/03/1980', ['health_date'])).toEqual(['health_date:14/03/1980']);
    expect(found('DOB 1980-03-14', ['health_date'])).toEqual(['health_date:1980-03-14']);
    expect(found('D.T.: 1.3.1980', ['health_date'])).toEqual(['health_date:1.3.1980']);
  });

  it('accepts a month-first slash date, because the claim lines write it that way', () => {
    expect(found('DOB 03/14/1980', ['health_date'])).toEqual(['health_date:03/14/1980']);
    // The dotted form is day-first only.
    expect(found('DOB 03.14.1980', ['health_date'])).toEqual([]);
  });

  it('rejects a date that is not on the calendar, with the leap year counted', () => {
    expect(found('DOB 31.04.1980', ['health_date'])).toEqual([]);
    expect(found('DOB 29.02.1981', ['health_date'])).toEqual([]);
    expect(found('DOB 29.02.1980', ['health_date'])).toEqual(['health_date:29.02.1980']);
    expect(found('DOB 1980-13-01', ['health_date'])).toEqual([]);
    expect(found('DOB 12.05.0123', ['health_date'])).toEqual([]);
  });

  it('does not take a version string or a longer dotted run for a date', () => {
    expect(found('DOB v1.12.2023.4', ['health_date'])).toEqual([]);
    expect(found('DOB 12.05.2023-7', ['health_date'])).toEqual([]);
    expect(found('DOB 12.05.20231', ['health_date'])).toEqual([]);
  });

  it('finds the keyword before the date within the window, and shortly after it', () => {
    expect(found('12.05.2023 (DOB)', ['health_date'])).toEqual(['health_date:12.05.2023']);
    const far = `DOB ${'x '.repeat(40)}12.05.2023`;
    expect(found(far, ['health_date'])).toEqual([]);
  });

  it('masks both dates of an admission line when each has its keyword', () => {
    expect(found('Yatış: 02.11.2023, Taburcu: 09.11.2023', ['health_date'])).toEqual([
      'health_date:02.11.2023',
      'health_date:09.11.2023',
    ]);
  });
});

describe('ssn_us', () => {
  it('matches the dashed form with no keyword', () => {
    expect(found('Patient 123-45-6789 billed', ['ssn_us'])).toEqual(['ssn_us:123-45-6789']);
  });

  it('matches nine digits only beside a keyword', () => {
    expect(found('SSN 123456789', ['ssn_us'])).toEqual(['ssn_us:123456789']);
    expect(found('Social Security: 123456789', ['ssn_us'])).toEqual(['ssn_us:123456789']);
    expect(found('Reference 123456789', ['ssn_us'])).toEqual([]);
  });

  it('rejects the ranges that were never issued', () => {
    for (const bad of ['000-12-3456', '666-12-3456', '912-12-3456', '123-00-4567', '123-45-0000']) {
      expect(found(`Record ${bad} filed`, ['ssn_us'])).toEqual([]);
    }
    expect(found('SSN 000123456', ['ssn_us'])).toEqual([]);
  });

  it('lets a keyword rescue an unissued number only in the loose mode', () => {
    expect(found('SSN 000-12-3456', ['ssn_us'], true)).toEqual([]);
    expect(found('SSN 000-12-3456', ['ssn_us'], false)).toEqual(['ssn_us:000-12-3456']);
    expect(found('SSN 000123456', ['ssn_us'], false)).toEqual(['ssn_us:000123456']);
    expect(found('Record 000-12-3456 filed', ['ssn_us'], false)).toEqual([]);
  });

  it('does not take a longer dashed run for an SSN', () => {
    expect(found('Part 123-45-6789-01 shipped', ['ssn_us'])).toEqual([]);
  });
});

describe('mbi_us', () => {
  it('matches the position grammar, hyphenated or not, with no keyword', () => {
    expect(found('id 1EG4-TE5-MK73 ok', ['mbi_us'])).toEqual(['mbi_us:1EG4-TE5-MK73']);
    expect(found('id 1EG4TE5MK73 ok', ['mbi_us'])).toEqual(['mbi_us:1EG4TE5MK73']);
    expect(found('id 1eg4te5mk73 ok', ['mbi_us'])).toEqual(['mbi_us:1eg4te5mk73']);
  });

  it('rejects a letter the grammar excludes, a wrong position and a wrong length', () => {
    expect(found('id 1BG4TE5MK73', ['mbi_us'])).toEqual([]); // B at position 2
    expect(found('id 1EG4TE5MK7Z', ['mbi_us'])).toEqual([]); // letter at a digit position
    expect(found('id 0EG4TE5MK73', ['mbi_us'])).toEqual([]); // leading zero
    expect(found('id 1EG4TE5MK7', ['mbi_us'])).toEqual([]);
    expect(found('id 1EG4TE5MK734', ['mbi_us'])).toEqual([]);
  });
});

describe('icd10', () => {
  it('matches a code beside a diagnosis keyword and not without one', () => {
    expect(found('Tanı: E11.9', ['icd10'])).toEqual(['icd10:E11.9']);
    expect(found('Diagnosis J45', ['icd10'])).toEqual(['icd10:J45']);
    expect(found('Ürün kodu E10 stokta', ['icd10'])).toEqual([]);
    expect(found('Vitamin B12', ['icd10'])).toEqual([]);
  });

  it('lets a list keep its keyword from one code to the next', () => {
    expect(found('Tanılar: E11.9, I10; J45.0 ve K35', ['icd10'])).toEqual([
      'icd10:E11.9',
      'icd10:I10',
      'icd10:J45.0',
      'icd10:K35',
    ]);
    // The keyword reaches 40 characters; a code past that, not in the list, is out.
    expect(found(`Tanı: E11.9. ${'x '.repeat(30)}Part I10 ships`, ['icd10'])).toEqual([
      'icd10:E11.9',
    ]);
  });

  it('does not take a longer code-like token for a diagnosis', () => {
    expect(found('Tanı: E11.9X', ['icd10'])).toEqual([]);
    expect(found('Tanı: E11.12345', ['icd10'])).toEqual([]);
    expect(found('Tanı: e11.9', ['icd10'])).toEqual([]);
  });
});

describe('atc', () => {
  it('matches the seven-character shape and needs no keyword', () => {
    expect(found('ilaç N02BE01 önerildi', ['atc'])).toEqual(['atc:N02BE01']);
  });

  it('rejects a group letter that is not an anatomical group, and a wrong length', () => {
    expect(found('Model E12AB34', ['atc'])).toEqual([]);
    expect(found('Part N02BE1', ['atc'])).toEqual([]);
    expect(found('Part N02BE012', ['atc'])).toEqual([]);
  });
});

describe('profile keyword context for the base recognisers', () => {
  const base = (text: string, strict: boolean, profile: 'default' | 'health'): string[] =>
    recognize(text, {
      recognizers: new Set<PiiKind>(['tckn', 'phone']),
      strictChecksum: strict,
      profile,
      data,
    }).map((m) => `${m.kind}:${m.value}`);

  it('rescues a mistyped national id beside a patient keyword, in the loose mode only', () => {
    expect(base('hasta 12345678901 kayıtlı', false, 'health')).toEqual(['tckn:12345678901']);
    expect(base('hasta 12345678901 kayıtlı', true, 'health')).toEqual([]);
    expect(base('hasta 12345678901 kayıtlı', false, 'default')).toEqual([]);
  });

  it('starts a rescued number at its first digit, not at the space before it', () => {
    const text = 'Hasta faks: 532 123 45 67 ok';
    const [match] = recognize(text, {
      recognizers: new Set<PiiKind>(['phone']),
      strictChecksum: true,
      profile: 'health',
      data,
    });

    expect(text.slice(match?.start, match?.end)).toBe('532 123 45 67');
  });

  it('applies to the base recognisers in a full list too, and to nothing outside it', () => {
    expect(base('faks 532 123 45 67', true, 'health')).toHaveLength(1);
    const email = recognize('faks 532 123 45 67', {
      recognizers: new Set<PiiKind>(['email']),
      strictChecksum: true,
      profile: 'health',
      data,
    });
    expect(email).toEqual([]);
  });

  it('does not add a second match for an id the base recogniser already took', () => {
    expect(base('hasta kimlik 10000000146', false, 'health')).toEqual(['tckn:10000000146']);
  });

  it('rescues a bare mobile number beside a fax keyword', () => {
    expect(base('faks 532 123 45 67', true, 'health')).toEqual(['phone:532 123 45 67']);
    expect(base('faks 532 123 45 67', true, 'default')).toEqual([]);
    expect(base('tel 532 123 45 67', true, 'health')).toEqual(['phone:532 123 45 67']);
  });
});
