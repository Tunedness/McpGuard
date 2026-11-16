/**
 * The PHI corpus generator.
 *
 * Synthetic from end to end: every identifier is computed, never copied, and no
 * name, address or real record appears anywhere. Checksummed values (a GTIN)
 * are built forwards from random digits, so the check digit is right by
 * construction rather than by search.
 *
 * Every item is born from its own seed, `<SEED>:<family>:<index>`, so adding a
 * family cannot reshuffle the ones beside it and the JSONL is reproduced byte
 * for byte. `corpus.test.ts` pins the file's sha256; CI regenerates and diffs.
 */
import { Rng } from '../rng.js';
import { NEGATIVE_FAMILIES, type PhiItem, type PhiKind, type PhiSpan } from './types.js';

export const SEED = 'mcpguard-phi-v1';

const PER_POSITIVE = 120;
const PER_MIXED = 60;
const PER_NEGATIVE = 60;
/** The keyword-collision family, gated, and its holdout, reported. */
const PER_COLLISION = 36;
/** Each exclusion word's positive is generated this many times, with different values. */
const PER_EXCLUSION_CASE = 3;
const PER_HOLDOUT = 48;

/** A piece of an item: plain text, or a labelled identifier. */
type Part = string | readonly [PhiKind, string];

/** Joins parts into text and records where each labelled one landed. */
function compose(parts: readonly Part[]): { text: string; spans: PhiSpan[] } {
  let text = '';
  const spans: PhiSpan[] = [];
  for (const part of parts) {
    if (typeof part === 'string') {
      text += part;
    } else {
      spans.push({ kind: part[0], start: text.length, end: text.length + part[1].length });
      text += part[1];
    }
  }
  return { text, spans };
}

// ---------------------------------------------------------------------------
// Value generators
// ---------------------------------------------------------------------------

const DIGITS = '0123456789';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const ALNUM = UPPER + DIGITS;
const MBI_LETTERS = 'ACDEFGHJKMNPQRTUVWXY';

function chars(rng: Rng, alphabet: string, n: number): string {
  let out = '';
  for (let i = 0; i < n; i++) out += alphabet[rng.int(alphabet.length)];
  return out;
}

function pad(n: number, width: number): string {
  return String(n).padStart(width, '0');
}

/** A reference number in one of the shapes a hospital system uses. */
function refToken(rng: Rng): string {
  switch (rng.int(8)) {
    case 5:
      return `${2019 + rng.int(7)}/${chars(rng, DIGITS, 5 + rng.int(3))}`;
    case 6:
      return `${chars(rng, DIGITS, 2)}.${chars(rng, DIGITS, 3)}.${chars(rng, DIGITS, 3)}`;
    case 7:
      return `${2019 + rng.int(7)}_${chars(rng, DIGITS, 5 + rng.int(3))}`;
    case 0:
      return chars(rng, DIGITS, 6 + rng.int(4));
    case 1:
      return `${chars(rng, UPPER, 1)}${chars(rng, DIGITS, 6 + rng.int(3))}`;
    case 2:
      return `${2019 + rng.int(7)}-${chars(rng, DIGITS, 6 + rng.int(2))}`;
    case 3:
      return `${chars(rng, UPPER, 2 + rng.int(2))}-${chars(rng, DIGITS, 5 + rng.int(3))}`;
    default:
      return `${chars(rng, DIGITS, 5)}-${chars(rng, DIGITS, 2)}`;
  }
}

interface Ymd {
  readonly y: number;
  readonly m: number;
  readonly d: number;
}

/** A real calendar date. Days stop at 28, so every month is valid without a leap check. */
function ymd(rng: Rng, minYear: number, maxYear: number): Ymd {
  return { y: minYear + rng.int(maxYear - minYear + 1), m: 1 + rng.int(12), d: 1 + rng.int(28) };
}

type DateStyle = 'dot' | 'slash-dm' | 'slash-md' | 'iso';

function formatDate(date: Ymd, style: DateStyle): string {
  switch (style) {
    case 'dot':
      return `${pad(date.d, 2)}.${pad(date.m, 2)}.${date.y}`;
    case 'slash-dm':
      return `${pad(date.d, 2)}/${pad(date.m, 2)}/${date.y}`;
    case 'slash-md':
      return `${pad(date.m, 2)}/${pad(date.d, 2)}/${date.y}`;
    case 'iso':
      return `${date.y}-${pad(date.m, 2)}-${pad(date.d, 2)}`;
  }
}

/** The GS1 check digit for the first 13 digits of a GTIN-14. */
function gtinCheckDigit(first13: string): string {
  let sum = 0;
  let weight = 3;
  for (let i = first13.length - 1; i >= 0; i--) {
    sum += Number(first13[i]) * weight;
    weight = weight === 3 ? 1 : 3;
  }
  return String((10 - (sum % 10)) % 10);
}

/** A GTIN-14 with a valid check digit, in the `0869…` shape Turkish medicines carry. */
function gtin14(rng: Rng): string {
  const first13 = `0869${chars(rng, DIGITS, 9)}`;
  return first13 + gtinCheckDigit(first13);
}

/** A GTIN-14 whose check digit is wrong by construction. */
function brokenGtin14(rng: Rng): string {
  const good = gtin14(rng);
  const wrong = String((Number(good[13]) + 1 + rng.int(8)) % 10);
  return good.slice(0, 13) + wrong;
}

/** A retail EAN-13 (`869…`) with a valid check digit. */
function ean13(rng: Rng): string {
  const first12 = `869${chars(rng, DIGITS, 9)}`;
  return first12 + gtinCheckDigit(`0${first12}`);
}

function serialNumber(rng: Rng): string {
  return chars(rng, ALNUM, 10 + rng.int(5));
}

function expiry(rng: Rng): string {
  return `${pad(26 + rng.int(4), 2)}${pad(1 + rng.int(12), 2)}${pad(1 + rng.int(28), 2)}`;
}

function lot(rng: Rng): string {
  return chars(rng, ALNUM, 4 + rng.int(5));
}

const GS = '\x1D';

/** A GS1 run in the human-readable form. */
function hriRun(rng: Rng): string {
  const parts = [`(01)${gtin14(rng)}`, `(21)${serialNumber(rng)}`];
  if (rng.chance(0.7)) parts.push(`(17)${expiry(rng)}`);
  if (rng.chance(0.7)) parts.push(`(10)${lot(rng)}`);
  // A document or a screen dump sets the groups apart with a space.
  return rng.chance(0.2) ? parts.map((p) => p.replace(')', ') ')).join(' ') : parts.join('');
}

/** A GS1 run in the raw data-carrier form, with the GS separators a scanner emits. */
function rawRun(rng: Rng): string {
  let out = `01${gtin14(rng)}21${serialNumber(rng)}`;
  const tail: string[] = [];
  if (rng.chance(0.7)) tail.push(`17${expiry(rng)}`);
  if (rng.chance(0.7)) tail.push(`10${lot(rng)}`);
  if (tail.length > 0) out += GS + tail.join(GS);
  return out;
}

/** The raw form as a reader prints it: a symbology identifier first and a space after the GTIN. */
function printedRawRun(rng: Rng): string {
  return `01${gtin14(rng)} 21${serialNumber(rng)}${rng.chance(0.5) ? ` 17${expiry(rng)}` : ''}`;
}

function ssn(rng: Rng): string {
  let area = 1 + rng.int(898);
  if (area === 666) area = 667;
  return `${pad(area, 3)}-${pad(1 + rng.int(99), 2)}-${pad(1 + rng.int(9999), 4)}`;
}

/** A Medicare Beneficiary Identifier built position by position, hyphenated or not. */
function mbi(rng: Rng, hyphen: boolean): string {
  const letter = (): string => chars(rng, MBI_LETTERS, 1);
  const alnum = (): string => chars(rng, MBI_LETTERS + DIGITS, 1);
  const digit = (): string => chars(rng, DIGITS, 1);
  const first = chars(rng, '123456789', 1);
  const a = `${first}${letter()}${alnum()}${digit()}`;
  const b = `${letter()}${alnum()}${digit()}`;
  const c = `${letter()}${letter()}${digit()}${digit()}`;
  return hyphen ? `${a}-${b}-${c}` : a + b + c;
}

/** An ICD-shaped code. Generated by shape — no code list is used or shipped. */
function icdCode(rng: Rng): string {
  const base = `${chars(rng, UPPER, 1)}${chars(rng, DIGITS, 2)}`;
  switch (rng.int(3)) {
    case 0:
      return base;
    case 1:
      return `${base}.${chars(rng, DIGITS, 1)}`;
    default:
      return `${base}.${chars(rng, DIGITS, 2)}`;
  }
}

/** An ATC-shaped code: an anatomical group letter, two digits, two letters, two digits. */
function atcCode(rng: Rng): string {
  return `${chars(rng, 'ABCDGHJLMNPRSV', 1)}${chars(rng, DIGITS, 2)}${chars(rng, UPPER, 2)}${chars(rng, DIGITS, 2)}`;
}

// ---------------------------------------------------------------------------
// Prose around the identifiers
// ---------------------------------------------------------------------------

// Sentences with no digit, no identifier and none of the ruleset's keywords, so
// the only thing that can fire in them is what a scene put there on purpose.
const TR_FILLER = [
  'Hasta poliklinik kontrolüne geldi.',
  'Şikayetleri belirgin olarak geriledi.',
  'Ek bir yakınması bulunmuyor.',
  'Önerilen tedavi aynen sürdürülsün.',
  'Kontrol için iki hafta sonra başvurması önerildi.',
  'Fizik muayene bulguları doğal.',
  'Reçete düzenlendi, kullanım şekli anlatıldı.',
  'Hasta ve yakını bilgilendirildi.',
  'Laboratuvar sonuçları dosyaya eklendi.',
  'Tedaviye uyumu iyi.',
];

const EN_FILLER = [
  'Patient seen in clinic for a routine follow-up.',
  'Symptoms have improved since the last visit.',
  'No new complaints were reported.',
  'Continue the current treatment plan.',
  'Return to clinic if symptoms worsen.',
  'Physical examination was unremarkable.',
  'Medication reviewed with the patient.',
  'Lab results were added to the chart.',
  'The patient was counselled on adherence.',
  'Claim submitted for review.',
];

const SEPARATORS = [': ', ' ', ' : ', ' - ', ' #', '= '];

function filler(rng: Rng, locale: 'tr' | 'en'): string {
  return rng.pick(locale === 'tr' ? TR_FILLER : EN_FILLER);
}

// ---------------------------------------------------------------------------
// Positives
// ---------------------------------------------------------------------------

const REF_ANCHORS_TR = [
  'Hasta No',
  'Protokol No',
  'Dosya No',
  'Takip No',
  'E-Reçete No',
  'Reçete No',
  'Rapor No',
  'Provizyon No',
  'Poliçe No',
  'Hasta Numarası',
  'Protokol Numarası',
];
const REF_ANCHORS_EN = [
  'MRN',
  'Patient ID',
  'Medical Record Number',
  'Member ID',
  'Policy Number',
  'Claim Number',
  'Chart No',
  'Encounter ID',
];

function refItem(rng: Rng): Pick<PhiItem, 'locale'> & { parts: Part[] } {
  const tr = rng.chance(0.6);
  const locale = tr ? 'tr' : 'en';
  const anchor = rng.pick(tr ? REF_ANCHORS_TR : REF_ANCHORS_EN);
  const sep = rng.pick(SEPARATORS);
  const token = refToken(rng);
  const lead = rng.chance(0.5) ? `${filler(rng, locale)} ` : '';
  const tail = rng.chance(0.5) ? ` ${filler(rng, locale)}` : '';
  const style = rng.int(3);
  if (style === 0) return { locale, parts: [lead, `${anchor}${sep}`, ['health_ref', token], tail] };
  if (style === 1) {
    return { locale, parts: [`${lead}${anchor.toUpperCase()}${sep}`, ['health_ref', token], tail] };
  }
  return {
    locale,
    parts: [
      `${lead}${tr ? 'Hasta' : 'Patient'}\n${anchor}${sep}`,
      ['health_ref', token],
      `\n${tail.trim()}`,
    ],
  };
}

const DATE_CONTEXT_TR = [
  'Doğum tarihi',
  'D.T.',
  'Yatış tarihi',
  'Taburcu tarihi',
  'Ölüm tarihi',
  'Ameliyat tarihi',
  'Yatış',
  'Taburcu',
];
const DATE_CONTEXT_EN = [
  'DOB',
  'Date of birth',
  'Admission date',
  'Discharge date',
  'Date of death',
  'Date of service',
  'Admitted',
  'Discharged',
];

function dateItem(rng: Rng): Pick<PhiItem, 'locale'> & { parts: Part[] } {
  const tr = rng.chance(0.6);
  const locale = tr ? 'tr' : 'en';
  const style = tr
    ? rng.pick<DateStyle>(['dot', 'dot', 'slash-dm', 'iso'])
    : rng.pick<DateStyle>(['slash-md', 'slash-md', 'iso', 'slash-dm']);
  const lead = rng.chance(0.5) ? `${filler(rng, locale)} ` : '';
  const context = rng.pick(tr ? DATE_CONTEXT_TR : DATE_CONTEXT_EN);
  const first = formatDate(ymd(rng, 1925, 2024), style);
  if (rng.chance(0.3)) {
    // Two dates in one line: admission and discharge, each with its own keyword.
    const second = formatDate(ymd(rng, 2020, 2025), style);
    const [a, b] = tr ? ['Yatış', 'Taburcu'] : ['Admission', 'Discharge'];
    return {
      locale,
      parts: [
        `${lead}${a}${rng.pick([': ', ' '])}`,
        ['health_date', first],
        `, ${b}: `,
        ['health_date', second],
        '.',
      ],
    };
  }
  return {
    locale,
    parts: [
      `${lead}${context}${rng.pick([': ', ' ', ' - '])}`,
      ['health_date', first],
      rng.chance(0.5) ? '.' : '',
    ],
  };
}

function gs1Item(rng: Rng): Pick<PhiItem, 'locale'> & { parts: Part[] } {
  const tr = rng.chance(0.65);
  const locale = tr ? 'tr' : 'en';
  const form = rng.int(10);
  const run = form < 5 ? hriRun(rng) : form < 8 ? rawRun(rng) : printedRawRun(rng);
  const scene = rng.int(4);
  if (scene === 0) {
    return {
      locale,
      parts: [
        'Eczane satış satırı: Parol 500 mg 20 tb, karekod ',
        ['gs1_serial', run],
        ', 1 adet.',
      ],
    };
  }
  if (scene === 1) {
    return {
      locale,
      parts: ['İTS bildirimi - ürün karekodu: ', ['gs1_serial', run], '\nDurum: satıldı'],
    };
  }
  if (scene === 2) {
    return {
      locale: 'en',
      parts: ['Dispensed pack scan: ', ['gs1_serial', run], ' -- verified at counter.'],
    };
  }
  // A symbology identifier is not part of the data; the mask starts after it.
  const prefix = form >= 8 ? rng.pick([']d2', ']C1', ']Q3']) : '';
  return { locale, parts: [`${filler(rng, locale)} UDI: ${prefix}`, ['gs1_serial', run], ''] };
}

function ssnItem(rng: Rng): Pick<PhiItem, 'locale'> & { parts: Part[] } {
  const scene = rng.int(4);
  const value = ssn(rng);
  if (scene === 0)
    return {
      locale: 'en',
      parts: ['Claim line: patient SSN ', ['ssn_us', value], ' billed to plan.'],
    };
  if (scene === 1)
    return { locale: 'en', parts: ['Subscriber ', ['ssn_us', value], ` ${filler(rng, 'en')}`] };
  if (scene === 2) {
    return {
      locale: 'en',
      parts: ['Social Security Number: ', ['ssn_us', value.replaceAll('-', '')], '\nVerified: yes'],
    };
  }
  return {
    locale: 'en',
    parts: ['SSN ', ['ssn_us', value.replaceAll('-', '')], ` ${filler(rng, 'en')}`],
  };
}

function mbiItem(rng: Rng): Pick<PhiItem, 'locale'> & { parts: Part[] } {
  const value = mbi(rng, rng.chance(0.5));
  const scene = rng.int(3);
  if (scene === 0)
    return { locale: 'en', parts: ['Medicare ID ', ['mbi_us', value], ' eligible.'] };
  if (scene === 1)
    return {
      locale: 'en',
      parts: ['Claim 837P, MBI: ', ['mbi_us', value], `\n${filler(rng, 'en')}`],
    };
  return { locale: 'en', parts: [`${filler(rng, 'en')} Beneficiary `, ['mbi_us', value], ''] };
}

const ICD_CONTEXT_TR = ['Tanı', 'Teşhis', 'Ön tanı', 'Ek tanı', 'ICD-10'];
const ICD_CONTEXT_EN = ['Diagnosis', 'Dx', 'Primary diagnosis', 'ICD-10'];

function icdItem(rng: Rng): Pick<PhiItem, 'locale'> & { parts: Part[] } {
  const tr = rng.chance(0.6);
  const locale = tr ? 'tr' : 'en';
  const context = rng.pick(tr ? ICD_CONTEXT_TR : ICD_CONTEXT_EN);
  const lead = rng.chance(0.5) ? `${filler(rng, locale)} ` : '';
  if (rng.chance(0.35)) {
    const parts: Part[] = [`${lead}${tr ? 'Tanılar' : 'Diagnoses'}: `];
    const count = 2 + rng.int(2);
    for (let i = 0; i < count; i++) {
      if (i > 0) parts.push(', ');
      parts.push(['icd10', icdCode(rng)]);
    }
    return { locale, parts };
  }
  return {
    locale,
    parts: [
      `${lead}${context}${rng.pick([': ', ' ', ' - '])}`,
      ['icd10', icdCode(rng)],
      rng.chance(0.5) ? '.' : '',
    ],
  };
}

function atcItem(rng: Rng): Pick<PhiItem, 'locale'> & { parts: Part[] } {
  const tr = rng.chance(0.5);
  const code = atcCode(rng);
  if (tr) {
    return rng.chance(0.5)
      ? { locale: 'tr', parts: ['Etken madde sınıfı: ', ['atc', code], '\nTedaviye başlandı.'] }
      : { locale: 'tr', parts: ['İlaç ', ['atc', code], ' önerildi. ', filler(rng, 'tr')] };
  }
  return rng.chance(0.5)
    ? { locale: 'en', parts: ['Therapeutic class ', ['atc', code], ' started.'] }
    : { locale: 'en', parts: [`${filler(rng, 'en')} ATC: `, ['atc', code], ''] };
}

/** A discharge summary with several identifiers of different kinds in it. */
function mixedItem(rng: Rng): Pick<PhiItem, 'locale'> & { parts: Part[] } {
  const tr = rng.chance(0.7);
  if (tr) {
    return {
      locale: 'tr',
      parts: [
        'EPİKRİZ\nProtokol No: ',
        ['health_ref', refToken(rng)],
        '\nDoğum tarihi: ',
        ['health_date', formatDate(ymd(rng, 1930, 2015), 'dot')],
        '\nYatış: ',
        ['health_date', formatDate(ymd(rng, 2022, 2025), 'dot')],
        ', Taburcu: ',
        ['health_date', formatDate(ymd(rng, 2022, 2025), 'dot')],
        '\nTanı: ',
        ['icd10', icdCode(rng)],
        ', ',
        ['icd10', icdCode(rng)],
        '\nTedavi: ',
        ['atc', atcCode(rng)],
        `\n${filler(rng, 'tr')}`,
      ],
    };
  }
  return {
    locale: 'en',
    parts: [
      'DISCHARGE SUMMARY\nMRN: ',
      ['health_ref', refToken(rng)],
      '\nDOB: ',
      ['health_date', formatDate(ymd(rng, 1930, 2015), 'slash-md')],
      '\nSSN ',
      ['ssn_us', ssn(rng)],
      '\nMedicare ',
      ['mbi_us', mbi(rng, true)],
      '\nDiagnosis: ',
      ['icd10', icdCode(rng)],
      `\n${filler(rng, 'en')}`,
    ],
  };
}

/**
 * Real clinical content that happens to have a word the exclusion lists carry
 * beside it: a prescription renewal, a home delivery, a patient portal on
 * Kubernetes. The anchor is a plainly clinical one, which is what the recogniser
 * must not be argued out of. One entry per exclusion word, TR and EN, and a test
 * holds the table to the lists so a word added to one is measured.
 */
interface ExclusionCase {
  readonly kind: 'ref' | 'date';
  readonly locale: 'tr' | 'en';
  /** Sentence with the exclusion word in it. */
  readonly lead: string;
  /** The clinical anchor or date keyword that follows it. */
  readonly anchor: string;
}

const EXCLUSION_CASES: readonly ExclusionCase[] = [
  {
    kind: 'ref',
    locale: 'tr',
    lead: 'Eczaneden ilacınız kargo ile gönderildi.',
    anchor: 'Reçete no',
  },
  { kind: 'ref', locale: 'tr', lead: 'İlaç kurye ile eve teslim edildi.', anchor: 'Hasta no' },
  { kind: 'ref', locale: 'tr', lead: 'Reçeteli ilaç gönderi olarak çıktı.', anchor: 'Protokol no' },
  { kind: 'ref', locale: 'tr', lead: 'Ortez sipariş edildi.', anchor: 'Hasta no' },
  { kind: 'ref', locale: 'tr', lead: 'Poliklinik faaliyet raporu hazırlandı.', anchor: 'Hasta no' },
  {
    kind: 'ref',
    locale: 'tr',
    lead: 'Hastanın tedavisi kasko kapsamında değerlendirildi.',
    anchor: 'Protokol no',
  },
  {
    kind: 'ref',
    locale: 'tr',
    lead: 'Kaza sonrası trafik sigortası işlemleri yürütüldü.',
    anchor: 'Protokol no',
  },
  {
    kind: 'ref',
    locale: 'tr',
    lead: 'Konut sigortası belgesi dosyaya eklendi.',
    anchor: 'Hasta no',
  },
  { kind: 'ref', locale: 'tr', lead: 'DASK belgesi istenmedi.', anchor: 'Hasta no' },
  { kind: 'ref', locale: 'tr', lead: 'Hasta özel araç ile geldi.', anchor: 'Hasta no' },
  { kind: 'ref', locale: 'tr', lead: 'Reçete yenileme talebi.', anchor: 'Reçete no' },
  { kind: 'ref', locale: 'en', lead: 'The pharmacy sent the refill by courier.', anchor: 'MRN' },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Home shipping of the insulin pens was arranged.',
    anchor: 'Patient ID',
  },
  { kind: 'ref', locale: 'en', lead: 'Specimen shipment to lab.', anchor: 'Patient ID' },
  { kind: 'ref', locale: 'en', lead: 'Symptom tracking app notes attached.', anchor: 'MRN' },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'A parcel with the glucose meter arrived.',
    anchor: 'Patient Number',
  },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Oxygen concentrator freight was delayed.',
    anchor: 'Patient No',
  },
  { kind: 'ref', locale: 'en', lead: 'Patient arrived by private vehicle.', anchor: 'MRN' },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Car insurance paperwork was not needed.',
    anchor: 'Patient ID',
  },
  { kind: 'ref', locale: 'en', lead: 'Auto insurance is unrelated to the visit.', anchor: 'MRN' },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Home insurance was mentioned in the social history.',
    anchor: 'Medical Record Number',
  },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'The annual report of the clinic was reviewed.',
    anchor: 'MRN',
  },
  { kind: 'ref', locale: 'en', lead: 'The refill renews monthly.', anchor: 'Patient ID' },
  { kind: 'ref', locale: 'en', lead: 'Refill renewal request received.', anchor: 'MRN' },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'DME wheelchair shipment to the beneficiary.',
    anchor: 'Claim number',
  },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Ambulance vehicle transport was billed.',
    anchor: 'Claim no',
  },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Home infusion supplies, tracking pending.',
    anchor: 'Claim #',
  },
  { kind: 'ref', locale: 'en', lead: 'Supplies went out by courier.', anchor: 'Claim ID' },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Ambulance vehicle transport, HCPCS A0428.',
    anchor: 'Medicare claim no',
  },
  { kind: 'ref', locale: 'en', lead: 'Shipping address on file.', anchor: 'Member ID' },
  { kind: 'ref', locale: 'en', lead: 'Mail-order parcel was sent.', anchor: 'Member Number' },
  { kind: 'ref', locale: 'en', lead: 'Mail-order pharmacy shipment.', anchor: 'Subscriber ID' },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Courier delivered the supplies.',
    anchor: 'Subscriber Number',
  },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Car insurance is unrelated to the visit.',
    anchor: 'Policy Holder ID',
  },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Annual report of the plan was filed.',
    anchor: 'Policyholder ID',
  },
  { kind: 'ref', locale: 'en', lead: 'Renewal due.', anchor: 'Insurance ID' },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Insurance number was confirmed; freight arrived.',
    anchor: 'Insurance number',
  },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Home insurance was mentioned in the history.',
    anchor: 'Health Plan ID',
  },
  {
    kind: 'ref',
    locale: 'en',
    lead: 'Freight of oxygen supplies was delayed.',
    anchor: 'Beneficiary ID',
  },
  { kind: 'ref', locale: 'en', lead: 'The annual report was reviewed.', anchor: 'Medicare ID' },
  { kind: 'ref', locale: 'en', lead: 'Refill by courier.', anchor: 'Prescription number' },
  { kind: 'ref', locale: 'tr', lead: 'Kargo ile gelen ilaç.', anchor: 'Medula takip no' },
  { kind: 'ref', locale: 'tr', lead: 'Kurye ile epikriz teslimi yapıldı.', anchor: 'Epikriz no' },
  { kind: 'ref', locale: 'tr', lead: 'Sipariş edilen cihaz için.', anchor: 'Provizyon no' },
  {
    kind: 'date',
    locale: 'tr',
    lead: 'Hasta portalı kubernetes üzerinde çalışıyor.',
    anchor: 'Doğum tarihi',
  },
  { kind: 'date', locale: 'tr', lead: 'Portal k8s ortamında çalışıyor.', anchor: 'Doğum tarihi' },
  { kind: 'date', locale: 'tr', lead: 'Webhook ile gelen kayıt:', anchor: 'Doğum tarihi' },
  {
    kind: 'date',
    locale: 'tr',
    lead: 'Admission controller yeni kaydı onayladı.',
    anchor: 'Doğum tarihi',
  },
  {
    kind: 'date',
    locale: 'tr',
    lead: 'Kalp pili batarya değişimi planlandı.',
    anchor: 'Ameliyat tarihi',
  },
  {
    kind: 'date',
    locale: 'tr',
    lead: 'Tekerlekli sandalye akü bakımı yapıldı.',
    anchor: 'Taburcu tarihi',
  },
  { kind: 'date', locale: 'en', lead: 'Pacemaker voltage was checked.', anchor: 'Date of birth' },
  { kind: 'date', locale: 'en', lead: 'Pacemaker battery was replaced.', anchor: 'Surgery date' },
  { kind: 'date', locale: 'en', lead: 'Dx: cluster headache.', anchor: 'Admission date' },
];

/**
 * The same content where the anchor is an ambiguous one (`takip no`, `dosya no`,
 * a bare `admission`): the exclusion word wins and the number or date is not
 * masked. That is the recall the exclusion lists cost, and these items put a
 * number on it. They are positives, outside the recall gate by design (a gate
 * here would only measure that the lists work as written) and reported next to
 * it.
 */
const AMBIGUOUS_CASES: readonly ExclusionCase[] = [
  { kind: 'ref', locale: 'tr', lead: 'Cihaz kargo ile geldi.', anchor: 'Takip no' },
  { kind: 'ref', locale: 'tr', lead: 'Poliklinik faaliyet raporu hazırlandı.', anchor: 'Rapor no' },
  {
    kind: 'ref',
    locale: 'tr',
    lead: 'Hasta yaralı, trafik sigortası işlemleri yürütüldü.',
    anchor: 'Dosya no',
  },
  { kind: 'ref', locale: 'tr', lead: 'İlaç kurye ile eve gitti.', anchor: 'Takip numarası' },
  { kind: 'ref', locale: 'en', lead: 'Wheelchair shipment arrived.', anchor: 'Policy number' },
  { kind: 'ref', locale: 'en', lead: 'Specimen courier was called.', anchor: 'Chart no' },
  { kind: 'ref', locale: 'en', lead: 'Ambulance vehicle was dispatched.', anchor: 'Encounter ID' },
  { kind: 'ref', locale: 'en', lead: 'Plan renewal is due.', anchor: 'Policy no' },
  { kind: 'date', locale: 'tr', lead: 'Hasta portalı kubernetes ortamında.', anchor: 'Yatış' },
  { kind: 'date', locale: 'tr', lead: 'Kalp pili batarya değişimi planlandı.', anchor: 'Taburcu' },
  { kind: 'date', locale: 'en', lead: 'Dx: cluster headache.', anchor: 'Admission' },
  { kind: 'date', locale: 'en', lead: 'Pacemaker battery was replaced.', anchor: 'Discharged' },
];

function exclusionItem(rng: Rng, index: number): Pick<PhiItem, 'locale'> & { parts: Part[] } {
  return caseItem(rng, EXCLUSION_CASES[index % EXCLUSION_CASES.length]);
}

function ambiguousItem(rng: Rng, index: number): Pick<PhiItem, 'locale'> & { parts: Part[] } {
  return caseItem(rng, AMBIGUOUS_CASES[index % AMBIGUOUS_CASES.length]);
}

function caseItem(
  rng: Rng,
  entry: ExclusionCase | undefined,
): Pick<PhiItem, 'locale'> & { parts: Part[] } {
  if (entry === undefined) throw new Error('empty exclusion table');
  const tr = entry.locale === 'tr';
  if (entry.kind === 'ref') {
    return {
      locale: entry.locale,
      parts: [
        `${entry.lead} ${entry.anchor}${rng.pick([': ', ' '])}`,
        ['health_ref', refToken(rng)],
      ],
    };
  }
  const style = tr ? 'dot' : rng.pick<DateStyle>(['iso', 'slash-md']);
  return {
    locale: entry.locale,
    parts: [
      `${entry.lead} ${entry.anchor}: `,
      ['health_date', formatDate(ymd(rng, 1930, 2024), style)],
    ],
  };
}

const POSITIVE_BUILDERS: Record<string, (rng: Rng) => Pick<PhiItem, 'locale'> & { parts: Part[] }> =
  {
    health_ref: refItem,
    health_date: dateItem,
    gs1_serial: gs1Item,
    ssn_us: ssnItem,
    mbi_us: mbiItem,
    icd10: icdItem,
    atc: atcItem,
    mixed: mixedItem,
  };

function makePositive(
  family: string,
  index: number,
  build: (rng: Rng, index: number) => Pick<PhiItem, 'locale'> & { parts: Part[] },
): PhiItem {
  const rng = new Rng(`${SEED}:${family}:${index}`);
  const { locale, parts } = build(rng, index);
  const { text, spans } = compose(parts);
  return {
    id: id(family, index),
    family,
    label: 'positive',
    locale,
    text,
    spans,
    trapFor: [],
    gated: true,
  };
}

function id(family: string, index: number): string {
  return `${family}.${String(index).padStart(4, '0')}`;
}

// ---------------------------------------------------------------------------
// Negatives — traps
// ---------------------------------------------------------------------------

interface Trap {
  readonly locale: 'tr' | 'en';
  readonly text: string;
  readonly trapFor: readonly PhiKind[];
  readonly gated?: boolean;
  readonly accepted?: string;
}

function digitsRun(rng: Rng, n: number): string {
  return chars(rng, DIGITS, n);
}

const NEGATIVE_BUILDERS: Record<(typeof NEGATIVE_FAMILIES)[number], (rng: Rng) => Trap> = {
  // Business numbers that look like references and carry no anchor of ours.
  'order-and-invoice-numbers'(rng) {
    const n = rng.int(5);
    if (n === 0)
      return {
        locale: 'tr',
        text: `Sipariş No: ${digitsRun(rng, 8)} onaylandı, kargoya verilecek.`,
        trapFor: ['health_ref', 'ssn_us'],
      };
    if (n === 1)
      return {
        locale: 'tr',
        text: `Fatura No: INV-${2020 + rng.int(6)}-${digitsRun(rng, 6)}, vade 30 gün.`,
        trapFor: ['health_ref'],
      };
    if (n === 2)
      return {
        locale: 'en',
        text: `Order #${digitsRun(rng, 9)} shipped. Invoice ${chars(rng, UPPER, 3)}-${digitsRun(rng, 7)} is attached.`,
        trapFor: ['health_ref', 'ssn_us'],
      };
    if (n === 3)
      return {
        locale: 'en',
        text: `Ticket ${chars(rng, UPPER, 2)}-${digitsRun(rng, 5)} was closed by the support team.`,
        trapFor: ['health_ref'],
      };
    return {
      locale: 'tr',
      text: `Cari hesap kodu ${chars(rng, UPPER, 2)}${digitsRun(rng, 7)}, sözleşme ${digitsRun(rng, 6)}.`,
      trapFor: ['health_ref'],
    };
  },
  // A retail barcode names a product, not a pack: no serial, so no match.
  'retail-barcodes'(rng) {
    const n = rng.int(4);
    if (n === 0)
      return {
        locale: 'tr',
        text: `Barkod: ${ean13(rng)} - Ürün stokta.`,
        trapFor: ['gs1_serial'],
      };
    if (n === 1)
      return {
        locale: 'en',
        text: `Scanned EAN ${ean13(rng)} at checkout; price 12.90.`,
        trapFor: ['gs1_serial'],
      };
    if (n === 2)
      return {
        locale: 'tr',
        text: `Koli etiketi (01)${gtin14(rng)} adet 24`,
        trapFor: ['gs1_serial'],
      };
    return {
      locale: 'en',
      text: `Case label 01${gtin14(rng)} packed 12 units.`,
      trapFor: ['gs1_serial'],
    };
  },
  'log-timestamps'(rng) {
    const d = ymd(rng, 2022, 2026);
    const n = rng.int(3);
    if (n === 0)
      return {
        locale: 'en',
        text: `${formatDate(d, 'iso')} 10:${pad(rng.int(60), 2)}:${pad(rng.int(60), 2)} INFO worker started pid=${digitsRun(rng, 5)}`,
        trapFor: ['health_date', 'health_ref'],
      };
    if (n === 1)
      return {
        locale: 'tr',
        text: `${formatDate(d, 'dot')} ${pad(rng.int(24), 2)}:${pad(rng.int(60), 2)} yedekleme tamamlandı`,
        trapFor: ['health_date'],
      };
    return {
      locale: 'en',
      text: `[${formatDate(d, 'iso')}T08:${pad(rng.int(60), 2)}:00Z] GET /api/v1/items 200 ${digitsRun(rng, 3)}ms`,
      trapFor: ['health_date'],
    };
  },
  'version-strings'(rng) {
    const n = rng.int(3);
    if (n === 0)
      return {
        locale: 'en',
        text: `Release ${1 + rng.int(9)}.${1 + rng.int(12)}.${2020 + rng.int(6)} is now available.`,
        trapFor: ['health_date'],
      };
    if (n === 1)
      return {
        locale: 'en',
        text: `node v${18 + rng.int(8)}.${rng.int(20)}.${rng.int(10)}, npm ${8 + rng.int(4)}.${rng.int(10)}.${rng.int(10)}`,
        trapFor: ['health_date', 'ssn_us'],
      };
    return {
      locale: 'tr',
      text: `Sürüm ${1 + rng.int(4)}.${rng.int(30)}.${rng.int(100)} yayınlandı; değişiklik listesine bakın.`,
      trapFor: ['health_date'],
    };
  },
  // `E10` and `B12` are product codes, vitamins and room numbers before they are diagnoses.
  'product-codes'(rng) {
    const code = icdCode(rng);
    const n = rng.int(4);
    if (n === 0)
      return { locale: 'tr', text: `Ürün kodu ${code} stokta mevcut.`, trapFor: ['icd10'] };
    if (n === 1)
      return {
        locale: 'tr',
        text: `Vitamin B12 ve D3 takviyesi alışveriş listesinde.`,
        trapFor: ['icd10'],
      };
    if (n === 2)
      return {
        locale: 'en',
        text: `Cable type ${chars(rng, UPPER, 1)}${digitsRun(rng, 2)} fits room ${chars(rng, UPPER, 1)}${digitsRun(rng, 2)}.`,
        trapFor: ['icd10'],
      };
    return {
      locale: 'en',
      text: `Part ${code}-${digitsRun(rng, 4)} ships in two weeks.`,
      trapFor: ['icd10', 'health_ref'],
    };
  },
  // The words are there, the number is not.
  'anchor-without-number'(rng) {
    const n = rng.int(6);
    if (n === 0)
      return {
        locale: 'tr',
        text: 'Protokol numaranızı getirmeyi unutmayın.',
        trapFor: ['health_ref'],
      };
    if (n === 1)
      return { locale: 'tr', text: 'Hasta no alanı boş bırakılamaz.', trapFor: ['health_ref'] };
    if (n === 2)
      return {
        locale: 'en',
        text: 'MRN is required before the visit can be booked.',
        trapFor: ['health_ref'],
      };
    if (n === 3)
      return {
        locale: 'tr',
        text: `Reçete no: yok, ${filler(rng, 'tr')}`,
        trapFor: ['health_ref'],
      };
    if (n === 4)
      return {
        locale: 'en',
        text: 'Please bring your Medical Record Number and your insurance card.',
        trapFor: ['health_ref'],
      };
    return {
      locale: 'tr',
      text: `Dosya no 3. sırada değil; ${filler(rng, 'tr')}`,
      trapFor: ['health_ref'],
    };
  },
  'dates-without-context'(rng) {
    const style = rng.pick<DateStyle>(['dot', 'slash-dm', 'iso', 'slash-md']);
    const date = formatDate(ymd(rng, 2020, 2026), style);
    const n = rng.int(4);
    if (n === 0)
      return {
        locale: 'tr',
        text: `Toplantı ${date} tarihinde yapılacak, gündem ekte.`,
        trapFor: ['health_date'],
      };
    if (n === 1)
      return {
        locale: 'en',
        text: `The invoice is due on ${date}; late fees apply after that.`,
        trapFor: ['health_date'],
      };
    if (n === 2)
      return {
        locale: 'tr',
        text: `Teslimat ${date} günü, kargo firması arayacak.`,
        trapFor: ['health_date'],
      };
    return {
      locale: 'en',
      text: `Quarterly review scheduled ${date}. Agenda to follow.`,
      trapFor: ['health_date'],
    };
  },
  // Digit runs and dashed groups that are not an SSN: unissued ranges, or no keyword.
  'bare-digit-runs'(rng) {
    const n = rng.int(6);
    if (n === 0)
      return {
        locale: 'en',
        text: `Reference ${digitsRun(rng, 9)} was logged by the batch job.`,
        trapFor: ['ssn_us'],
      };
    if (n === 1)
      return {
        locale: 'en',
        text: `Record 000-${pad(1 + rng.int(99), 2)}-${pad(1 + rng.int(9999), 4)} is a test fixture.`,
        trapFor: ['ssn_us'],
      };
    if (n === 2)
      return {
        locale: 'en',
        text: `Code 666-${pad(1 + rng.int(99), 2)}-${pad(1 + rng.int(9999), 4)} is reserved.`,
        trapFor: ['ssn_us'],
      };
    if (n === 3)
      return {
        locale: 'en',
        text: `Range ${900 + rng.int(100)}-${pad(1 + rng.int(99), 2)}-${pad(1 + rng.int(9999), 4)} is not issued.`,
        trapFor: ['ssn_us'],
      };
    if (n === 4)
      return {
        locale: 'en',
        text: `Item ${pad(1 + rng.int(665), 3)}-00-${pad(1 + rng.int(9999), 4)} has no group.`,
        trapFor: ['ssn_us'],
      };
    return {
      locale: 'tr',
      text: `Makbuz ${digitsRun(rng, 9)} numarasıyla kaydedildi.`,
      trapFor: ['ssn_us'],
    };
  },
  // Right length, wrong positions: a letter the grammar excludes, a digit where a letter goes.
  'mbi-near-misses'(rng) {
    const good = mbi(rng, false);
    const n = rng.int(5);
    if (n === 0)
      return {
        locale: 'en',
        text: `Token ${good.slice(0, 10)} was rejected.`,
        trapFor: ['mbi_us'],
      };
    if (n === 1)
      return {
        locale: 'en',
        text: `Token ${good}${digitsRun(rng, 1)} was rejected.`,
        trapFor: ['mbi_us'],
      };
    if (n === 2) {
      const bad = `${good.slice(0, 1)}B${good.slice(2)}`;
      return { locale: 'en', text: `Session ${bad} expired.`, trapFor: ['mbi_us'] };
    }
    if (n === 3) {
      const bad = `${good.slice(0, 3)}Z${good.slice(4)}`;
      return { locale: 'en', text: `Build id ${bad} is stale.`, trapFor: ['mbi_us'] };
    }
    return {
      locale: 'en',
      text: `commit ${chars(rng, '0123456789abcdef', 11)} merged`,
      trapFor: ['mbi_us'],
    };
  },
  // A code with no diagnosis keyword beside it, and a keyword with no code.
  'icd-without-context'(rng) {
    const code = icdCode(rng);
    const n = rng.int(4);
    if (n === 0)
      return {
        locale: 'en',
        text: `Gate ${code} closes at ${pad(rng.int(24), 2)}:30.`,
        trapFor: ['icd10'],
      };
    if (n === 1)
      return { locale: 'tr', text: 'Tanı koyulamadı, ek tetkik planlandı.', trapFor: ['icd10'] };
    if (n === 2)
      return { locale: 'en', text: `Seat ${code} is by the window.`, trapFor: ['icd10'] };
    return {
      locale: 'tr',
      text: `Teşhis konulmadan önce ${filler(rng, 'tr').toLowerCase()}`,
      trapFor: ['icd10'],
    };
  },
  // A GTIN without its serial, a chain with no `(21)`, or a check digit that does not hold.
  'gs1-incomplete'(rng) {
    const n = rng.int(5);
    if (n === 0)
      return {
        locale: 'tr',
        text: `Karekod (01)${gtin14(rng)}(17)${expiry(rng)}(10)${lot(rng)}`,
        trapFor: ['gs1_serial'],
      };
    if (n === 1)
      return {
        locale: 'tr',
        text: `Ürün (01)${brokenGtin14(rng)}(21)${serialNumber(rng)}`,
        trapFor: ['gs1_serial'],
      };
    if (n === 2)
      return {
        locale: 'en',
        text: `Packed 01${brokenGtin14(rng)}21${serialNumber(rng)} in bin 4.`,
        trapFor: ['gs1_serial'],
      };
    if (n === 3)
      return {
        locale: 'en',
        text: `GTIN (01)${gtin14(rng)} lists the product only.`,
        trapFor: ['gs1_serial'],
      };
    return {
      locale: 'en',
      text: `Lot (10)${lot(rng)} expires (17)${expiry(rng)}.`,
      trapFor: ['gs1_serial'],
    };
  },
  'atc-lookalikes'(rng) {
    const n = rng.int(4);
    if (n === 0)
      return {
        locale: 'en',
        text: `Model ${chars(rng, 'EFIKOQTUWXYZ', 1)}${digitsRun(rng, 2)}${chars(rng, UPPER, 2)}${digitsRun(rng, 2)} is discontinued.`,
        trapFor: ['atc'],
      };
    if (n === 1)
      return {
        locale: 'en',
        text: `Drive ${chars(rng, 'abcdgh', 1)}${digitsRun(rng, 2)}${chars(rng, 'abcdefgh', 2)}${digitsRun(rng, 2)} mounted at boot.`,
        trapFor: ['atc'],
      };
    if (n === 2)
      return {
        locale: 'tr',
        text: `Parça ${chars(rng, 'ABCDGHJLMNPRSV', 1)}${digitsRun(rng, 2)}${chars(rng, UPPER, 2)}${digitsRun(rng, 1)} depoda.`,
        trapFor: ['atc'],
      };
    return {
      locale: 'tr',
      text: `Kod ${chars(rng, 'ABCDGHJLMNPRSV', 1)}${digitsRun(rng, 3)}${chars(rng, UPPER, 2)}${digitsRun(rng, 2)} geçersiz.`,
      trapFor: ['atc'],
    };
  },
  // Clinical writing with nothing identifying in it.
  'clinical-prose'(rng) {
    const tr = rng.chance(0.5);
    const locale = tr ? 'tr' : 'en';
    return {
      locale,
      text: `${filler(rng, locale)} ${filler(rng, locale)} ${filler(rng, locale)}`,
      trapFor: [],
    };
  },
  // Ruleset keywords used in a non-clinical sense, each with a word the exclusion
  // lists carry. Gated: a recogniser that fires on a courier's tracking number has
  // a false positive, whatever the keyword it fired on.
  'keyword-collisions'(rng) {
    const n = rng.int(6);
    if (n === 0)
      return {
        locale: 'tr',
        text: `Kargo takip no: ${digitsRun(rng, 12)}, tahmini teslim yarın.`,
        trapFor: ['health_ref'],
      };
    if (n === 1)
      return {
        locale: 'en',
        text: `Insurance policy number ${chars(rng, UPPER, 2)}${digitsRun(rng, 7)} renews yearly.`,
        trapFor: ['health_ref'],
      };
    if (n === 2)
      return {
        locale: 'en',
        text: `Kubernetes admission webhook rotated its certificate on ${formatDate(ymd(rng, 2023, 2026), 'iso')}.`,
        trapFor: ['health_date'],
      };
    if (n === 3)
      return {
        locale: 'tr',
        text: `Rapor no: ${digitsRun(rng, 7)} (yıllık faaliyet raporu).`,
        trapFor: ['health_ref'],
      };
    if (n === 4)
      return {
        locale: 'en',
        text: `Battery discharge test ran on ${formatDate(ymd(rng, 2023, 2026), 'slash-md')}.`,
        trapFor: ['health_date'],
      };
    // ACCEPTED FALSE POSITIVE. `claim` is a plainly clinical anchor (a health claim
    // number must not be argued out of masking by a `shipment` or `courier` beside
    // it), so this item is masked. It stays here, still a negative and still counted
    // as a false positive: the decision is the user's (2026-11-16) and the
    // measurement keeps showing what it costs.
    return {
      locale: 'en',
      text: `The claim number ${digitsRun(rng, 9)} was filed with the courier.`,
      trapFor: ['health_ref'],
      accepted: 'claim is a plainly clinical anchor and overrides the exclusion word',
    };
  },
  // The same kind of collision, written after the exclusion lists were, with
  // wording the lists do not carry. This is the family that says whether the lists
  // generalise or memorise the one above. Reported, never gated, and never used to
  // tune the lists: a miss here is a number to read, not a bug to patch.
  'keyword-collisions-holdout'(rng) {
    const year = 2019 + rng.int(7);
    const n = rng.int(12);
    const base = { trapFor: ['health_ref' as const], gated: false };
    const dateTrap = { trapFor: ['health_date' as const], gated: false };
    if (n === 0)
      return {
        ...base,
        locale: 'tr',
        text: `Takip no: ${digitsRun(rng, 12)} (PTT gönderisi), tahmini teslim cuma.`,
      };
    if (n === 1)
      return {
        ...base,
        locale: 'en',
        text: `Policy number ${chars(rng, UPPER, 2)}${digitsRun(rng, 7)} covers the office fire damage; the broker sent the schedule.`,
      };
    if (n === 2)
      return {
        ...base,
        locale: 'en',
        text: `Claim number ${digitsRun(rng, 9)} was opened for the warehouse flood.`,
      };
    if (n === 3)
      return {
        ...base,
        locale: 'tr',
        text: `Rapor no: ${digitsRun(rng, 7)} (denetim raporu, bağımsız denetçi).`,
      };
    if (n === 4)
      return {
        ...base,
        locale: 'tr',
        text: `Reçete no: ${digitsRun(rng, 5)} (kek tarifi, mutfak defteri).`,
      };
    if (n === 5)
      return {
        ...base,
        locale: 'tr',
        text: `Belediye meclisi toplantısı, protokol no: ${year}-${digitsRun(rng, 4)}.`,
      };
    if (n === 6)
      return {
        ...base,
        locale: 'tr',
        text: `İcra dairesi dosya no: ${year}/${digitsRun(rng, 6)} (borç takibi).`,
      };
    if (n === 7)
      return {
        ...base,
        locale: 'en',
        text: `Goods receipt MRN: ${digitsRun(rng, 10)} posted to the ledger.`,
      };
    if (n === 8)
      return {
        ...dateTrap,
        locale: 'en',
        text: `Admission to the programme closes on ${formatDate(ymd(rng, 2024, 2027), 'iso')}.`,
      };
    if (n === 9)
      return {
        ...dateTrap,
        locale: 'en',
        text: `The discharge of the debt was registered on ${formatDate(ymd(rng, 2022, 2026), 'slash-md')}.`,
      };
    if (n === 10)
      return {
        ...dateTrap,
        locale: 'tr',
        text: `Hesaba yatış ${formatDate(ymd(rng, 2022, 2026), 'dot')} tarihinde yapıldı.`,
      };
    return {
      ...dateTrap,
      locale: 'en',
      text: `The startup was born ${formatDate(ymd(rng, 2015, 2024), 'iso')} in a garage.`,
    };
  },
};

function makeNegative(family: (typeof NEGATIVE_FAMILIES)[number], index: number): PhiItem {
  const rng = new Rng(`${SEED}:${family}:${index}`);
  const trap = NEGATIVE_BUILDERS[family](rng);
  return {
    id: id(family, index),
    family,
    label: 'negative',
    locale: trap.locale,
    text: trap.text,
    spans: [],
    trapFor: trap.trapFor,
    gated: trap.gated ?? true,
    ...(trap.accepted === undefined ? {} : { accepted: trap.accepted }),
  };
}

/** Builds the whole corpus, deterministically. */
export function generateCorpus(): PhiItem[] {
  const items: PhiItem[] = [];
  for (const [family, build] of Object.entries(POSITIVE_BUILDERS)) {
    const count = family === 'mixed' ? PER_MIXED : PER_POSITIVE;
    for (let i = 0; i < count; i++) items.push(makePositive(family, i, build));
  }
  // Appended after the others so the items before it are the ones they always were.
  for (let i = 0; i < EXCLUSION_CASES.length * PER_EXCLUSION_CASE; i++) {
    items.push(makePositive('exclusion-mixed', i, exclusionItem));
  }
  for (let i = 0; i < AMBIGUOUS_CASES.length * PER_EXCLUSION_CASE; i++) {
    items.push({ ...makePositive('ambiguous-anchor-mixed', i, ambiguousItem), gated: false });
  }
  for (const family of NEGATIVE_FAMILIES) {
    const count =
      family === 'keyword-collisions'
        ? PER_COLLISION
        : family === 'keyword-collisions-holdout'
          ? PER_HOLDOUT
          : PER_NEGATIVE;
    for (let i = 0; i < count; i++) items.push(makeNegative(family, i));
  }
  return items;
}

/** One JSON object per line, in corpus order. */
export function toJsonl(items: readonly PhiItem[]): string {
  return `${items.map((item) => JSON.stringify(item)).join('\n')}\n`;
}

/** The exclusion table, for the test that holds it to the ruleset's lists. */
export function exclusionLeads(): string[] {
  return EXCLUSION_CASES.map((c) => c.lead);
}
