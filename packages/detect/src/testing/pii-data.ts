/**
 * A small PII keyword section for the tests, so the recogniser tests do not
 * depend on the words the shipped ruleset happens to carry. The shipped data is
 * exercised where it is shipped: the CLI and the bench load the real one.
 */
import { type CompiledPiiData, compilePiiData, type PiiData } from '../pii/context.js';

export const PII_FIXTURE: PiiData = {
  profiles: { health: ['health_ref', 'health_date', 'gs1_serial', 'ssn_us', 'mbi_us'] },
  anchors: {
    health_ref: [
      'hasta no',
      'protokol no',
      'e-reçete no',
      'mrn',
      'medical record number',
      'takip no',
      'rapor no',
      'claim number',
      'claim #',
      'member id',
      'medicare id',
    ],
  },
  context: {
    health_date: [
      'doğum tarihi',
      'd.t.',
      'yatış',
      'taburcu',
      'dob',
      'date of birth',
      'discharge',
      'admission',
      'admission date',
    ],
    ssn_us: ['ssn', 'social security'],
    icd10: ['tanı', 'tanılar', 'teşhis', 'icd', 'diagnosis', 'dx'],
    gs1_serial: ['karekod', 'seri', 'lot', 'udi', 'gtin'],
  },
  exclude: {
    health_ref: ['kargo', 'courier', 'faaliyet raporu'],
    health_date: ['webhook', 'battery'],
  },
  strong: {
    health_ref: ['hasta', 'reçete', 'protokol', 'mrn', 'claim', 'member', 'medicare'],
    health_date: ['doğum tarihi', 'dob', 'date of birth', 'admission date'],
  },
  profileContext: { tckn: ['hasta', 'sigortalı', 'yabancı kimlik'], phone: ['faks', 'fax'] },
};

export function fixtureData(overrides: Partial<PiiData> = {}): CompiledPiiData {
  return compilePiiData({ ...PII_FIXTURE, ...overrides });
}
