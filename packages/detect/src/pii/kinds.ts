/**
 * The PII kinds, in the three classes ADR-012 gives them.
 *
 * The class decides what switches a recogniser on, not how it recognises:
 *
 * - **base** kinds run for every deployment, and are exactly the set that
 *   shipped before profiles existed;
 * - **health** kinds run when `pii.profile` is `health`;
 * - **attribute** kinds reveal a clinical fact rather than identify a person,
 *   so no profile switches them on — a deployment names them in
 *   `pii.recognizers` and nowhere else.
 */

export const BASE_KINDS = ['tckn', 'vkn', 'iban', 'card', 'phone', 'email'] as const;

export const HEALTH_KINDS = [
  'health_ref',
  'health_date',
  'gs1_serial',
  'ssn_us',
  'mbi_us',
] as const;

export const ATTRIBUTE_KINDS = ['icd10', 'atc'] as const;

/** Every kind, base first. The order is the tie-break when two matches cover the same span. */
export const PII_KINDS = [...BASE_KINDS, ...HEALTH_KINDS, ...ATTRIBUTE_KINDS] as const;

export type BaseKind = (typeof BASE_KINDS)[number];
export type HealthKind = (typeof HEALTH_KINDS)[number];
export type AttributeKind = (typeof ATTRIBUTE_KINDS)[number];
export type PiiKind = BaseKind | HealthKind | AttributeKind;

/** `pii.profile`: `default` is the shipped base set, byte for byte. */
export type PiiProfile = 'default' | 'health';

const BASE: ReadonlySet<string> = new Set(BASE_KINDS);

/** Whether a kind is one of the shipped base kinds. */
export function isBaseKind(kind: PiiKind): kind is BaseKind {
  return BASE.has(kind);
}
