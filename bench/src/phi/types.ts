/**
 * The labelled PHI corpus format.
 *
 * The unit is **one content item**, the same unit the engine decides over. What
 * a human labelled is only `spans`: where each identifier is, and which kind.
 * Nothing the engine computes is stored, so a recogniser regression cannot keep
 * passing. Everything in it is synthetic — generated, never copied.
 */

/** The kinds the benchmark scores; the base kinds are not in scope here. */
export const PHI_KINDS = [
  'health_ref',
  'health_date',
  'gs1_serial',
  'ssn_us',
  'mbi_us',
  'icd10',
  'atc',
] as const;

export type PhiKind = (typeof PHI_KINDS)[number];

/** A labelled identifier: a half-open range over `text`, in UTF-16 code units. */
export interface PhiSpan {
  readonly kind: PhiKind;
  readonly start: number;
  readonly end: number;
}

/** One labelled content item. */
export interface PhiItem {
  readonly id: string;
  /** For a positive, `<kind>` or `mixed`; for a negative, the trap it sets. */
  readonly family: string;
  readonly label: 'positive' | 'negative';
  readonly locale: 'tr' | 'en';
  readonly text: string;
  /** What a recogniser must find. Empty on every negative. */
  readonly spans: readonly PhiSpan[];
  /** The kinds a negative is designed to trick. Empty on a positive. */
  readonly trapFor: readonly PhiKind[];
  /**
   * Whether a false positive here counts against the gate.
   *
   * `false` only for the holdout collisions: non-clinical uses of a keyword,
   * written after the exclusion lists with wording they do not carry. They
   * measure whether the lists generalise, so they are reported, not gated, and
   * never used to tune the lists. It is also `false` for the ambiguous-anchor
   * positives, whose recall is the price of the exclusion lists and is reported
   * as a number of its own, outside the recall gate.
   */
  readonly gated: boolean;
  /**
   * Set on a negative whose false positive is a decision, not a gap: the reason.
   * It is still counted as a false positive, in the gate and in the rates; the
   * report lists how many fired so the decision stays visible.
   */
  readonly accepted?: string;
}

/** The positive families: one per kind, a composite, and clinical content beside an exclusion word. */
export const POSITIVE_FAMILIES = [
  ...PHI_KINDS,
  'mixed',
  'exclusion-mixed',
  'ambiguous-anchor-mixed',
] as const;

/** The negative families — every one is a trap on purpose. */
export const NEGATIVE_FAMILIES = [
  'order-and-invoice-numbers',
  'retail-barcodes',
  'log-timestamps',
  'version-strings',
  'product-codes',
  'anchor-without-number',
  'dates-without-context',
  'bare-digit-runs',
  'mbi-near-misses',
  'icd-without-context',
  'gs1-incomplete',
  'atc-lookalikes',
  'clinical-prose',
  'keyword-collisions',
  'keyword-collisions-holdout',
] as const;

/** The gates ADR-012 sets, in one place so the report and the test read the same ones. */
export const GATES: Readonly<
  Record<
    PhiKind,
    { readonly recall: number; readonly falsePositive: number; readonly class: string } | null
  >
> = {
  gs1_serial: { recall: 0.99, falsePositive: 0, class: 'checksum or structure gated' },
  mbi_us: { recall: 0.99, falsePositive: 0, class: 'checksum or structure gated' },
  health_ref: { recall: 0.95, falsePositive: 0.01, class: 'anchored or contextual' },
  health_date: { recall: 0.95, falsePositive: 0.01, class: 'anchored or contextual' },
  ssn_us: { recall: 0.95, falsePositive: 0.01, class: 'anchored or contextual' },
  icd10: { recall: 0.95, falsePositive: 0.01, class: 'anchored or contextual' },
  // ADR-012 sets no target for `atc`: it is shape-only and opt-in, so it is
  // measured and reported, not gated.
  atc: null,
};
