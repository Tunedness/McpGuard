/**
 * The labelled corpus format.
 *
 * The unit is **one content item**, not a session: this engine decides over one
 * tool result at a time, and a corpus whose unit does not match the engine's
 * measures something else.
 *
 * Nothing derived is stored. No expected score, no expected findings, no
 * pre-computed spans beyond the ones a human labelled. Everything else is
 * computed by the real engine at replay time, so a normaliser regression cannot
 * keep passing.
 */

/** The attacks the scanner exists to catch. */
export const ATTACK_FAMILIES = [
  'direct-override',
  'role-switch',
  'exfil-url',
  'exfil-tool',
  'credential-request',
  'hidden-unicode',
  'encoded-payload',
  'html-css-hidden',
  'data-appendix',
  'persistence',
  'multi-part-split',
  'confusable-homoglyph',
] as const;

/**
 * The honest content a false positive would ruin.
 *
 * Every one of these is a trap on purpose. `security-docs` contains the attack
 * strings verbatim; `tr-support-transcript` is saturated with polite Turkish
 * imperatives; `binary-ish-blobs` is everything the base64 detector must not
 * fire on; `prompt-engineering-content` legitimately *is* instructions, which
 * is the sharpest one — if the engine cannot tell a prompt template from an
 * injected prompt, that is a finding worth publishing rather than hiding.
 */
export const BENIGN_FAMILIES = [
  'security-docs',
  'readme-and-cli-help',
  'tr-support-transcript',
  'code-and-diffs',
  'binary-ish-blobs',
  'i18n-text',
  'logs-and-stacktraces',
  'structured-records',
  'email-threads',
  'prompt-engineering-content',
] as const;

export type AttackFamily = (typeof ATTACK_FAMILIES)[number];
export type BenignFamily = (typeof BENIGN_FAMILIES)[number];
export type CorpusFamily = AttackFamily | BenignFamily;

/** A half-open range over `text`. */
export interface Span {
  readonly start: number;
  readonly end: number;
}

/** One labelled content item. */
export interface CorpusItem {
  readonly id: string;
  readonly family: CorpusFamily;
  readonly label: 'positive' | 'negative';
  readonly locale: 'tr' | 'en' | 'mixed';
  readonly contentKind: 'tool_result' | 'resource';
  readonly mimeType: string;
  /** Realistic, so per-tool policy can be exercised during replay. */
  readonly toolName: string;
  readonly text: string;
  /**
   * Where the injected payload actually is. Positives only.
   *
   * This is what lets the harness measure whether `strip` removed the right
   * thing. Without it a stripper that deletes the whole document scores perfect
   * recall and nobody notices.
   */
  readonly payloadSpans: readonly Span[] | null;
  /** The weakest action that still counts as catching this item. */
  readonly expectedMinAction: 'flag' | 'block' | null;
  readonly note: string;
}

/**
 * Which half of the corpus an item belongs to.
 *
 * The operating point is chosen on `calibration` and the headline number is
 * reported on `validation`. Both are printed. The corpus and the ruleset are
 * written by the same hands from the same sources, so without this split "95%"
 * would mean "95% on data I tuned against" — which is not a claim about
 * anything.
 */
export type Split = 'calibration' | 'validation';
