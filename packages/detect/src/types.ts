/**
 * What the scanner is asked about, and what it answers.
 *
 * These types are frozen ahead of the detectors that produce them, so the
 * benchmark harness, the proxy and the audit record can all be written against
 * a fixed shape while the engine behind it is still being calibrated.
 */

/** Where a piece of content came from. Decides which rules even apply. */
export type ContentKind = 'tool_result' | 'resource' | 'tool_description' | 'prompt';

/** One thing to scan. */
export interface ContentItem {
  /** Stable within one scan, so a finding can name the part it was in. */
  readonly id: string;
  readonly text: string;
  readonly kind: ContentKind;
  readonly mimeType?: string | undefined;
  /**
   * An opaque label the proxy fills with `<server>__<tool>`.
   *
   * Opaque on purpose: it lets per-tool policy work without the engine ever
   * learning what a tool is.
   */
  readonly channel?: string | undefined;
}

/** A half-open range over the item's raw text, in UTF-16 code units. */
export interface Span {
  readonly start: number;
  readonly end: number;
}

/** Which detector produced a finding. Families combine, they do not add up. */
export type Family =
  | 'signature'
  | 'imperative'
  | 'unicode'
  | 'encoding'
  | 'exfil'
  | 'frame'
  | 'anomaly';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** One thing a detector noticed. */
export interface Finding {
  /** Rule id for signature findings; a detector-defined id for the rest. */
  readonly ruleId: string;
  readonly family: Family;
  readonly severity: Severity;
  /** 0–1000, integer. ADR-009: no floating point on the score path. */
  readonly weight: number;
  readonly span: Span;
  /** Cut from the **masked** text, never the raw. Capped, controls escaped. */
  readonly evidence: string;
  /** Set when the finding was reached by decoding something first. */
  readonly viaDecode?: 'base64' | 'hex' | 'percent' | 'entity' | 'tag-unicode' | undefined;
}

/** What the scanner decided should happen to the content. */
export type ScanAction = 'allow' | 'flag' | 'strip' | 'block';

/** One edit `strip` made, so the audit record can reconstruct what changed. */
export interface Edit {
  readonly span: Span;
  readonly replacement: string;
  readonly reason: string;
}

/** A masked piece of PII, for the report and the audit record. Never the raw value. */
export interface PiiFinding {
  readonly kind: string;
  readonly span: Span;
  /** The masked replacement that went into the forwarded content. */
  readonly masked: string;
}

/** The answer. */
export interface ScanVerdict {
  /** 0–100, integer. */
  readonly score: number;
  readonly action: ScanAction;
  readonly findings: readonly Finding[];
  /** PII masked in the forwarded content, on its own axis from the action. */
  readonly piiFindings: readonly PiiFinding[];
  /** Every edit made to the content — strip neutralisations and PII masks. */
  readonly edits: readonly Edit[];
  /** The text to forward: masked, and stripped when the action was `strip`. */
  readonly text: string;
  /** True when the item was too large for full rule evaluation. */
  readonly degraded: boolean;
  readonly scannedBytes: number;
  readonly totalBytes: number;
  /** Recorded so any decision can be reproduced against what made it. */
  readonly engineVersion: string;
  readonly rulesetVersion: string;
  readonly rulesetDigest: string;
}

/** How PII masking is configured for one scan. Absent → no masking. */
export interface PiiScanConfig {
  /** Recogniser ids to run; empty runs all shipped recognisers. */
  readonly recognizers: readonly string[];
  readonly strictChecksum: boolean;
  readonly keepLast: number;
  readonly correlationTags: boolean;
  /** HMAC key for correlation tags. Absent → tags are omitted. */
  readonly correlationKey?: string | undefined;
}

/** The thresholds and posture one scan runs under. */
export interface ScanOptions {
  readonly action: 'flag' | 'strip' | 'block';
  readonly flagAt: number;
  readonly blockAt: number;
  readonly maxBytes: number;
  readonly onDegraded: 'flag' | 'block' | 'allow';
  /** PII masking, on its own axis from the injection action. Absent → off. */
  readonly pii?: PiiScanConfig | undefined;
}
