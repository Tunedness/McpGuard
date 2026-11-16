/**
 * Runs the PHI corpus through the **real** engine and measures each recogniser.
 *
 * No model of the scanner: every item goes through `scanContent()` with the
 * shipped ruleset and a policy shaped like a regulated deployment — the health
 * profile on, every recogniser named — so the number is the product's. A span
 * counts as found only when kind, start and end all match the label; a mask that
 * covers half an identifier leaves the other half in the clear, and calling that
 * a hit would flatter the recogniser.
 */
import {
  type CompiledRuleset,
  PII_KINDS,
  type ScanOptions,
  scanContent,
} from '@tunedness/mcpguard-detect';
import { PHI_KINDS, type PhiItem, type PhiKind } from './types.js';

/** What one recogniser did over the corpus. */
export interface KindMetrics {
  /** Labelled spans of this kind. */
  readonly spans: number;
  /** Labelled spans found exactly. */
  readonly found: number;
  readonly recall: number;
  /** Detections of this kind in a positive item that no label accounts for. */
  readonly strayInPositives: number;
  /** Gated negatives the kind fired on, and how many gated negatives there were. */
  readonly negativeFires: number;
  readonly negatives: number;
  readonly falsePositiveRate: number;
  /** The same, over only the negatives built to trick this kind. */
  readonly trapFires: number;
  readonly traps: number;
  readonly trapFalsePositiveRate: number;
  /** The holdout collisions the kind was set a trap by: reported, not part of the gate. */
  readonly holdoutFires: number;
  readonly holdouts: number;
  /** Of those holdout items, how many the kind missed but another kind masked. */
  readonly holdoutOther: number;
  /** Accepted false positives that fired, and how many there are (a subset of the negatives). */
  readonly acceptedFires: number;
  readonly accepted: number;
  /** Ambiguous-anchor positives: labelled spans, found. Outside the recall gate, reported. */
  readonly ambiguousSpans: number;
  readonly ambiguousFound: number;
}

export type Metrics = Record<PhiKind, KindMetrics>;

/** The scan options the benchmark runs under. */
export function optionsFor(strictChecksum: boolean): ScanOptions {
  return {
    action: 'flag',
    flagAt: 40,
    blockAt: 70,
    maxBytes: 262_144,
    onDegraded: 'flag',
    pii: {
      profile: 'health',
      recognizers: [...PII_KINDS],
      strictChecksum,
      keepLast: 0,
      correlationTags: false,
    },
  };
}

/** One detection reduced to what the scoring reads. */
interface Detection {
  readonly kind: string;
  readonly start: number;
  readonly end: number;
}

/** Scans every item and returns its detections. */
export function detections(
  items: readonly PhiItem[],
  ruleset: CompiledRuleset,
  options: ScanOptions,
): Map<string, Detection[]> {
  const out = new Map<string, Detection[]>();
  for (const item of items) {
    const verdict = scanContent(
      { id: item.id, text: item.text, kind: 'tool_result', mimeType: 'text/plain' },
      ruleset,
      options,
    );
    // Every kind, not only the scored ones: a holdout item masked as something
    // else (a ten-digit number read as a tax id) is still masked, and the report
    // says so.
    out.set(
      item.id,
      verdict.piiFindings.map((f) => ({ kind: f.kind, start: f.span.start, end: f.span.end })),
    );
  }
  return out;
}

/** Measures every recogniser from the detections. */
export function measure(items: readonly PhiItem[], found: Map<string, Detection[]>): Metrics {
  const result = {} as Record<PhiKind, KindMetrics>;
  for (const kind of PHI_KINDS) {
    let spans = 0;
    let hit = 0;
    let stray = 0;
    let negativeFires = 0;
    let negatives = 0;
    let trapFires = 0;
    let traps = 0;
    let holdoutFires = 0;
    let holdouts = 0;
    let holdoutOther = 0;
    let acceptedFires = 0;
    let accepted = 0;
    let ambiguousSpans = 0;
    let ambiguousFound = 0;
    for (const item of items) {
      const mine = (found.get(item.id) ?? []).filter((d) => d.kind === kind);
      if (item.label === 'positive') {
        const labelled = item.spans.filter((s) => s.kind === kind);
        const exact = labelled.filter((span) =>
          mine.some((d) => d.start === span.start && d.end === span.end),
        ).length;
        if (!item.gated) {
          // The price of the exclusion lists, counted apart from the recall gate.
          ambiguousSpans += labelled.length;
          ambiguousFound += exact;
          continue;
        }
        spans += labelled.length;
        hit += exact;
        stray += mine.filter(
          (d) => !labelled.some((s) => s.start === d.start && s.end === d.end),
        ).length;
        continue;
      }
      const fired = mine.length > 0;
      const trapped = item.trapFor.includes(kind);
      if (item.gated) {
        negatives++;
        if (fired) negativeFires++;
        if (item.accepted !== undefined && trapped) {
          accepted++;
          if (fired) acceptedFires++;
        }
        if (trapped) {
          traps++;
          if (fired) trapFires++;
        }
      } else if (trapped) {
        holdouts++;
        if (fired) holdoutFires++;
        else if ((found.get(item.id) ?? []).length > 0) holdoutOther++;
      }
    }
    result[kind] = {
      spans,
      found: hit,
      recall: spans === 0 ? 1 : hit / spans,
      strayInPositives: stray,
      negativeFires,
      negatives,
      falsePositiveRate: negatives === 0 ? 0 : negativeFires / negatives,
      trapFires,
      traps,
      trapFalsePositiveRate: traps === 0 ? 0 : trapFires / traps,
      holdoutFires,
      holdouts,
      holdoutOther,
      acceptedFires,
      accepted,
      ambiguousSpans,
      ambiguousFound,
    };
  }
  return result;
}
