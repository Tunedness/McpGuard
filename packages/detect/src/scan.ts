/**
 * The scanner's entry point.
 *
 * **Phase 3 stub.** The detectors arrive in phases 4 and 5; this returns an
 * empty finding set so the benchmark harness can be built, run and gated
 * against the real interface before there is anything to measure. The first
 * recorded recall is 0%, which is the honest starting number and the reason the
 * corpus comes first: the sibling tool froze a detection axis before measuring
 * it and had to change the decision afterwards, with 2337 candidate operating
 * points showing that no threshold on that axis could meet the targets.
 */
import { combine, decide } from './score/index.js';
import type { ContentItem, ScanOptions, ScanVerdict } from './types.js';
import { DETECT_VERSION } from './version.js';

/** The ruleset a scan runs against. Compiled once, by `ruleset/`. */
export interface CompiledRuleset {
  readonly rulesetVersion: string;
  readonly digest: string;
  readonly ruleCount: number;
  /** Rule ids the ruleset marked as able to carry a verdict alone. */
  readonly standalone: ReadonlySet<string>;
}

/** An empty ruleset, so a caller can run the engine before one is loaded. */
export const EMPTY_RULESET: CompiledRuleset = {
  rulesetVersion: '0.0.0',
  digest: '0'.repeat(64),
  ruleCount: 0,
  standalone: new Set(),
};

/**
 * Scans one content item.
 *
 * Deterministic: the same item, ruleset and options produce the same verdict on
 * every platform, byte for byte (ADR-009).
 */
export function scanContent(
  item: ContentItem,
  ruleset: CompiledRuleset,
  options: ScanOptions,
): ScanVerdict {
  const totalBytes = byteLength(item.text);
  const degraded = totalBytes > options.maxBytes;
  const scannedBytes = degraded ? options.maxBytes : totalBytes;

  // Phase 4 replaces this with the detector pipeline. Until then the finding
  // set is empty by construction rather than by accident, and the benchmark
  // records what that is worth.
  const findings: ScanVerdict['findings'] = [];
  const { score } = combine({ findings, standalone: ruleset.standalone });
  const action = decide(score, options, degraded);

  return {
    score,
    action,
    findings,
    edits: [],
    text: item.text,
    degraded,
    scannedBytes,
    totalBytes,
    engineVersion: DETECT_VERSION,
    rulesetVersion: ruleset.rulesetVersion,
    rulesetDigest: ruleset.digest,
  };
}

/**
 * UTF-8 length, which is what a size cap has to be measured in.
 *
 * `String.length` counts UTF-16 code units, so a Turkish result would be
 * reported smaller than it is on the wire and a budget written in bytes would
 * not be the budget that applies.
 */
export function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}
