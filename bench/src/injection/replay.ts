/**
 * Runs the corpus through the **real** engine.
 *
 * No model of the scanner: every item goes through `scanContent()` with the
 * real compiled ruleset, exactly as the proxy would call it, so the measured
 * number is the product's and not a description of it.
 *
 * In phase 3 the ruleset is empty and every verdict is `allow`, which is the
 * point: the 0% recall this prints is honest, and it is what the detectors in
 * phases 4 and 5 are calibrated to move.
 */

import type { ScanOptions } from '@mcpguard/detect';
import { type CompiledRuleset, scanContent } from '@mcpguard/detect';
import type { CorpusItem } from './types.js';

/** One item's outcome under one operating point. */
export interface ReplayResult {
  readonly item: CorpusItem;
  readonly score: number;
  readonly action: string;
  /** True when a positive was caught, or a negative was left alone. */
  readonly correct: boolean;
}

/** The options a scan runs under, at one flag threshold. */
export function optionsAt(flagAt: number, blockAt: number): ScanOptions {
  return { action: 'flag', flagAt, blockAt, maxBytes: 262_144, onDegraded: 'flag' };
}

/** Scans every item and labels each outcome correct or not. */
export function replay(
  items: readonly CorpusItem[],
  ruleset: CompiledRuleset,
  options: ScanOptions,
): ReplayResult[] {
  return items.map((item) => {
    const verdict = scanContent(
      {
        id: item.id,
        text: item.text,
        kind: item.contentKind,
        // Pass the mime type the server would have sent: it drives the
        // doc-shape damping, so a scan that omits it is not the scan the proxy
        // runs, and the number it produces is not the product's.
        mimeType: item.mimeType,
        channel: item.toolName,
      },
      ruleset,
      options,
    );
    const caught = verdict.action !== 'allow';
    const correct = item.label === 'positive' ? caught : !caught;
    return { item, score: verdict.score, action: verdict.action, correct };
  });
}
