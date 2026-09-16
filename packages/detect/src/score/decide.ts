/**
 * Turning a score into one of four actions.
 *
 * The bands are simple on purpose: an operator reading a verdict during an
 * incident should be able to check the arithmetic in their head.
 */
import type { ScanAction, ScanOptions } from '../types.js';

/** What a score means under one set of thresholds. */
export function decide(score: number, options: ScanOptions, degraded: boolean): ScanAction {
  if (degraded) {
    // A partially scanned item is not a clean one. `flag` is the default
    // because silence is the wrong answer either way, and blocking every large
    // result would make the proxy the thing that broke the workflow.
    const fallback = options.onDegraded;
    if (fallback === 'block') return 'block';
    if (fallback === 'flag') return score >= options.flagAt ? configured(options) : 'flag';
  }
  if (score >= options.blockAt) {
    // Above the block line the configured action still governs: `block` is
    // opt-in and per-tool (PRD §8), so a tool left on the default gets `flag`
    // no matter how high the score went. The operator decides what enforcement
    // means; the engine only decides what it found.
    return configured(options);
  }
  if (score >= options.flagAt) {
    return options.action === 'block' ? 'flag' : configured(options);
  }
  return 'allow';
}

/** The action the policy asked for, as a {@link ScanAction}. */
function configured(options: ScanOptions): ScanAction {
  return options.action;
}
