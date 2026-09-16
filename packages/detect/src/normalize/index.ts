/**
 * The one walk every detector reads from.
 *
 * Nothing re-walks the string. The case fold, the skeleton fold, the character
 * classes, the region marks and the clause split are produced together and
 * handed to the detectors as fixed artifacts, so a 100 KB result is traversed a
 * small constant number of times rather than once per rule.
 */
import { type CharClasses, classify_all } from './classes.js';
import { type Clause, splitClauses } from './clauses.js';
import { caseFold, type Folded, skeletonFold } from './fold.js';
import { type DocShape, shapeOf } from './regions.js';

export interface Normalized {
  readonly raw: string;
  /** Case-folded, Turkish-aware, with the offset map back to `raw`. */
  readonly folded: Folded;
  /** The skeleton fold of `folded.text`; same length, same offsets. */
  readonly skeleton: string;
  readonly classes: CharClasses;
  readonly shape: DocShape;
  readonly clauses: readonly Clause[];
}

/** Runs the shared normalization pass over one item's raw text. */
export function normalize(raw: string, mimeType: string | undefined): Normalized {
  const folded = caseFold(raw);
  return {
    raw,
    folded,
    skeleton: skeletonFold(folded.text),
    classes: classify_all(raw),
    shape: shapeOf(raw, mimeType),
    clauses: splitClauses(raw),
  };
}

export type { CharClasses, ClassedChar } from './classes.js';
export { isPictographic } from './classes.js';
export type { Clause } from './clauses.js';
export type { Folded } from './fold.js';
export { rawSpan } from './fold.js';
export type { DocShape, Region } from './regions.js';
export { inCode, inComment } from './regions.js';
