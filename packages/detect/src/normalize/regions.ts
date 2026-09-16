/**
 * Coarse region marking over the raw text.
 *
 * A signature inside a fenced code block, or in a document that is mostly code
 * or mostly headings, is far more likely to be documentation quoting an attack
 * than an attack. The scanner does not need a full Markdown parser to tell the
 * difference — it needs to know, for a given offset, whether it sits in quoted
 * code, and whether the whole item reads like a document rather than a tool
 * result. Both are computed in one pass.
 */

/** A half-open raw-offset range that a finding can be tested against. */
export interface Region {
  readonly start: number;
  readonly end: number;
  readonly kind: 'code' | 'comment';
}

/** What one item looks like, for damping decisions. */
export interface DocShape {
  readonly regions: readonly Region[];
  /** Fraction of characters inside a fenced/inline code region. */
  readonly codeRatio: number;
  /** Count of Markdown ATX headings (`#` … `######`). */
  readonly headings: number;
  /**
   * True when the item reads like prose-with-structure rather than a payload:
   * several headings, or a high code ratio. Damps the noisy families.
   */
  readonly docLike: boolean;
}

const FENCE = /```[\s\S]*?```|~~~[\s\S]*?~~~/g;
const INLINE_CODE = /`[^`\n]+`/g;
const HTML_COMMENT = /<!--[\s\S]*?-->/g;
const HEADING = /^#{1,6}\s/gm;

/** Marks regions and measures the document's shape, in one look. */
export function shapeOf(raw: string, mimeType: string | undefined): DocShape {
  const regions: Region[] = [];
  let codeChars = 0;

  for (const match of raw.matchAll(FENCE)) {
    const start = match.index ?? 0;
    regions.push({ start, end: start + match[0].length, kind: 'code' });
    codeChars += match[0].length;
  }
  for (const match of raw.matchAll(INLINE_CODE)) {
    const start = match.index ?? 0;
    // Skip inline code that a fence already covers.
    if (regions.some((r) => start >= r.start && start < r.end)) continue;
    regions.push({ start, end: start + match[0].length, kind: 'code' });
    codeChars += match[0].length;
  }
  for (const match of raw.matchAll(HTML_COMMENT)) {
    const start = match.index ?? 0;
    regions.push({ start, end: start + match[0].length, kind: 'comment' });
  }

  const headings = [...raw.matchAll(HEADING)].length;
  const codeRatio = raw.length === 0 ? 0 : codeChars / raw.length;
  // Documentation that quotes attacks is long and structured — several headings,
  // or mostly code. A short page with one heading is not that, and treating it as
  // a document was damping genuine injections served as markdown to nothing. The
  // mime type no longer lowers the bar on its own.
  void mimeType;
  const docLike = headings >= 3 || codeRatio > 0.25;

  return { regions, codeRatio, headings, docLike };
}

/** Whether an offset sits inside a code region. */
export function inCode(regions: readonly Region[], offset: number): boolean {
  return regions.some((r) => r.kind === 'code' && offset >= r.start && offset < r.end);
}

/** Whether an offset sits inside an HTML comment. */
export function inComment(regions: readonly Region[], offset: number): boolean {
  return regions.some((r) => r.kind === 'comment' && offset >= r.start && offset < r.end);
}
