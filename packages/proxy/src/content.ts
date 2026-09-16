/**
 * Extracting the text the scanner reads out of an MCP result, and putting the
 * guarded text back.
 *
 * A tool result and a resource read carry a list of content blocks; the text
 * ones are what a poisoned server hides an instruction in, and what a leaky one
 * exposes PII through. This module knows the shape of those blocks and nothing
 * about scanning — it hands out `{ id, text }` items and takes back guarded text
 * by the same id, so `guard.ts` can stay engine-facing and this can stay
 * protocol-facing.
 */

/** A minimal view of a content block; only text blocks carry scannable text. */
export interface TextBlockRef {
  readonly id: string;
  readonly text: string;
}

/** A CallToolResult / ReadResourceResult, loosely typed for extraction. */
export interface ResultLike {
  content?: unknown;
  contents?: unknown;
  [key: string]: unknown;
}

/** Pulls every text block out of a result, tagged by a stable id. */
export function extractText(result: ResultLike): TextBlockRef[] {
  const refs: TextBlockRef[] = [];
  const blocks = Array.isArray(result.content)
    ? result.content
    : Array.isArray(result.contents)
      ? result.contents
      : [];
  blocks.forEach((block, index) => {
    if (isTextBlock(block)) refs.push({ id: String(index), text: block.text });
  });
  return refs;
}

/**
 * Rebuilds a result with each text block replaced by its guarded text.
 *
 * A shallow structural copy: only the `text` field of the blocks named in
 * `guarded` changes, everything else is carried through untouched, so a result
 * McpGuard does not understand still passes with its text guarded.
 */
export function replaceText(result: ResultLike, guarded: ReadonlyMap<string, string>): ResultLike {
  const key = Array.isArray(result.content)
    ? 'content'
    : Array.isArray(result.contents)
      ? 'contents'
      : undefined;
  if (key === undefined) return result;
  const blocks = result[key] as unknown[];
  const nextBlocks = blocks.map((block, index) => {
    const text = guarded.get(String(index));
    if (text === undefined || !isTextBlock(block)) return block;
    return { ...block, text };
  });
  return { ...result, [key]: nextBlocks };
}

/** Whether the value is a `{ type: 'text', text: string }` block. */
function isTextBlock(value: unknown): value is { type: string; text: string } {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as { type?: unknown }).type === 'text' &&
    typeof (value as { text?: unknown }).text === 'string'
  );
}
