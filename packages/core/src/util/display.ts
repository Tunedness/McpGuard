/**
 * Showing a string a server chose to a person, without letting it act on them.
 *
 * Tool names and descriptions are the server's words, and McpGuard prints them
 * where an operator reviews them: `lock --diff` is the screen a rug-pull is
 * approved on. `JSON.stringify` quotes a string but escapes only U+0000 to
 * U+001F. Everything else that changes how a terminal or a viewer draws a
 * line gets through it: C1 controls (U+009B is a one-character CSI), the bidi
 * overrides and isolates (a name that reads as another name), zero-width and
 * other format characters, and the line and paragraph separators. Those are
 * written out as `\uXXXX`, which is still valid JSON, so the result can be
 * parsed back and shows what the text is rather than what it pretends to be.
 */

/** Control (C0, C1), format (bidi, zero-width, tag) and line/paragraph separators. */
const UNSAFE = /[\p{Cc}\p{Cf}\u2028\u2029]/gu;

const unit = (value: number): string => `\\u${value.toString(16).padStart(4, '0')}`;

/** Escapes the characters above in already-serialised JSON, as valid JSON escapes. */
export function escapeUnsafeJson(json: string): string {
  return json.replace(UNSAFE, (char) => {
    const point = char.codePointAt(0) ?? 0;
    if (point <= 0xffff) return unit(point);
    const offset = point - 0x10000;
    return unit(0xd800 + (offset >> 10)) + unit(0xdc00 + (offset & 0x3ff));
  });
}

/** A JSON-quoted string that is safe to print. */
export function quote(value: string): string {
  return escapeUnsafeJson(JSON.stringify(value));
}
