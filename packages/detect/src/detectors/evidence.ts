/**
 * Cutting a short excerpt for a finding, safe to write to a log.
 *
 * The excerpt is drawn from the item's raw text, capped, and every control
 * character is rendered as its escape so the evidence cannot itself carry an
 * ANSI sequence or a newline into whatever terminal or SIEM reads the audit
 * record. Phase 5's masker runs before the verdict is recorded, so the raw text
 * an evidence excerpt sees at audit time is already masked; here it is only ever
 * shown back to the same process.
 */
import type { Span } from '../types.js';

/** A ≤ 64-char, control-escaped excerpt of `raw` at `span`. */
export function evidenceOf(raw: string, span: Span): string {
  const slice = raw.slice(span.start, Math.min(span.end, span.start + 64));
  let out = '';
  for (const char of slice) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) {
      out += `\\u${code.toString(16).padStart(4, '0')}`;
    } else {
      out += char;
    }
  }
  return out.trim();
}
