/**
 * Applying edits, and turning injection findings into the edits that neutralise
 * them.
 *
 * `strip` does the least it can: it neutralises the spans the detectors marked
 * and defangs the egress constructs, and it leaves everything around them byte
 * for byte. A placeholder that named the rule would hand the attacker an oracle
 * and hand the model a token to interpret, so the replacement is a fixed, inert
 * marker and the span→rule mapping lives in the audit record instead.
 */
import type { Edit, Finding, Span } from './types.js';

/** The inert marker a neutralised span becomes. Reads as data, not instruction. */
export const STRIP_MARKER = '[…]';

/**
 * Applies edits to text, right to left, so each edit's offsets stay valid.
 *
 * Overlapping edits are resolved by keeping the earlier-starting, longer one:
 * two findings on the same span must not produce a double replacement.
 */
export function applyEdits(text: string, edits: readonly Edit[]): string {
  const ordered = dedupeSpans(edits).sort((a, b) => b.span.start - a.span.start);
  let out = text;
  for (const edit of ordered) {
    out = out.slice(0, edit.span.start) + edit.replacement + out.slice(edit.span.end);
  }
  return out;
}

/** Drops an edit whose span is contained in another's. */
function dedupeSpans(edits: readonly Edit[]): Edit[] {
  const sorted = [...edits].sort((a, b) => a.span.start - b.span.start || b.span.end - a.span.end);
  const out: Edit[] = [];
  let lastEnd = -1;
  for (const edit of sorted) {
    if (edit.span.start < lastEnd) continue;
    out.push(edit);
    lastEnd = edit.span.end;
  }
  return out;
}

/**
 * The edits that neutralise a set of injection findings.
 *
 * Invisible-Unicode findings are deleted outright — the characters have no
 * legitimate content to preserve. Everything else is replaced with the inert
 * marker. A defanged egress construct keeps its visible URL text for the human
 * reading the audit log, with the scheme rewritten so nothing auto-fetches.
 */
export function buildStripEdits(raw: string, findings: readonly Finding[]): Edit[] {
  const edits: Edit[] = [];
  for (const finding of findings) {
    if (finding.family === 'unicode') {
      edits.push({ span: finding.span, replacement: '', reason: `strip:${finding.ruleId}` });
    } else if (finding.family === 'exfil') {
      edits.push({
        span: finding.span,
        replacement: defang(raw.slice(finding.span.start, finding.span.end)),
        reason: `strip:${finding.ruleId}`,
      });
    } else {
      edits.push({
        span: finding.span,
        replacement: STRIP_MARKER,
        reason: `strip:${finding.ruleId}`,
      });
    }
  }
  return edits;
}

/** Rewrites a URL construct so it cannot auto-fetch, keeping the text visible. */
function defang(fragment: string): string {
  return fragment
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, '[$1 (image removed)]')
    .replace(/<img[^>]*>/gi, '[image removed]')
    .replace(/https?:/gi, (scheme) => scheme.replace('http', 'hxxp'));
}

/** Whether a span is fully inside any of a set of spans. */
export function within(span: Span, spans: readonly Span[]): boolean {
  return spans.some((s) => span.start >= s.start && span.end <= s.end);
}
