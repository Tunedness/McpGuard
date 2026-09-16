/**
 * The hidden-Unicode detector.
 *
 * Scoped so legitimate multilingual text does not fire. Two classes of
 * character behave differently: those with no legitimate use in a tool result
 * fire on a single occurrence, and those that are orthographically real — ZWNJ
 * in Persian, a BOM at the start, emoji zero-width joiners — fire only on
 * density or on a bit-pattern that decodes to printable ASCII.
 */
import { isPictographic, type Normalized } from '../normalize/index.js';
import type { Finding } from '../types.js';

export function detectUnicode(normalized: Normalized): Finding[] {
  const { chars, hasRtl } = normalized.classes;
  if (chars.length === 0) return [];
  const findings: Finding[] = [];

  const tags = chars.filter((c) => c.kind === 'tag');
  if (tags.length > 0) {
    // Tag characters have one use here: carrying an invisible instruction. Any
    // occurrence is decisive. The decoded ASCII is the evidence.
    const decoded = tags.map((c) => String.fromCodePoint((c.codePoint - 0xe0000) & 0x7f)).join('');
    findings.push({
      ruleId: 'unicode.tag-block',
      family: 'unicode',
      severity: 'critical',
      weight: 950,
      span: { start: tags[0]?.at ?? 0, end: (tags[tags.length - 1]?.at ?? 0) + 1 },
      evidence: `tag-block: ${decoded.slice(0, 48)}`,
    });
  }

  const bidi = chars.filter((c) => c.kind === 'bidi');
  if (bidi.length > 0) {
    const opens = bidi.filter((c) => c.codePoint === 0x202d || c.codePoint === 0x202e).length;
    // An override in a document with no RTL script has nothing legitimate to do,
    // and an unbalanced set of controls is a reordering trick.
    if ((opens > 0 && !hasRtl) || unbalanced(bidi.map((c) => c.codePoint))) {
      findings.push({
        ruleId: 'unicode.bidi-override',
        family: 'unicode',
        severity: 'high',
        weight: 720,
        span: { start: bidi[0]?.at ?? 0, end: (bidi[bidi.length - 1]?.at ?? 0) + 1 },
        evidence: 'bidi control reordering visible text',
      });
    }
  }

  const zeroWidth = chars.filter((c) => c.kind === 'zero-width');
  if (zeroWidth.length > 0) {
    const legitimate = countLegitimateZeroWidth(normalized.raw, zeroWidth);
    const suspicious = zeroWidth.length - legitimate;
    // Fires on density (a run interrupting Latin words) rather than presence, so
    // a single ZWNJ inside an Arabic word — counted as legitimate above — never
    // reaches here.
    if (suspicious >= 4) {
      findings.push({
        ruleId: 'unicode.zero-width-density',
        family: 'unicode',
        severity: suspicious >= 8 ? 'high' : 'medium',
        weight: suspicious >= 8 ? 680 : 420,
        span: { start: zeroWidth[0]?.at ?? 0, end: (zeroWidth[zeroWidth.length - 1]?.at ?? 0) + 1 },
        evidence: `${suspicious} zero-width characters splitting visible text`,
      });
    }
  }

  return findings;
}

/** Whether an open/close sequence of direction controls is unbalanced. */
function unbalanced(codes: readonly number[]): boolean {
  let depth = 0;
  for (const code of codes) {
    if (code === 0x202a || code === 0x202b || code === 0x202d || code === 0x202e) depth++;
    else if (code === 0x202c) depth--;
    else if (code >= 0x2066 && code <= 0x2068) depth++;
    else if (code === 0x2069) depth--;
  }
  return depth !== 0;
}

/**
 * Counts the zero-width characters that have a legitimate reason to be there.
 *
 * A ZWJ between two pictographs is an emoji sequence; a ZWNJ or ZWJ adjacent to
 * an RTL/Indic character is orthographically required; a single BOM at offset 0
 * is a byte-order mark. Everything else is a candidate.
 */
function countLegitimateZeroWidth(
  raw: string,
  zeroWidth: readonly { at: number; codePoint: number }[],
): number {
  // Walk the raw text once into a code-point array with offsets. Neighbour
  // lookups then read the array, which is what makes an emoji joiner between two
  // surrogate-pair pictographs legible — offset arithmetic lands mid-pair and
  // would report no neighbour at all.
  const cps: { cp: number; at: number }[] = [];
  let at = 0;
  for (const char of raw) {
    cps.push({ cp: char.codePointAt(0) ?? 0, at });
    at += char.length;
  }
  const indexAt = new Map<number, number>();
  for (let i = 0; i < cps.length; i++) {
    const entry = cps[i];
    if (entry !== undefined) indexAt.set(entry.at, i);
  }

  let legitimate = 0;
  for (const zw of zeroWidth) {
    if (zw.codePoint === 0xfeff && zw.at === 0) {
      legitimate++;
      continue;
    }
    const index = indexAt.get(zw.at);
    if (index === undefined) continue;
    const before = cps[index - 1]?.cp;
    const after = cps[index + 1]?.cp;
    if (
      zw.codePoint === 0x200d &&
      before !== undefined &&
      after !== undefined &&
      isPictographic(before) &&
      isPictographic(after)
    ) {
      legitimate++;
      continue;
    }
    if (before !== undefined && isComplexScript(before)) legitimate++;
  }
  return legitimate;
}

/** Arabic/Persian and Indic ranges where ZWNJ/ZWJ are part of the orthography. */
function isComplexScript(code: number): boolean {
  return (
    (code >= 0x0600 && code <= 0x06ff) ||
    (code >= 0x0900 && code <= 0x0dff) ||
    (code >= 0xfb50 && code <= 0xfdff) ||
    (code >= 0xfe70 && code <= 0xfeff)
  );
}
