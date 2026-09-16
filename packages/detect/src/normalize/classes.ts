/**
 * Per-code-point structural facts, gathered in one walk over the raw text.
 *
 * These are cheap byte-class checks — no rule evaluation — so they run over the
 * whole buffer even when rule matching is truncated for size. That asymmetry is
 * deliberate: a 10 MB result cannot spend the rule budget, but a smuggling
 * payload made of invisible characters must not walk straight through because
 * the tail was not scanned.
 */

/** One code point the walk found worth remembering, with its raw offset. */
export interface ClassedChar {
  /** UTF-16 offset into the raw text. */
  readonly at: number;
  readonly codePoint: number;
  readonly kind: CharKind;
}

export type CharKind =
  | 'tag' // U+E0000..E007F — the classic invisible prompt carrier
  | 'bidi' // LRO/RLO/PDF and the isolates — direction overrides
  | 'zero-width' // ZWSP/ZWNJ/ZWJ/WJ/BOM/soft-hyphen — legitimate *and* abused
  | 'variation'; // variation selectors — emoji styling, or a hiding place

/** The counts and positions D3 reasons about. */
export interface CharClasses {
  readonly chars: readonly ClassedChar[];
  readonly total: number;
  /** True when any RTL script character is present, so a bidi control is expected. */
  readonly hasRtl: boolean;
}

function classify(code: number): CharKind | undefined {
  if (code >= 0xe0000 && code <= 0xe007f) return 'tag';
  if (code === 0x202a || code === 0x202b || code === 0x202c) return 'bidi';
  if (code === 0x202d || code === 0x202e) return 'bidi';
  if (code >= 0x2066 && code <= 0x2069) return 'bidi';
  if (
    code === 0x200b ||
    code === 0x200c ||
    code === 0x200d ||
    code === 0x2060 ||
    code === 0xfeff ||
    code === 0x00ad
  ) {
    return 'zero-width';
  }
  if ((code >= 0xfe00 && code <= 0xfe0f) || (code >= 0xe0100 && code <= 0xe01ef)) {
    return 'variation';
  }
  return undefined;
}

/** RTL script ranges, enough to tell "a bidi control here is expected" from "not". */
function isRtl(code: number): boolean {
  return (
    (code >= 0x0590 && code <= 0x05ff) || // Hebrew
    (code >= 0x0600 && code <= 0x06ff) || // Arabic
    (code >= 0x0700 && code <= 0x074f) || // Syriac
    (code >= 0x0750 && code <= 0x077f) || // Arabic Supplement
    (code >= 0x08a0 && code <= 0x08ff) || // Arabic Extended-A
    (code >= 0xfb50 && code <= 0xfdff) || // Arabic Presentation Forms-A
    (code >= 0xfe70 && code <= 0xfeff) // Arabic Presentation Forms-B
  );
}

/** Whether a code point is Extended_Pictographic enough for the ZWJ/VS rules. */
export function isPictographic(code: number): boolean {
  return (
    (code >= 0x1f000 && code <= 0x1faff) ||
    (code >= 0x2600 && code <= 0x27bf) ||
    code === 0x2764 ||
    (code >= 0x2190 && code <= 0x21ff)
  );
}

/** Walks the raw text once and records every classed code point. */
export function classify_all(raw: string): CharClasses {
  const chars: ClassedChar[] = [];
  let total = 0;
  let hasRtl = false;
  let at = 0;
  for (const char of raw) {
    const code = char.codePointAt(0) ?? 0;
    total++;
    if (!hasRtl && isRtl(code)) hasRtl = true;
    const kind = classify(code);
    if (kind !== undefined) chars.push({ at, codePoint: code, kind });
    at += char.length;
  }
  return { chars, total, hasRtl };
}
