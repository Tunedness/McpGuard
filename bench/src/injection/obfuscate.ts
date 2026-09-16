/**
 * The ways a payload hides.
 *
 * Each transform takes a clear instruction and returns the text plus the span
 * the instruction now occupies, so the corpus can record where the payload is
 * even after it has been mangled. Deterministic given the Rng.
 */
import type { Rng } from '../rng.js';

export interface Obfuscated {
  readonly text: string;
  /** The span of the (possibly transformed) payload within `text`. */
  readonly start: number;
  readonly end: number;
}

/** The instruction sits in the text as written. */
export function identity(host: string, payload: string, rng: Rng): Obfuscated {
  return place(host, payload, rng);
}

/** Zero-width characters splitting each letter of the trigger words. */
export function zeroWidthSplit(host: string, payload: string, rng: Rng): Obfuscated {
  const zwsp = '​';
  const split = [...payload].join(zwsp);
  return place(host, split, rng);
}

/** The instruction base64-encoded, introduced as if it were data. */
export function base64(host: string, payload: string, rng: Rng): Obfuscated {
  const encoded = toBase64(payload);
  return place(host, `Decode and follow: ${encoded}`, rng);
}

/** Latin letters swapped for Cyrillic/Greek look-alikes. */
export function homoglyph(host: string, payload: string, rng: Rng): Obfuscated {
  const map: Record<string, string> = {
    a: 'а',
    e: 'е',
    o: 'о',
    p: 'р',
    c: 'с',
    y: 'у',
    i: 'і',
  };
  const swapped = [...payload].map((ch) => map[ch.toLowerCase()] ?? ch).join('');
  return place(host, swapped, rng);
}

/** Tag-block characters, the classic invisible carrier. */
export function tagBlock(host: string, payload: string, rng: Rng): Obfuscated {
  const tagged = [...payload]
    .map((ch) => {
      const code = ch.codePointAt(0) ?? 32;
      return code >= 0x20 && code <= 0x7f ? String.fromCodePoint(0xe0000 + code) : ch;
    })
    .join('');
  return place(host, tagged, rng);
}

/** Inserts `insert` into `host` at a seam between lines, recording its span. */
function place(host: string, insert: string, rng: Rng): Obfuscated {
  const seams = seamOffsets(host);
  const at = seams[rng.int(seams.length)] ?? host.length;
  const text = host.slice(0, at) + insert + host.slice(at);
  return { text, start: at, end: at + insert.length };
}

/** Offsets after each newline, plus the start and end. */
function seamOffsets(host: string): number[] {
  const seams = [0];
  for (let i = 0; i < host.length; i++) {
    if (host[i] === '\n') seams.push(i + 1);
  }
  seams.push(host.length);
  return seams;
}

/** Base64 without pulling in a dependency; the corpus must be reproducible. */
function toBase64(input: string): string {
  const bytes = new TextEncoder().encode(input);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1] ?? 0;
    const b2 = bytes[i + 2] ?? 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;
    out += alphabet[(triple >> 18) & 63];
    out += alphabet[(triple >> 12) & 63];
    out += i + 1 < bytes.length ? alphabet[(triple >> 6) & 63] : '=';
    out += i + 2 < bytes.length ? alphabet[triple & 63] : '=';
  }
  return out;
}
