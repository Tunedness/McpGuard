/**
 * The encoded-payload detector.
 *
 * "Contains base64" is worthless — every tool result has JWTs, hashes, PEM
 * blocks and minified assets. The value is entirely in the rejection gates,
 * which run before any decoding: a candidate that is a known digest length, a
 * digest-named JSON field, or an image data URL is skipped without a decode.
 * What survives is decoded once, checked for printability, and — only if it
 * reads like text — re-scanned with the signature and imperative detectors, so
 * the family scores on what the hidden instruction says, never on the fact that
 * something was encoded.
 */
import type { Normalized } from '../normalize/index.js';
import { normalize } from '../normalize/index.js';
import type { CompiledRules } from '../ruleset/compile.js';
import type { CompiledLexicons } from '../ruleset/load.js';
import type { Finding } from '../types.js';
import { detectImperative } from './imperative.js';
import { detectSignatures } from './signature.js';

const MAX_DECODE_BYTES = 8_192;
const MAX_CANDIDATES = 32;

/** Finds instructions hidden inside an encoded run. */
export function detectEncoding(
  normalized: Normalized,
  rules: CompiledRules,
  lexicons: CompiledLexicons,
): Finding[] {
  const raw = normalized.raw;
  const candidates = [...raw.matchAll(/[A-Za-z0-9+/=_-]{24,}/g)];
  const findings: Finding[] = [];
  let decoded = 0;

  for (const candidate of candidates) {
    if (decoded >= MAX_CANDIDATES) break;
    const value = candidate[0];
    const at = candidate.index ?? 0;
    if (value.length > MAX_DECODE_BYTES) continue;
    if (shouldSkip(raw, at, value)) continue;

    const text = decodeBase64(value);
    if (text === undefined || !looksLikeText(text)) continue;
    decoded++;

    // Re-scan the decoded text. A hidden instruction is more suspicious than a
    // stated one, so its findings are weighted up.
    const inner = normalize(text, 'text/plain');
    const nested = [
      ...detectSignatures(inner, rules, 'tool_result'),
      ...detectImperative(inner, lexicons),
    ];
    for (const finding of nested) {
      findings.push({
        ruleId: finding.ruleId,
        family: 'encoding',
        severity: finding.severity === 'low' ? 'medium' : finding.severity,
        weight: Math.min(1000, Math.floor((finding.weight * 5) / 4)),
        span: { start: at, end: at + value.length },
        evidence: `base64 → ${finding.evidence}`,
        viaDecode: 'base64',
      });
    }
  }

  return findings;
}

/** The cheap rejections, all before any decode. */
function shouldSkip(raw: string, at: number, value: string): boolean {
  // Pure hex at a digest length: sha family, md5, etc.
  if (/^[0-9a-f]+$/i.test(value) && [32, 40, 64, 96, 128].includes(value.length)) return true;
  // Inside an image or font data URL.
  const prefix = raw.slice(Math.max(0, at - 24), at);
  if (/data:(image|font)\//.test(prefix)) return true;
  // In a JSON field whose name says it is a digest, key, token or signature.
  const before = raw.slice(Math.max(0, at - 48), at);
  if (
    /"(sha\d*|hash|digest|etag|signature|sig|nonce|iv|salt|key|cert|thumbprint|checksum)"\s*:\s*"?$/i.test(
      before,
    )
  ) {
    return true;
  }
  // A JWT is three dot-separated segments; its header and payload are JSON, and
  // the signature is the third segment. Let the whole token through to decode —
  // the JSON body is exactly where an instruction could hide.
  return false;
}

/** Decodes a base64 / base64url run, or `undefined` if it is not valid. */
function decodeBase64(value: string): string | undefined {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const lookup = new Map<string, number>();
  for (let i = 0; i < alphabet.length; i++) lookup.set(alphabet[i] as string, i);
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of padded) {
    if (char === '=') break;
    const v = lookup.get(char);
    if (v === undefined) return undefined;
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  if (bytes.length === 0) return undefined;
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
  } catch {
    return undefined;
  }
}

/**
 * Whether decoded bytes read like text rather than a binary blob.
 *
 * Three-part test: mostly printable, a plausible amount of whitespace, and at
 * least one run of letters. Random bytes fail all three, which is what keeps the
 * false-positive base of this family near zero.
 */
function looksLikeText(text: string): boolean {
  if (text.length < 6) return false;
  let printable = 0;
  let spaces = 0;
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    if (code === 0x20 || code === 0x0a || code === 0x09) spaces++;
    if (code >= 0x20 && code !== 0x7f) printable++;
  }
  const printableRatio = printable / text.length;
  const spaceRatio = spaces / text.length;
  return (
    printableRatio >= 0.85 &&
    spaceRatio >= 0.02 &&
    spaceRatio <= 0.4 &&
    /[a-zçğışöü]{3,}/i.test(text)
  );
}
