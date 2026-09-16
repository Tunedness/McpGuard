/**
 * Structural anomaly: cheap corroborators, weight-capped, never standalone.
 *
 * None of these is enough on its own — the combiner caps the family low — but
 * each is a real signal that raises a borderline verdict: CSS that hides
 * directive text, an HTML comment carrying an instruction, and the data-appendix
 * shape where a clean payload is followed by a command.
 */
import type { Normalized } from '../normalize/index.js';
import type { Finding } from '../types.js';
import { evidenceOf } from './evidence.js';

const HIDDEN_CSS =
  /(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|aria-hidden\s*=\s*["']?true)/i;
const IMPERATIVE_HINT = /\b(ignore|disregard|reveal|send|delete|yok say|göster|gönder|sil)\b/i;

export function detectAnomaly(normalized: Normalized): Finding[] {
  const raw = normalized.raw;
  const findings: Finding[] = [];

  // Directive text wrapped in a hiding style.
  const css = HIDDEN_CSS.exec(raw);
  if (css !== null) {
    const start = css.index;
    const window = raw.slice(start, start + 300);
    if (IMPERATIVE_HINT.test(window)) {
      findings.push({
        ruleId: 'anomaly.css-hidden',
        family: 'anomaly',
        severity: 'high',
        weight: 480,
        span: { start, end: start + css[0].length },
        evidence: evidenceOf(raw, { start, end: start + css[0].length }),
      });
    }
  }

  // An HTML comment carrying an instruction.
  for (const region of normalized.shape.regions) {
    if (region.kind !== 'comment') continue;
    const text = raw.slice(region.start, region.end);
    if (IMPERATIVE_HINT.test(text)) {
      findings.push({
        ruleId: 'anomaly.comment-directive',
        family: 'anomaly',
        severity: 'low',
        weight: 300,
        span: { start: region.start, end: region.end },
        evidence: evidenceOf(raw, { start: region.start, end: region.end }),
      });
    }
  }

  // The data-appendix shape: a large clean prefix, then imperative text at the
  // tail. Cheap to check and the family the corpus tests with `data-appendix`.
  if (raw.length > 120) {
    const head = raw.slice(0, Math.floor(raw.length * 0.8));
    const tail = raw.slice(Math.floor(raw.length * 0.8));
    const headStructured =
      /^[\s]*[[{]/.test(head) || head.split('\n').every((l) => l.includes(',') || l.trim() === '');
    if (
      headStructured &&
      IMPERATIVE_HINT.test(tail) &&
      /\b(the assistant|note for|now|şimdi)\b/i.test(tail)
    ) {
      const start = raw.length - tail.length;
      findings.push({
        ruleId: 'anomaly.data-appendix',
        family: 'anomaly',
        severity: 'medium',
        weight: 360,
        span: { start, end: raw.length },
        evidence: evidenceOf(raw, { start, end: raw.length }),
      });
    }
  }

  return findings;
}
