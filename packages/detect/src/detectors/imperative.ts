/**
 * The imperative-mood detector: deterministic, no NLP model.
 *
 * A tool result is data; a clause that gives the reader a second-person command
 * is an anomaly in data. This is not part-of-speech tagging — it is a
 * closed-lexicon, morphology-aware clause classifier, and the lexicons are data
 * in the ruleset.
 *
 * It is the highest-false-positive family there is: README files, CLI help,
 * error messages telling you which command to run, and — in the primary market —
 * Turkish support and administrative prose, which is thick with polite
 * imperatives. So its cap in the score combiner is the lowest of any family and
 * it can never carry a block on its own. What it emits is corroboration: enough
 * to flag, never enough to stop traffic alone.
 */

import type { Clause, Normalized } from '../normalize/index.js';
import type { CompiledLexicons } from '../ruleset/load.js';
import type { Finding } from '../types.js';
import { evidenceOf } from './evidence.js';

/** English adverbs that may precede a verb-initial imperative. */
const EN_LEADING = new Set([
  'now',
  'immediately',
  'first',
  'then',
  'please',
  'kindly',
  'instead',
  'also',
  'quickly',
  'silently',
  'always',
  'never',
]);

/** English subject markers that mean a clause is not an imperative. */
const EN_SUBJECT = /^(the|a|an|it|this|these|there|we|i|you can|you may|users can|they)\b/;

/** English modal-directive openers, a second way in. */
const EN_MODAL =
  /^(you (must|should|need to|have to|are (required|instructed) to)|do not|never|always)\b/;

/** Turkish imperative / obligation suffixes on a clause's final verb. */
const TR_IMPERATIVE_SUFFIX =
  /(ma|me|maliyiz|meliyiz|malisin|melisin|meli|mali|iniz|ınız|unuz|ünüz|in|ın|un|ün|sin|sın|sun|sün)$/;

/** Turkish periphrastic obligation and prohibitive markers. */
const TR_OBLIGATION = /(zorundas|gerekiyor|gerekir|lazim|lazım|sakin|sakın)\b/;

/** The finding this detector emits, if it emits one. */
export function detectImperative(normalized: Normalized, lexicons: CompiledLexicons): Finding[] {
  const clauses = normalized.clauses;
  if (clauses.length === 0) return [];

  const turkish = looksTurkish(normalized.folded.text);
  let imperativeCount = 0;
  let capabilityCount = 0;
  let secondPerson = false;
  let firstSpan: { start: number; end: number } | undefined;

  for (const clause of clauses) {
    if (isBenign(clause.text.toLowerCase(), lexicons)) continue;
    const verdict = turkish ? classifyTurkish(clause, lexicons) : classifyEnglish(clause, lexicons);
    if (verdict === 'none') continue;
    imperativeCount++;
    if (verdict === 'capability') capabilityCount++;
    if (mentionsSecondPerson(clause.text.toLowerCase(), turkish)) secondPerson = true;
    if (firstSpan === undefined) {
      firstSpan = { start: clause.start, end: clause.start + clause.text.length };
    }
  }

  if (firstSpan === undefined) return [];

  const density = imperativeCount / clauses.length;
  // Fires meaningfully at two imperatives with real density, or one that both
  // addresses the reader and is not in a doc-shaped item.
  const fires =
    (imperativeCount >= 2 && density >= 0.25) ||
    (imperativeCount >= 1 && secondPerson && !normalized.shape.docLike);
  if (!fires) return [];

  // Weight rises with capability verbs (imperatives that name an agent action)
  // and with density, but is bounded well under the block band by the family
  // cap in the combiner. A pure count of polite imperatives lands low.
  const capabilityRatio = imperativeCount === 0 ? 0 : capabilityCount / imperativeCount;
  const weight = clampWeight(260 + Math.round(capabilityRatio * 280) + Math.round(density * 160));

  return [
    {
      ruleId: `imperative.${turkish ? 'tr' : 'en'}`,
      family: 'imperative',
      severity: capabilityCount > 0 ? 'medium' : 'low',
      weight,
      span: firstSpan,
      evidence: evidenceOf(normalized.raw, firstSpan),
    },
  ];
}

type ClauseVerdict = 'none' | 'imperative' | 'capability';

function classifyEnglish(clause: Clause, lexicons: CompiledLexicons): ClauseVerdict {
  const words = clause.text
    .toLowerCase()
    .replace(/^[-*\d.)\s]+/, '')
    .split(/\s+/);
  let i = 0;
  while (i < words.length && EN_LEADING.has(words[i] ?? '')) i++;
  const head = words[i];
  if (head === undefined) return 'none';
  const lowered = clause.text.toLowerCase();
  if (EN_SUBJECT.test(lowered)) {
    // A modal directive still counts even with a subject: "you must delete".
    return EN_MODAL.test(lowered) && hasCapability(words, lexicons) ? 'capability' : 'none';
  }
  if (lexicons.verbsEn.has(head)) {
    return lexicons.verbsEn.has(head) ? 'capability' : 'imperative';
  }
  if (EN_MODAL.test(lowered)) {
    return hasCapability(words, lexicons) ? 'capability' : 'imperative';
  }
  return 'none';
}

function classifyTurkish(clause: Clause, lexicons: CompiledLexicons): ClauseVerdict {
  const lowered = clause.text.toLowerCase();
  if (TR_OBLIGATION.test(lowered)) {
    return hasTurkishCapability(lowered, lexicons) ? 'capability' : 'imperative';
  }
  const words = lowered.replace(/^[-*\d.)\s]+/, '').split(/\s+/);
  const last = words[words.length - 1]?.replace(/[.,!?;:]+$/, '') ?? '';
  // Bare stem imperative: the final word is itself an action stem.
  if (lexicons.verbsTr.has(last)) return 'capability';
  // Inflected imperative: the final word starts with an action stem and ends in
  // an imperative/obligation suffix.
  for (const stem of lexicons.verbsTr) {
    if (last.startsWith(stem) && last.length > stem.length && TR_IMPERATIVE_SUFFIX.test(last)) {
      return 'capability';
    }
  }
  return 'none';
}

function hasCapability(words: readonly string[], lexicons: CompiledLexicons): boolean {
  return words.some((word) => lexicons.verbsEn.has(word));
}

function hasTurkishCapability(text: string, lexicons: CompiledLexicons): boolean {
  return [...lexicons.verbsTr].some((stem) => text.includes(stem));
}

function mentionsSecondPerson(text: string, turkish: boolean): boolean {
  if (turkish) {
    // Turkish marks the second person on the verb as well as with a pronoun.
    // `-sin`/`-siniz` (imperative/present) and the possessive `-nız` are all the
    // addressee showing up, which is what distinguishes a command from a
    // description even when there is no `sen`/`siz`.
    return (
      /\b(sen|siz|senin|sizin)\b/.test(text) ||
      /(nız|niz|nuz|nüz)\b/.test(text) ||
      /(sın|sin|sun|sün|siniz|sınız|sunuz|sünüz)\b/.test(text)
    );
  }
  return /\byou\b|\byour\b/.test(text);
}

function isBenign(lowered: string, lexicons: CompiledLexicons): boolean {
  return lexicons.benignImperatives.some((phrase) => lowered.includes(phrase));
}

/** Turkish-specific letters plus a small stopword probe decide the locale. */
function looksTurkish(text: string): boolean {
  const turkishLetters = (text.match(/[çğışöü]/g) ?? []).length;
  const trStop = (text.match(/\b(ve|bir|bu|için|ile|değil|olarak|sonra)\b/g) ?? []).length;
  const enStop = (text.match(/\b(the|and|for|with|not|then|your)\b/g) ?? []).length;
  return turkishLetters + trStop > enStop;
}

function clampWeight(value: number): number {
  return value < 0 ? 0 : value > 1000 ? 1000 : value;
}
