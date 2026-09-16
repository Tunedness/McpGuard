/**
 * The signature detector: literal, phrase and regex rules from the ruleset.
 *
 * Runs off the single automaton pass. Literals and phrase tokens and regex
 * prefilters are all terms in it, so one search over the folded surface finds
 * every candidate; phrase rules then confirm ordering off the token hits and
 * regexes run only on the segment their prefilter marked.
 *
 * The highest-false-positive input this detector sees is documentation quoting
 * an attack, so a hit inside quoted code is damped rather than scored full.
 */
import { search } from '../ac/aho-corasick.js';
import { inCode, type Normalized, rawSpan } from '../normalize/index.js';
import type { CompiledRules } from '../ruleset/compile.js';
import type { Rule } from '../ruleset/schema.js';
import { WEIGHT_SCALE } from '../score/combine.js';
import type { ContentKind, Finding } from '../types.js';
import { evidenceOf } from './evidence.js';

/** Finds every signature hit in one item. */
export function detectSignatures(
  normalized: Normalized,
  rules: CompiledRules,
  kind: ContentKind,
): Finding[] {
  const findings: Finding[] = [];
  // Two surfaces, searched separately so each hit knows which text it is on: the
  // skeleton fold catches deasciified and homoglyph spellings, the case fold
  // catches anything the skeleton fold would have flattened away.
  const surfaces: [string, ReturnType<typeof search>][] = [
    [normalized.skeleton, search(rules.automaton, normalized.skeleton)],
    [normalized.folded.text, search(rules.automaton, normalized.folded.text)],
  ];

  // Group phrase-token hits by rule so a phrase can confirm ordering without
  // scanning the text again. Each hit remembers its surface for the boundary
  // check the phrase matcher makes.
  const tokenHits = new Map<string, TokenHit[]>();

  for (const [text, hits] of surfaces) {
    for (const hit of hits) {
      if (hit.id.startsWith('lit:')) {
        const rule = rules.literalRules.get(hit.id);
        // A literal ending in punctuation (e.g. `.env`) has no leading letter to
        // anchor on, so the boundary check is skipped for those; otherwise a
        // literal must sit on word boundaries.
        const anchored = /^[\p{L}\p{N}]/u.test(hit.value);
        if (
          rule !== undefined &&
          applies(rule, kind) &&
          (!anchored || onBoundary(text, hit.start, hit.end, true))
        ) {
          pushFinding(findings, normalized, rule, hit.start, hit.end);
        }
      } else if (hit.id.startsWith('tok:')) {
        const ruleId = hit.id.split(':')[1] ?? '';
        const list = tokenHits.get(ruleId) ?? [];
        list.push({ token: hit.value, start: hit.start, end: hit.end, text });
        tokenHits.set(ruleId, list);
      } else if (hit.id.startsWith('pre:')) {
        const ruleId = hit.id.split(':')[1] ?? '';
        runRegexesFor(findings, normalized, rules, ruleId, hit.start, kind);
      }
    }
  }

  for (const phrase of rules.phrases) {
    if (!applies(phrase.rule, kind)) continue;
    const hits = tokenHits.get(phrase.rule.id);
    if (hits === undefined) continue;
    const span = confirmPhrase(phrase.tokens, phrase.maxGap, phrase.prefix, hits);
    if (span !== undefined) pushFinding(findings, normalized, phrase.rule, span.start, span.end);
  }

  return dedupe(findings);
}

function applies(rule: Rule, kind: ContentKind): boolean {
  return rule.contentKinds.includes(kind);
}

/** Whether a code unit is part of a word (so a match inside it is not a match). */
function isWordChar(char: string | undefined): boolean {
  if (char === undefined) return false;
  // Underscore is deliberately a boundary, not a word character: `API_KEY` and
  // `send_email` are two words to a reader, and a rule for `key` should match
  // inside `API_KEY` while still not matching inside `keys`.
  return /[\p{L}\p{N}]/u.test(char);
}

/**
 * Whether a match at `[start, end)` sits on word boundaries.
 *
 * The automaton matches substrings, so `key` is found inside `keys` and `monkey`
 * alike. A leading boundary is always required; a trailing boundary is required
 * only for an exact token, because a prefix token is meant to match the start of
 * an inflected word — `talimat` inside `talimatları` is the whole point.
 */
function onBoundary(text: string, start: number, end: number, requireTrailing: boolean): boolean {
  if (isWordChar(text[start - 1])) return false;
  if (requireTrailing && isWordChar(text[end])) return false;
  return true;
}

/** One phrase-token hit, with the surface it was found on for boundary checks. */
interface TokenHit {
  readonly token: string;
  readonly start: number;
  readonly end: number;
  readonly text: string;
}

/** Confirms an ordered token sequence within a gap, returning its span. */
function confirmPhrase(
  tokens: readonly string[],
  maxGap: number,
  prefix: boolean,
  hits: readonly TokenHit[],
): { start: number; end: number } | undefined {
  const sorted = [...hits].sort((a, b) => a.start - b.start);
  let start: number | undefined;
  let cursor = -1;
  let tokenIndex = 0;
  for (const hit of sorted) {
    const want = tokens[tokenIndex];
    if (want === undefined) continue;
    // The token has to be this rule's token and has to sit on a word boundary:
    // a leading boundary always, a trailing one for an exact token, because a
    // prefix token deliberately matches the start of an inflected word.
    const isToken = prefix
      ? hit.token.startsWith(want) || want.startsWith(hit.token)
      : hit.token === want;
    const matches = isToken && onBoundary(hit.text, hit.start, hit.end, !prefix);
    if (!matches) continue;
    // The gap is counted in characters between token hits: the next token must
    // begin within maxGap+1 words of the previous, approximated at 24 chars a
    // word, which is generous and needs no second tokenisation.
    if (cursor >= 0 && hit.start - cursor > (maxGap + 1) * 24) {
      if (want === tokens[0]) {
        start = hit.start;
        cursor = hit.end;
        tokenIndex = 1;
      }
      continue;
    }
    if (tokenIndex === 0) start = hit.start;
    cursor = hit.end;
    tokenIndex++;
    if (tokenIndex === tokens.length) {
      return start === undefined ? undefined : { start, end: hit.end };
    }
  }
  return undefined;
}

/** Runs the regex rules a prefilter gates, on a window around the hit. */
function runRegexesFor(
  findings: Finding[],
  normalized: Normalized,
  rules: CompiledRules,
  ruleId: string,
  prefilterAt: number,
  kind: ContentKind,
): void {
  for (const compiled of rules.regexRules.values()) {
    for (const entry of compiled) {
      if (entry.rule.id !== ruleId || !applies(entry.rule, kind)) continue;
      const from = Math.max(0, prefilterAt - 2_048);
      const to = Math.min(normalized.folded.text.length, prefilterAt + 2_048);
      const segment = normalized.folded.text.slice(from, to);
      // `entry.regex` was compiled without a global or sticky flag, so `exec` is
      // stateless and needs no fresh cursor.
      const match = entry.regex.exec(segment);
      if (match !== null) {
        pushFinding(
          findings,
          normalized,
          entry.rule,
          from + match.index,
          from + match.index + match[0].length,
        );
      }
    }
  }
}

function pushFinding(
  findings: Finding[],
  normalized: Normalized,
  rule: Rule,
  foldedStart: number,
  foldedEnd: number,
): void {
  const span = rawSpan(normalized.folded.offsets, foldedStart, foldedEnd);
  const quoted = inCode(normalized.shape.regions, span.start);
  // A hit in quoted code is documentation quoting an attack far more often than
  // an attack, so it is damped here. Doc-shape damping is applied centrally in
  // the combiner, which also collapses the multiplicity a quoting document
  // creates — so it is deliberately not repeated per finding.
  let weight = rule.weight;
  if (quoted) weight = Math.floor((weight * rule.quotedDamping) / WEIGHT_SCALE);
  findings.push({
    ruleId: rule.id,
    family: 'signature',
    severity: rule.severity,
    weight,
    span,
    evidence: evidenceOf(normalized.raw, span),
  });
}

/** Keeps one finding per (rule, raw span). */
function dedupe(findings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.span.start}:${finding.span.end}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding);
  }
  return out;
}
