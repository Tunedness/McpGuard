/**
 * Splitting text into clauses, for the imperative detector.
 *
 * Not a sentence tokeniser — clause boundaries are what matter, because an
 * injected instruction is usually one clause grafted onto ordinary text. Splits
 * on line breaks and on `. ! ? : ; \n`, with a short abbreviation guard so a
 * version number or `e.g.` does not start a new clause.
 */

/** One clause, with its raw offset so a finding can point at it. */
export interface Clause {
  readonly text: string;
  readonly start: number;
}

const ABBREVIATIONS = new Set([
  'e.g',
  'i.e',
  'etc',
  'vs',
  'no',
  'vb',
  'bkz',
  'ör',
  'dr',
  'mr',
  'mrs',
  'ms',
]);

/** Splits raw text into clauses. Empty clauses are dropped. */
export function splitClauses(raw: string): Clause[] {
  const clauses: Clause[] = [];
  let start = 0;
  for (let i = 0; i < raw.length; i++) {
    const char = raw[i];
    const isBreak = char === '\n' || char === '!' || char === '?' || char === ';' || char === ':';
    const isPeriod = char === '.';
    if (!isBreak && !isPeriod) continue;
    if (isPeriod) {
      // Guard against abbreviations and decimals: a period between two digits,
      // or after a known abbreviation, does not end a clause.
      const prev = raw[i - 1];
      const next = raw[i + 1];
      if (prev !== undefined && next !== undefined && /\d/.test(prev) && /\d/.test(next)) continue;
      const word = raw.slice(start, i).trimStart().split(/\s+/).pop()?.toLowerCase() ?? '';
      if (ABBREVIATIONS.has(word)) continue;
    }
    const text = raw.slice(start, i).trim();
    if (text.length > 0) clauses.push({ text, start: leadingOffset(raw, start, i) });
    start = i + 1;
  }
  const tail = raw.slice(start).trim();
  if (tail.length > 0) clauses.push({ text: tail, start: leadingOffset(raw, start, raw.length) });
  return clauses;
}

/** The offset of the first non-space character in `raw[from:to]`. */
function leadingOffset(raw: string, from: number, to: number): number {
  let i = from;
  while (i < to && /\s/.test(raw[i] ?? '')) i++;
  return i;
}
