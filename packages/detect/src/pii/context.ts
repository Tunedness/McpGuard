/**
 * Keyword context for the recognisers that have no checksum.
 *
 * The words live in the ruleset (`@tunedness/mcpguard-ruleset/pii/`) as data and
 * are matched here as plain tokens. No pattern is ever built from them: a list
 * of words cannot backtrack, so editing the data cannot introduce a ReDoS, and
 * the compiled form is the same on every platform.
 *
 * Matching folds both sides the same way — lower case, Turkish letters to their
 * ASCII base — so `Reçete No`, `RECETE NO` and `recete no` are one phrase. The
 * fold keeps every offset, so a hit in the folded text is a hit in the raw text.
 */
import { sha256 } from '../util/hash.js';
import { stableStringify, toJsonValue } from '../util/json.js';
import type { HealthKind } from './kinds.js';

/** The keyword lists the recognisers read, as the ruleset's `pii` section carries them. */
export interface PiiData {
  /** Which recognisers each profile switches on. */
  readonly profiles: { readonly health: readonly HealthKind[] };
  /** Words that must precede a reference number. */
  readonly anchors: { readonly health_ref: readonly string[] };
  /** Words that must sit beside a value for it to be PII. */
  readonly context: {
    readonly health_date: readonly string[];
    readonly ssn_us: readonly string[];
    readonly icd10: readonly string[];
    readonly gs1_serial: readonly string[];
  };
  /**
   * Words that say a keyword hit is not clinical: a courier's tracking number,
   * a Kubernetes admission webhook. A candidate with one of them beside it is
   * not masked.
   */
  readonly exclude: {
    readonly health_ref: readonly string[];
    readonly health_date: readonly string[];
  };
  /**
   * Words that make a keyword unambiguously clinical (`reçete`, `hasta`, `patient`,
   * `date of birth`...). An anchor or context phrase that contains one is not
   * overridden by an exclusion word; only an ambiguous one (`takip no`,
   * `rapor no`, `admission`) is.
   */
  readonly strong: {
    readonly health_ref: readonly string[];
    readonly health_date: readonly string[];
  };
  /** Words a profile adds to a base recogniser's own context. */
  readonly profileContext: {
    readonly tckn: readonly string[];
    readonly phone: readonly string[];
  };
}

/** The keyword lists, by the recogniser that reads them. */
export type ContextKey =
  | 'health_ref'
  | 'health_date'
  | 'ssn_us'
  | 'icd10'
  | 'gs1_serial'
  | 'exclude_health_ref'
  | 'exclude_health_date'
  | 'strong_health_ref'
  | 'strong_health_date'
  | 'profile_tckn'
  | 'profile_phone';

/** A phrase index: first token → the phrases (as token lists) that start with it. */
type PhraseIndex = ReadonlyMap<string, readonly (readonly string[])[]>;

/** The PII section of a ruleset, validated, digested and indexed. */
export interface CompiledPiiData {
  /** Digest over this data alone; the ruleset's own `digest` does not cover it (ADR-012). */
  readonly digest: string;
  readonly profiles: { readonly health: readonly HealthKind[] };
  readonly phrases: Readonly<Record<ContextKey, PhraseIndex>>;
}

/** A recogniser was asked for but the ruleset carries no PII data for it. */
export class PiiDataMissingError extends Error {
  constructor(what: string) {
    super(
      `${what} needs the ruleset's pii section, and this ruleset has none — load a ruleset that ships pii data`,
    );
    this.name = 'PiiDataMissingError';
  }
}

// `#` is a token of its own so a phrase can say `claim #`; every other symbol is a separator.
const TOKEN = /[\p{L}\p{N}]+|#/gu;

const TR_FOLD: Readonly<Record<string, string>> = {
  ç: 'c',
  ğ: 'g',
  ı: 'i',
  ö: 'o',
  ş: 's',
  ü: 'u',
  â: 'a',
  î: 'i',
  û: 'u',
};

function foldChar(ch: string): string {
  // `İ` lower-cases to two code units; it is the one character whose fold would
  // otherwise shift every offset after it.
  if (ch === 'İ') return 'i';
  const lower = ch.toLowerCase();
  const same = lower.length === ch.length ? lower : ch;
  return TR_FOLD[same] ?? same;
}

/** Lower-cases and ASCII-folds Turkish letters, keeping the length and every offset. */
export function foldText(text: string): string {
  let out = '';
  for (const ch of text) out += foldChar(ch);
  return out;
}

function tokensOf(folded: string): string[] {
  return [...folded.matchAll(TOKEN)].map((m) => m[0]);
}

function indexPhrases(words: readonly string[]): PhraseIndex {
  const index = new Map<string, string[][]>();
  for (const word of words) {
    const tokens = tokensOf(foldText(word));
    const first = tokens[0];
    if (first === undefined) continue;
    const list = index.get(first) ?? [];
    list.push(tokens);
    index.set(first, list);
  }
  return index;
}

/** Digests and indexes the ruleset's PII section. */
export function compilePiiData(data: PiiData): CompiledPiiData {
  return {
    digest: sha256(stableStringify(toJsonValue(data))),
    profiles: { health: [...data.profiles.health] },
    phrases: {
      health_ref: indexPhrases(data.anchors.health_ref),
      health_date: indexPhrases(data.context.health_date),
      ssn_us: indexPhrases(data.context.ssn_us),
      icd10: indexPhrases(data.context.icd10),
      gs1_serial: indexPhrases(data.context.gs1_serial),
      exclude_health_ref: indexPhrases(data.exclude.health_ref),
      exclude_health_date: indexPhrases(data.exclude.health_date),
      strong_health_ref: indexPhrases(data.strong.health_ref),
      strong_health_date: indexPhrases(data.strong.health_date),
      profile_tckn: indexPhrases(data.profileContext.tckn),
      profile_phone: indexPhrases(data.profileContext.phone),
    },
  };
}

/** One place a keyword phrase occurs, in raw offsets. */
export interface Occurrence {
  readonly start: number;
  readonly end: number;
}

interface Token {
  readonly text: string;
  readonly start: number;
  readonly end: number;
}

/** The most separator characters allowed between two tokens of one phrase. */
const MAX_PHRASE_GAP = 3;

/** How far before a candidate an occurrence can start and still reach it. */
const REACH = 160;

/**
 * One item's text, tokenised once and queried per recogniser.
 *
 * Built only when a recogniser that needs keyword context is on, so a scan with
 * the profile off never pays for it.
 */
export class PiiText {
  readonly raw: string;
  readonly #data: CompiledPiiData | undefined;
  #tokens: Token[] | undefined;
  readonly #cache = new Map<ContextKey, Occurrence[]>();

  constructor(raw: string, data: CompiledPiiData | undefined) {
    this.raw = raw;
    this.#data = data;
  }

  /** Every occurrence of a keyword phrase for `key`, ordered by start. */
  occurrences(key: ContextKey): readonly Occurrence[] {
    const cached = this.#cache.get(key);
    if (cached !== undefined) return cached;
    if (this.#data === undefined) throw new PiiDataMissingError(`the ${key} keywords`);
    const index = this.#data.phrases[key];
    const tokens = this.#tokenise();
    const found: Occurrence[] = [];
    for (let i = 0; i < tokens.length; i++) {
      const first = tokens[i];
      const phrases = first === undefined ? undefined : index.get(first.text);
      if (first === undefined || phrases === undefined) continue;
      for (const phrase of phrases) {
        const last = this.#matchAt(tokens, i, phrase);
        if (last !== undefined) found.push({ start: first.start, end: last.end });
      }
    }
    this.#cache.set(key, found);
    return found;
  }

  /**
   * Whether a keyword for `key` sits within `before` characters ahead of
   * `[start, end)` or `after` characters behind it.
   */
  near(key: ContextKey, start: number, end: number, before: number, after: number): boolean {
    const found = this.occurrences(key);
    let lo = 0;
    let hi = found.length;
    const floor = start - before - REACH;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if ((found[mid]?.start ?? 0) < floor) lo = mid + 1;
      else hi = mid;
    }
    for (let i = lo; i < found.length; i++) {
      const occ = found[i];
      if (occ === undefined || occ.start > end + after) break;
      if (occ.end <= start && start - occ.end <= before) return true;
      if (occ.start >= end && occ.start - end <= after) return true;
    }
    return false;
  }

  /** Every keyword occurrence for `key` within the window of `[start, end)`, as {@link near} reads it. */
  nearOccurrences(
    key: ContextKey,
    start: number,
    end: number,
    before: number,
    after: number,
  ): Occurrence[] {
    const found = this.occurrences(key);
    const hits: Occurrence[] = [];
    for (let i = this.#lowerBound(found, start - before - REACH); i < found.length; i++) {
      const occ = found[i];
      if (occ === undefined || occ.start > end + after) break;
      if (
        (occ.end <= start && start - occ.end <= before) ||
        (occ.start >= end && occ.start - end <= after)
      ) {
        hits.push(occ);
      }
    }
    return hits;
  }

  /** Whether an occurrence of `key` lies wholly inside `outer`. */
  contains(key: ContextKey, outer: Occurrence): boolean {
    const found = this.occurrences(key);
    for (let i = this.#lowerBound(found, outer.start); i < found.length; i++) {
      const occ = found[i];
      if (occ === undefined || occ.start >= outer.end) break;
      if (occ.end <= outer.end) return true;
    }
    return false;
  }

  #lowerBound(found: readonly Occurrence[], floor: number): number {
    let lo = 0;
    let hi = found.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if ((found[mid]?.start ?? 0) < floor) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  #tokenise(): Token[] {
    if (this.#tokens === undefined) {
      const folded = foldText(this.raw);
      this.#tokens = [...folded.matchAll(TOKEN)].map((m) => ({
        text: m[0],
        start: m.index ?? 0,
        end: (m.index ?? 0) + m[0].length,
      }));
    }
    return this.#tokens;
  }

  #matchAt(tokens: readonly Token[], at: number, phrase: readonly string[]): Token | undefined {
    let prev: Token | undefined;
    for (let k = 0; k < phrase.length; k++) {
      const token = tokens[at + k];
      if (token === undefined || token.text !== phrase[k]) return undefined;
      if (prev !== undefined && token.start - prev.end > MAX_PHRASE_GAP) return undefined;
      prev = token;
    }
    return prev;
  }
}
