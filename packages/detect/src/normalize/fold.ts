/**
 * Case folding and the skeleton fold, done deterministically.
 *
 * Two traps make the platform's built-ins unusable here.
 *
 * `String.prototype.toLowerCase()` maps `I`→`i`, which is wrong in Turkish, and
 * `toLocaleLowerCase('tr')` reads the ICU build, so its result varies across
 * Node distributions — and this package's whole promise is that the same input
 * folds the same way everywhere (ADR-009). So the six Turkish letters are folded
 * from an explicit table and everything else goes through `toLowerCase()`.
 *
 * `İ` (U+0130) is the sharp one: `toLowerCase()` turns it into two code points,
 * `i` + a combining dot, which shifts every offset after it. The table folds it
 * to a single `i`, and the offset map records the one place a character was
 * dropped so a span still lands where a human put it.
 */

/** Turkish letters, upper and lower, folded to an ASCII-ish lower form. */
const TURKISH_FOLD: Record<string, string> = {
  İ: 'i',
  I: 'ı',
  // Uppercase homoglyphs fold to lowercase Latin first; the skeleton table then
  // has nothing left to do for them, but the case fold must not miss them.
  Ç: 'ç',
  Ğ: 'ğ',
  Ö: 'ö',
  Ş: 'ş',
  Ü: 'ü',
};

/**
 * The skeleton fold: strips Turkish diacritics for matching only.
 *
 * Turkish is routinely typed without diacritics — `gonder`, `talimatlari`,
 * `onceki` — so a ruleset authored in deasciified form matches both the
 * diacritic and the plain spelling. Applied on top of the case fold.
 */
const SKELETON: Record<string, string> = {
  ç: 'c',
  ğ: 'g',
  ı: 'i',
  ö: 'o',
  ş: 's',
  ü: 'u',
  â: 'a',
  î: 'i',
  û: 'u',
  // Common Cyrillic and Greek homoglyphs, folded to their Latin look-alikes.
  // An attacker swapping `o` for a Cyrillic `о` is hiding a word from a literal
  // match, not writing Russian; the skeleton fold is where that is undone.
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  у: 'y',
  і: 'i',
  х: 'x',
  ѕ: 's',
  ԁ: 'd',
  ο: 'o',
  ρ: 'p',
  ν: 'v',
};

/** A folded string plus the map back to the raw text's offsets. */
export interface Folded {
  /** The folded text. */
  readonly text: string;
  /** `offsets[i]` is the raw UTF-16 offset the folded character at `i` came from. */
  readonly offsets: readonly number[];
}

/**
 * Case-folds, Turkish-aware, and records where each folded character came from.
 *
 * NFC-normalises first so a precomposed and a decomposed `ü` fold the same way.
 */
export function caseFold(raw: string): Folded {
  const source = raw.normalize('NFC');
  let text = '';
  const offsets: number[] = [];
  let rawIndex = 0;
  for (const char of source) {
    const folded = TURKISH_FOLD[char] ?? char.toLowerCase();
    for (const piece of folded) {
      text += piece;
      // Every folded code unit points back at the start of the raw character it
      // came from. A fold that expands (it should not, given the table) still
      // yields offsets a slice can use.
      offsets.push(rawIndex);
    }
    rawIndex += char.length;
  }
  return { text, offsets };
}

/** Applies the skeleton fold to already case-folded text, preserving length. */
export function skeletonFold(folded: string): string {
  let out = '';
  for (const char of folded) {
    out += SKELETON[char] ?? char;
  }
  return out;
}

/**
 * The raw span a folded span maps back to.
 *
 * The skeleton fold is length-preserving and the case fold's table never
 * expands, so a folded `[start, end)` maps to `[offsets[start], offsets[end-1]+1)`
 * — clamped, because an empty or trailing span must still produce a usable range.
 */
export function rawSpan(
  offsets: readonly number[],
  start: number,
  end: number,
): {
  start: number;
  end: number;
} {
  if (offsets.length === 0) return { start: 0, end: 0 };
  const clampedStart = Math.max(0, Math.min(start, offsets.length - 1));
  const clampedEnd = Math.max(clampedStart, Math.min(end, offsets.length));
  const rawStart = offsets[clampedStart] ?? 0;
  const last = offsets[clampedEnd - 1];
  const rawEnd = last === undefined ? rawStart : last + 1;
  return { start: rawStart, end: rawEnd };
}
