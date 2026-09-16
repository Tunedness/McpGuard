/**
 * A seeded generator, so the corpus is a file anyone can regenerate.
 *
 * mulberry32 over an FNV-1a seed. Nothing here is cryptographic and nothing
 * needs to be: the only requirement is that the same seed produces the same
 * bytes on every machine and every Node version, which `Math.random()` cannot
 * promise and a committed corpus depends on.
 */
export class Rng {
  #state: number;

  constructor(seed: string) {
    this.#state = fnv1a(seed);
  }

  /** The next float in [0, 1). */
  next(): number {
    this.#state = (this.#state + 0x6d2b79f5) | 0;
    let t = this.#state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  /** An integer in [0, bound). */
  int(bound: number): number {
    return Math.floor(this.next() * bound);
  }

  /** One element, chosen uniformly. */
  pick<T>(values: readonly T[]): T {
    const value = values[this.int(values.length)];
    if (value === undefined) throw new Error('pick() from an empty list');
    return value;
  }

  /** True with the given probability. */
  chance(probability: number): boolean {
    return this.next() < probability;
  }
}

function fnv1a(input: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}
