/**
 * Writes `bench/phi/corpus.jsonl`.
 *
 * `node dist/phi/generate.js`. The output is committed and pinned by
 * `corpus.test.ts`; CI runs this and `git diff --exit-code`s the result, so a
 * change to the generator that changes the corpus cannot land unnoticed.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateCorpus, toJsonl } from './corpus.js';

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '..', '..', 'phi');
mkdirSync(dir, { recursive: true });
const target = join(dir, 'corpus.jsonl');
const items = generateCorpus();
writeFileSync(target, toJsonl(items));
console.log(`wrote ${items.length} items to ${target}`);
