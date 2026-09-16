/**
 * Writes `bench/injection/corpus.jsonl`.
 *
 * `node dist/injection/generate.js`. The output is committed and pinned by
 * `corpus.test.ts`; CI runs this and `git diff --exit-code`s the result, so a
 * change to the generator that changes the corpus cannot land unnoticed.
 */
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateCorpus, toJsonl } from './corpus.js';

const here = dirname(fileURLToPath(import.meta.url));
const target = join(here, '..', '..', 'injection', 'corpus.jsonl');
const items = generateCorpus();
writeFileSync(target, toJsonl(items));
console.log(`wrote ${items.length} items to ${target}`);
