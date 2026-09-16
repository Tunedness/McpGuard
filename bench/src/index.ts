/**
 * `@mcpguard/bench` — the corpus, the replay harness and the latency harness.
 *
 * Private and never published. It exists so the numbers in the product
 * requirements are measurements rather than intentions, and so CI can fail when
 * they move.
 */
export { generateCorpus, SEED, splitOf, toJsonl } from './injection/corpus.js';
export { optionsAt, replay } from './injection/replay.js';
export { metricsAt, partition, sweep } from './injection/sweep.js';
export type { CorpusItem } from './injection/types.js';
