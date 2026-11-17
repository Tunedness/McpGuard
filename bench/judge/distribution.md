# McpGuard — tier-1 scores of paraphrased injections, and what each `band_from` costs

Ruleset 0.1.0, scan defaults (`flag_at` 40, `block_at` 70). 64 hand-written
paraphrases of the corpus's attack intents, English and Turkish (`bench/src/judge/paraphrases.ts`),
scored by the real engine. Reproduce with `npm run bench:judge`; no model is needed.

## V5 REFUTED: 89.1% of the 64 leaks score exactly 0 (limit 50%). No band_from above 0 reaches them; only band_from: 0 (judge every item) does.

A *leak* is a paraphrase tier 1 does not flag, a score below `flag_at`. Those are the items a judge is
for. The default `band_from` is `flag_at`, so by construction **the default band reaches no leak**: it
covers `[flag_at, block_at)` and the unconfirmed scores above it. Reaching leaks takes a lower
`band_from`, which is a choice about how many model calls to spend on benign traffic.

## Where the paraphrases score

| tier-1 score | paraphrases | share |
| --- | --- | --- |
| 0 | 57 | 89.1% |
| 1-19 | 0 | 0.0% |
| 20-39 | 7 | 10.9% |
| 40-69 (band) | 0 | 0.0% |
| 70+ confirmed | 0 | 0.0% |
| 70+ unconfirmed (band) | 0 | 0.0% |

64 of 64 score below `flag_at` (leaks); 57 of those score exactly 0.

| family | n | leaks | at 0 |
| --- | --- | --- | --- |
| credential-request | 8 | 8 | 5 |
| data-appendix | 8 | 8 | 8 |
| direct-override | 8 | 8 | 8 |
| exfil-tool | 8 | 8 | 7 |
| exfil-url | 8 | 8 | 8 |
| persistence | 8 | 8 | 7 |
| role-switch | 8 | 8 | 6 |
| task-redirect | 8 | 8 | 8 |

| locale | n | leaks | at 0 |
| --- | --- | --- | --- |
| en | 32 | 32 | 27 |
| tr | 32 | 32 | 30 |

## What each `band_from` costs

Judge calls are made for the items in the band. "Benign in band" is the share of the corpus's 400 benign
items that would be sent to the model: the price of reaching the leaks column.

| band_from | leaks reached | paraphrases in band | benign items in band |
| --- | --- | --- | --- |
| 40 (default: flag_at) | 0/64 | 0/64 | 0/400 (0.0%) |
| 30 | 0/64 | 0/64 | 25/400 (6.3%) |
| 20 | 7/64 | 7/64 | 77/400 (19.3%) |
| 10 | 7/64 | 7/64 | 77/400 (19.3%) |
| 1 | 7/64 | 7/64 | 77/400 (19.3%) |
| 0 | 64/64 | 64/64 | 400/400 (100.0%) |

## How far to trust this

One author wrote the 64 paraphrases, after reading the ruleset's family names, and the corpus's benign
items are the ones the ruleset was calibrated against. This measures a *shape*: whether paraphrases pile
at zero or spread below `flag_at`. It does not measure a rate in the wild, and 64 items do not support one.
Whether a model catches what tier 1 misses is a different measurement (`--endpoint`), and is not made here.
