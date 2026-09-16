# McpGuard — injection detection benchmark

Corpus: 700 labelled content items. Operating point chosen on the
calibration split, headline measured on the validation split.

## Chosen operating point

| flag_at | block_at | recall | false positives | precision | F1 | margin |
| --- | --- | --- | --- | --- | --- | --- |
| 80 | 70 | 0.0% | 0.0% | 1.000 | 0.000 | -79 |

## Verdict against PRD §6

- catch ≥ 95%:          NOT MET (0.0%) [validation split]
- false positives < 2%: MET (0.0%)

The detectors arrive in phases 4 and 5. This is the phase 3 baseline: the
ruleset is empty, so every verdict is `allow` and recall is 0%. The number is
real from the first run, which is the reason the corpus and this harness come
before the engine — the sibling tool froze a detection axis ahead of measuring
it and had to reopen the decision when no threshold on that axis could meet the
targets. Lowering a gate is never how a change is made to pass here; the gate is
the record of what was achieved.
