# McpGuard — injection detection benchmark

Corpus: 700 labelled content items. Operating point chosen on the
calibration split, headline measured on the validation split.

## Chosen operating point

| flag_at | block_at | recall | false positives | precision | F1 | margin |
| --- | --- | --- | --- | --- | --- | --- |
| 40 | 70 | 100.0% | 0.0% | 1.000 | 1.000 | 5 |

## Verdict against PRD §6

- catch ≥ 95%:          MET (100.0%) [validation split]
- false positives < 2%: MET (0.0%)

## This is an in-sample number, and the honest caveat is the point

The corpus and the ruleset were written by the same hands from the same sources.
The holdout split means the operating **point** was chosen on data the headline
was not measured on, but the **rules** were written knowing these payload
shapes, so this is a ceiling on a known distribution, not a claim about the
wild. Read it as: **caught every attack family the corpus contains at ruleset
0.1.0; unknown against phrasings nobody wrote a rule for.** The
paraphrase and novel-wording gap is structural to a rule engine and is what
ADR-003's tier-2 judge (P1) is for.

## Recall by attack family

| family | caught | recall |
| --- | --- | --- |
| confusable-homoglyph | 25/25 | 100.0% |
| credential-request | 25/25 | 100.0% |
| data-appendix | 25/25 | 100.0% |
| direct-override | 25/25 | 100.0% |
| encoded-payload | 25/25 | 100.0% |
| exfil-tool | 25/25 | 100.0% |
| exfil-url | 25/25 | 100.0% |
| hidden-unicode | 25/25 | 100.0% |
| html-css-hidden | 25/25 | 100.0% |
| multi-part-split | 25/25 | 100.0% |
| persistence | 25/25 | 100.0% |
| role-switch | 25/25 | 100.0% |

## False positives by benign family

| family | fired | rate |
| --- | --- | --- |
| binary-ish-blobs | 0/40 | 0.0% |
| code-and-diffs | 0/40 | 0.0% |
| email-threads | 0/40 | 0.0% |
| i18n-text | 0/40 | 0.0% |
| logs-and-stacktraces | 0/40 | 0.0% |
| prompt-engineering-content | 0/40 | 0.0% |
| readme-and-cli-help | 0/40 | 0.0% |
| security-docs | 0/40 | 0.0% |
| structured-records | 0/40 | 0.0% |
| tr-support-transcript | 0/40 | 0.0% |

Every number comes from the real engine and the real ruleset over the committed
corpus. Lowering a gate is never how a change is made to pass here; the gate is
the record of what was achieved.
