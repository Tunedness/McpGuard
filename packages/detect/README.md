# @tunedness/mcpguard-detect

The pure tier-1 detection engine behind [McpGuard](../../README.md):
prompt-injection detectors, PII recognisers, integer scoring, and the strip
action.

Deterministic by construction — the score path is integer arithmetic and the
ruleset is data with a digest (over its rules and lexicons), so the same content
scanned with the same ruleset produces the same verdict on every platform, byte
for byte. It performs no I/O and takes the ruleset as an already-parsed object;
`@tunedness/mcpguard-ruleset` ships the data.

## The health profile

`pii.profile: health` adds `health_ref`, `health_date`, `gs1_serial`, `ssn_us` and
`mbi_us`; `icd10` and `atc` run only when named. The keyword lists they read ship in
`@tunedness/mcpguard-ruleset/pii/` and are digested apart from the ruleset (`piiDigest`).

What the numbers mean. `bench/phi/results.md` reports every recogniser against a
synthetic corpus, and each gated one (`atc` is not gated) meets its ADR-012 gate there. That is an **in-sample**
gate: the corpus, the recognisers and the keyword lists were written together. A
second family, `keyword-collisions-holdout`, uses non-clinical references and dates
in wording the exclusion lists do not carry. It is reported and not gated, and the
reading is plain: on such text the two keyword-anchored recognisers
(`health_ref`, `health_date`) mostly still mask: 48 of 48 holdout items were masked,
46 as the intended kind and 2 as another. Over-masking in health data is the chosen
side of the trade, not an accident. An exclusion word never overrides a plainly
clinical anchor (`reçete no`, `MRN`, `date of birth`, and the health-claim and plan
anchors `claim #`, `member id`, `subscriber id`, `insurance id`...), and an ambiguous
one (`takip no`, bare `admission`) beside such a word is left unmasked. That is the
recall the lists cost: the ambiguous-anchor positives in the benchmark are all
unmasked (0 of 36), and the report prints the number. The same decision has a
price on the other side: `The claim number N was filed with the courier` is masked, a
false positive the benchmark keeps and counts (6 of 816 negatives, 0.7%). Names, addresses, URLs and IP addresses are not recognised.

## License

Apache-2.0. See [NOTICE](NOTICE).
