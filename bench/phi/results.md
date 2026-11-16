# McpGuard — PHI recogniser benchmark

Corpus: 1959 synthetic content items; no real record, name or address is in
it. Scored with the health profile on and every recogniser named, so overlap
resolution between kinds is part of what is measured.

A labelled span is found only when kind, start and end all match.

## Gates (ADR-012)

| recogniser | target | result at `strict_checksum: true` |
| --- | --- | --- |
| health_ref | recall ≥ 95.0%, false positives ≤ 1.0% | MET |
| health_date | recall ≥ 95.0%, false positives ≤ 1.0% | MET |
| gs1_serial | recall ≥ 99.0%, false positives ≤ 0.0% | MET |
| ssn_us | recall ≥ 95.0%, false positives ≤ 1.0% | MET |
| mbi_us | recall ≥ 99.0%, false positives ≤ 0.0% | MET |
| icd10 | recall ≥ 95.0%, false positives ≤ 1.0% | MET |
| atc | none (shape only, opt-in) | not gated |

The gate is checked at the default, `strict_checksum: true`. Both operating
points are measured below; the loose one is reported, not gated.

## `strict_checksum: true` (default)

| recogniser | found | recall | false positives (all negatives) | false positives (its traps) | holdout collisions | accepted false positives | ambiguous-anchor recall (not gated) | stray in positives |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| health_ref | 312/312 | 100.0% | 6/816 (0.7%) | 6/180 (3.3%) | 26/28 (+2 as another kind) | 6/6 | 0/24 | 0 |
| health_date | 316/316 | 100.0% | 0/816 (0.0%) | 0/188 (0.0%) | 20/20 | 0/0 | 0/12 | 0 |
| gs1_serial | 120/120 | 100.0% | 0/816 (0.0%) | 0/120 (0.0%) | 0/0 | 0/0 | 0/0 | 0 |
| ssn_us | 141/141 | 100.0% | 0/816 (0.0%) | 0/112 (0.0%) | 0/0 | 0/0 | 0/0 | 0 |
| mbi_us | 141/141 | 100.0% | 0/816 (0.0%) | 0/60 (0.0%) | 0/0 | 0/0 | 0/0 | 0 |
| icd10 | 278/278 | 100.0% | 0/816 (0.0%) | 0/120 (0.0%) | 0/0 | 0/0 | 0/0 | 0 |
| atc | 159/159 | 100.0% | 0/816 (0.0%) | 0/60 (0.0%) | 0/0 | 0/0 | 0/0 | 0 |

## `strict_checksum: false`

| recogniser | found | recall | false positives (all negatives) | false positives (its traps) | holdout collisions | accepted false positives | ambiguous-anchor recall (not gated) | stray in positives |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| health_ref | 312/312 | 100.0% | 6/816 (0.7%) | 6/180 (3.3%) | 26/28 (+2 as another kind) | 6/6 | 0/24 | 0 |
| health_date | 316/316 | 100.0% | 0/816 (0.0%) | 0/188 (0.0%) | 20/20 | 0/0 | 0/12 | 0 |
| gs1_serial | 120/120 | 100.0% | 0/816 (0.0%) | 0/120 (0.0%) | 0/0 | 0/0 | 0/0 | 0 |
| ssn_us | 141/141 | 100.0% | 0/816 (0.0%) | 0/112 (0.0%) | 0/0 | 0/0 | 0/0 | 0 |
| mbi_us | 141/141 | 100.0% | 0/816 (0.0%) | 0/60 (0.0%) | 0/0 | 0/0 | 0/0 | 0 |
| icd10 | 278/278 | 100.0% | 0/816 (0.0%) | 0/120 (0.0%) | 0/0 | 0/0 | 0/0 | 0 |
| atc | 159/159 | 100.0% | 0/816 (0.0%) | 0/60 (0.0%) | 0/0 | 0/0 | 0/0 | 0 |

## This is an in-sample number

The corpus and the recognisers were written by the same hands, and the keyword
and exclusion lists were tuned while the corpus was in view. These are ceilings
on a known distribution, not a claim about real records.

The *keyword-collisions* family is gated like every other: an anchor word used
outside medicine (a courier's tracking number, a Kubernetes admission webhook)
is a false positive, and the exclusion lists in the ruleset's `pii/` data are
what the recognisers use to stay out of it. Because those lists were written
with that family in view, a second family sits beside it:
*keyword-collisions-holdout* is the same kind of collision in wording the lists
do not carry, written after the lists and never used to adjust them. It is
reported in the *holdout collisions* column (items the recogniser missed but
another one masked are counted beside it), not gated, and it is the number to
read for how far the exclusion lists generalise.

Read it this way: the gate is an in-sample gate. On wording the lists do not
carry, a reference number or a date that is not clinical is still, for the most
part, masked. For health data that is the deliberate trade — masking too much is
preferred to missing a record — and the exclusion words are there to cut the
collisions the corpus names, not to promise that unseen ones are left alone.
The exclusion words never override a plainly clinical anchor (`reçete no`,
`hasta no`, `MRN`, `date of birth`, and the health-claim and plan anchors:
`claim`, `member`, `subscriber`, `insurance`, `policy holder`...): the
*exclusion-mixed* positives, at least one for every exclusion word and every
strong anchor, hold that, and the recall gate counts them.

*Accepted false positives.* `claim` is a strong anchor by decision, so `The claim
number N was filed with the courier` is masked. That item stays in the corpus as a
negative and is counted as a false positive in the rate over all negatives; the
column lists how many fired. Nothing is set aside: the gate is ADR-012's, the rate
over all negatives, and it counts them.

The rate over a kind's own traps is reported and not gated: the accepted `claim ...
courier` template comes up 6 times in the sample, which puts `health_ref` at 3.3%
on its own traps while the rate over all negatives stays under its 1%.

*Ambiguous-anchor recall.* The other side of the exclusion lists: an ambiguous
anchor (`takip no`, `dosya no`, bare `admission`) beside an exclusion word is
suppressed, and a record that really is clinical is then not masked. The
*ambiguous-anchor-mixed* positives measure that price. They are outside the recall
gate (a gate would only confirm the lists do what they say) and reported in their
own column.

*Stray in positives* counts detections of a kind in a positive item that no
label accounts for. It is not gated.

Every number comes from the real engine and the real ruleset over the committed
corpus. Lowering a gate is never how a change is made to pass here.
