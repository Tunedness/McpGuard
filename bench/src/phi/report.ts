/**
 * The gate, the numbers and the markdown that records them.
 *
 * The thresholds are ADR-012's and are copied from `types.ts`, not chosen here.
 * There is no tolerance: a number is at its gate or it is not, and lowering a
 * gate is never how a change is made to pass.
 */
import type { Metrics } from './replay.js';
import { GATES, PHI_KINDS, type PhiKind } from './types.js';

/** Whether a kind met its gate, and why not when it did not. */
export interface GateResult {
  readonly kind: PhiKind;
  readonly gated: boolean;
  readonly met: boolean;
  readonly reasons: readonly string[];
}

export function checkGates(metrics: Metrics): GateResult[] {
  return PHI_KINDS.map((kind) => {
    const gate = GATES[kind];
    const m = metrics[kind];
    if (gate === null) return { kind, gated: false, met: true, reasons: [] };
    const reasons: string[] = [];
    if (m.recall < gate.recall) {
      reasons.push(`recall ${pct(m.recall)} < ${pct(gate.recall)}`);
    }
    if (m.falsePositiveRate > gate.falsePositive) {
      reasons.push(`false positives ${pct(m.falsePositiveRate)} > ${pct(gate.falsePositive)}`);
    }
    return { kind, gated: true, met: reasons.length === 0, reasons };
  });
}

export function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function table(metrics: Metrics): string {
  const rows = PHI_KINDS.map((kind) => {
    const m = metrics[kind];
    return `| ${kind} | ${m.found}/${m.spans} | ${pct(m.recall)} | ${m.negativeFires}/${m.negatives} (${pct(m.falsePositiveRate)}) | ${m.trapFires}/${m.traps} (${pct(m.trapFalsePositiveRate)}) | ${m.holdoutFires}/${m.holdouts}${m.holdoutOther > 0 ? ` (+${m.holdoutOther} as another kind)` : ''} | ${m.acceptedFires}/${m.accepted} | ${m.ambiguousFound}/${m.ambiguousSpans} | ${m.strayInPositives} |`;
  }).join('\n');
  return `| recogniser | found | recall | false positives (all negatives) | false positives (its traps) | holdout collisions | accepted false positives | ambiguous-anchor recall (not gated) | stray in positives |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
${rows}`;
}

export function renderMarkdown(
  size: number,
  strict: Metrics,
  loose: Metrics,
  gates: readonly GateResult[],
): string {
  const gateRows = gates
    .map((g) => {
      const gate = GATES[g.kind];
      const target =
        gate === null
          ? 'none (shape only, opt-in)'
          : `recall ≥ ${pct(gate.recall)}, false positives ≤ ${pct(gate.falsePositive)}`;
      const verdict = !g.gated ? 'not gated' : g.met ? 'MET' : `NOT MET — ${g.reasons.join('; ')}`;
      return `| ${g.kind} | ${target} | ${verdict} |`;
    })
    .join('\n');
  return `# McpGuard — PHI recogniser benchmark

Corpus: ${size} synthetic content items; no real record, name or address is in
it. Scored with the health profile on and every recogniser named, so overlap
resolution between kinds is part of what is measured.

A labelled span is found only when kind, start and end all match.

## Gates (ADR-012)

| recogniser | target | result at \`strict_checksum: true\` |
| --- | --- | --- |
${gateRows}

The gate is checked at the default, \`strict_checksum: true\`. Both operating
points are measured below; the loose one is reported, not gated.

## \`strict_checksum: true\` (default)

${table(strict)}

## \`strict_checksum: false\`

${table(loose)}

## This is an in-sample number

The corpus and the recognisers were written by the same hands, and the keyword
and exclusion lists were tuned while the corpus was in view. These are ceilings
on a known distribution, not a claim about real records.

The *keyword-collisions* family is gated like every other: an anchor word used
outside medicine (a courier's tracking number, a Kubernetes admission webhook)
is a false positive, and the exclusion lists in the ruleset's \`pii/\` data are
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
The exclusion words never override a plainly clinical anchor (\`reçete no\`,
\`hasta no\`, \`MRN\`, \`date of birth\`, and the health-claim and plan anchors:
\`claim\`, \`member\`, \`subscriber\`, \`insurance\`, \`policy holder\`...): the
*exclusion-mixed* positives, at least one for every exclusion word and every
strong anchor, hold that, and the recall gate counts them.

*Accepted false positives.* \`claim\` is a strong anchor by decision, so \`The claim
number N was filed with the courier\` is masked. That item stays in the corpus as a
negative and is counted as a false positive in the rate over all negatives; the
column lists how many fired. Nothing is set aside: the gate is ADR-012's, the rate
over all negatives, and it counts them.

The rate over a kind's own traps is reported and not gated: the accepted \`claim ...
courier\` template comes up 6 times in the sample, which puts \`health_ref\` at 3.3%
on its own traps while the rate over all negatives stays under its 1%.

*Ambiguous-anchor recall.* The other side of the exclusion lists: an ambiguous
anchor (\`takip no\`, \`dosya no\`, bare \`admission\`) beside an exclusion word is
suppressed, and a record that really is clinical is then not masked. The
*ambiguous-anchor-mixed* positives measure that price. They are outside the recall
gate (a gate would only confirm the lists do what they say) and reported in their
own column.

*Stray in positives* counts detections of a kind in a positive item that no
label accounts for. It is not gated.

Every number comes from the real engine and the real ruleset over the committed
corpus. Lowering a gate is never how a change is made to pass here.
`;
}
