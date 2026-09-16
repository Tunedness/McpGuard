# McpGuard — scan latency benchmark

500 scans per size, 50 discarded first. The scan is
pure and synchronous; the proxy adds a small constant framing cost on top.

## Reference workload

The committed corpus has a **median item of 188 bytes** and a **95th
percentile of 485 bytes** — tool results are mostly small. The budget of
PRD §6 (added latency p95 < 20 ms) is a claim about that distribution.

## Cost by size

| bytes | mean | p50 | p95 | max |
| --- | --- | --- | --- | --- |
| 1,000 | 0.197 | 0.191 | 0.235 | 0.686 |
| 4,000 | 0.799 | 0.787 | 0.866 | 1.335 |
| 16,000 | 2.915 | 2.898 | 3.137 | 4.405 |
| 32,000 | 7.299 | 7.221 | 7.896 | 9.504 |
| 64,000 | 15.160 | 15.091 | 16.028 | 20.634 |
| 128,000 | 31.567 | 31.416 | 33.259 | 37.075 |
| 262,144 | 47.183 | 47.089 | 49.151 | 50.468 |

## Verdict against PRD §6

- p95 < 20 ms on the reference workload: MET
- the budget holds up to roughly **64,000 bytes** per item

This is stated as a curve, not a single number, because "p95 < 20 ms" without a
size is a number that can be made true by choosing a small enough payload. The
scan is single-pass — one normalization walk, one Aho-Corasick pass, prefiltered
regexes only where a literal hit — so cost grows with **size**, not with the
number of rules: a ruleset twice as large scans in the same time. A result
larger than the crossover costs more than the budget; above 256 KiB it is
sampled (head, tail, interior windows) and marked degraded rather than scanned
in full, so the cost is bounded even for an unbounded input. Shrinking
`scan.max_bytes` is the lever an operator pulls to trade coverage for a tighter
tail on very large results.
