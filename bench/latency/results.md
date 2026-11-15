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
| 1,000 | 0.189 | 0.186 | 0.231 | 0.397 |
| 4,000 | 0.752 | 0.739 | 0.818 | 1.245 |
| 16,000 | 2.805 | 2.786 | 2.969 | 4.649 |
| 32,000 | 7.078 | 6.947 | 7.694 | 15.858 |
| 64,000 | 14.620 | 14.561 | 15.406 | 18.223 |
| 128,000 | 30.977 | 30.803 | 32.512 | 38.229 |
| 262,144 | 46.558 | 46.331 | 48.673 | 55.951 |

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

<!-- http-gateway:start -->
## HTTP gateway (`mcpguard serve`)

300 calls per size per era after 30 discarded, over real loopback sockets with
the SDK's own clients. All figures are milliseconds. **added** is what the gateway itself
contributed to a call: *in* is the request arriving to the upstream call leaving
(parsing, Host/Origin/token checks, the session ladder, the access decision), *out* is
the upstream answer arriving to the response fully written (the scan, PII masking, the
hash-chained audit append, serialisation). The p95 of their sum is the gated number; it
is taken inside the gateway, so loopback jitter between processes is not in it. The two
end-to-end columns are a sanity check only — the difference of two p95s is not the p95
of the difference, and it includes the second loopback hop and the extra JSON encode and
decode a proxy cannot avoid, which is why it is larger than **added**.

The gates are the engine path `runtime.ts` runs for `tools/call` (access decision,
content scan with PII masking, synchronous audit append). Its combination-rule and
manifest bookkeeping is not in this run.

### Legacy era (a session per client; opening one took 29.624 ms, not part of a call)

| bytes | in p95 | out p95 | **added p95** | added max | e2e proxied p95 | e2e direct p95 | p95 difference |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 188 | 0.164 | 0.535 | **0.697** | 1.259 | 5.258 | 2.270 | 2.987 |
| 1,000 | 0.142 | 1.410 | **1.652** | 2.067 | 7.524 | 2.308 | 5.216 |
| 4,000 | 0.070 | 1.945 | **2.007** | 2.305 | 6.108 | 1.869 | 4.239 |
| 16,000 | 0.052 | 3.880 | **3.921** | 4.487 | 7.686 | 1.803 | 5.883 |
| 64,000 | 0.063 | 16.163 | **16.212** | 29.944 | 19.981 | 2.143 | 17.838 |

### Modern era (no session, one shared upstream connection)

| bytes | in p95 | out p95 | **added p95** | added max | e2e proxied p95 | e2e direct p95 | p95 difference |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 188 | 0.150 | 0.802 | **1.052** | 2.157 | 6.086 | 2.197 | 3.889 |
| 1,000 | 0.252 | 1.666 | **1.933** | 2.461 | 7.685 | 2.275 | 5.410 |
| 4,000 | 0.093 | 1.980 | **2.057** | 2.512 | 6.121 | 1.945 | 4.176 |
| 16,000 | 0.055 | 3.893 | **3.952** | 4.468 | 7.566 | 1.775 | 5.792 |
| 64,000 | 0.069 | 15.876 | **15.926** | 21.905 | 19.739 | 2.144 | 17.595 |

### Verdict against PRD §6 and ADR-011

- added p95 < 20 ms on the reference workload (the scan benchmark's: 1,000 bytes, the 95th percentile item floored at 1 KB; the corpus median is 188 bytes, its own row), both eras: MET
- the gate is the reference row only. Larger rows are the curve: the cost is the scan's, which grows with size (see the scan table above), and the gateway's own part (in) stays near a tenth of a millisecond at every size.
<!-- http-gateway:end -->
