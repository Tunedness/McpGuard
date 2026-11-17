---
'@tunedness/mcpguard': minor
'@tunedness/mcpguard-core': minor
'@tunedness/mcpguard-detect': minor
---

An opt-in tier-2 judge for what the deterministic scan cannot settle. It is off by
default (`judge.enabled: false`): with it off nothing connects anywhere, no model
runtime joins the dependency tree, and the bytes forwarded, the scores and the audit
records are what they were.

Turned on, the proxy asks a local OpenAI-compatible endpoint (Ollama, llama-server,
vLLM; the global `fetch`, no new dependency) about items whose tier-1 score lies in
`[judge.band_from, block_at)` (`band_from` defaults to `flag_at`), and about a score
at or above `block_at` that tier 1 could not confirm with a second family. The judge
only ever raises a decision: an `injection` answer flags what tier 1 let through,
and on a tool set to `block` it is the second opinion tier 1 was missing. `benign`,
a timeout, an error or a malformed answer leave tier 1's decision alone, and the
bytes forwarded are always the ones tier 1 produced. The judge sees the text as the policy masks it
inside a per-request boundary, and its answer is a label and an integer; none of its
words reach a record.

The endpoint must be on this machine unless `judge.allow_remote: true`, and then it
must be `https`. A call has a timeout (`judge.timeout`, 5000ms), at most
`judge.max_inflight` calls at once (1) with none queued, a circuit breaker
(`judge.circuit_failures` 5, `judge.circuit_open_for` 30s) and a 256-entry cache. The
defaults come from one measurement on one setup: gemma4:12b Q4_K_M through Ollama,
one request at a time, 124 calls: p50 2.7s, p95 3.3s, p99 3.6s. A faster server can shorten them,
and concurrency is bounded by the model server's own (Ollama queues the rest).

An audit record gains `tier1Action` and `judge` (`adapter`, `model`, `modelRevision`,
`latencyMs`, `truncated`, `cached`, and the item's own `score`, `tier1Action`, `outcome`,
`confidence`, `effect`; `judge.items` lists every item when a call had more than one)
only when the judge was consulted. The final action is the worst of `tier1Action` and
`applyJudge` run on each recorded item, a pure function exported from
`@tunedness/mcpguard-core`. A `security_event` carries
`tunedness.judge_model`, `tunedness.judge_outcome` and `tunedness.judge_effect`, and
`judge_unavailable` is emitted once when the breaker opens. `ScanVerdict` gains
`corroborated` and `maskedText`; the score path is untouched.

`judge.reasoning_effort` (sent as `reasoning_effort`, default `none`) and `judge.max_tokens`
(default 32) exist for models that think before answering: with the default budget such a model
returns an empty answer. `reasoning_effort: omit` leaves the field out of the request, for a server that does not
know it; one that rejects the field fails every call (`http_400`) and there is no retry
or guess. A failed call records why (`output_truncated`, `empty_content`, `no_content`,
`bad_envelope`, `unparseable`, `http_<n>`, `network`).

The judge sees the text as the policy masks it: with `pii.enabled: false` (or a server
override of it) a judge on this machine sees the raw text. A remote judge with masking off
is refused at start-up (`wrap`, `serve`, `validate`): turn masking on, or use a loopback judge.

`npm run bench:judge` reports where tier 1 scores paraphrased injections and what each
`band_from` costs. Read `bench/judge/distribution.md` before relying on the default
band: it reaches no paraphrase tier 1 misses.
