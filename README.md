# McpGuard

[![Designed & Maintained with Tan](https://www.muhammetsafak.com.tr/badges/designed-maintained-with-tan.svg)](https://www.muhammetsafak.com.tr/en/tan/)

**A security proxy that sits between an AI client and its MCP servers.** It sees
every tool call and every result, scans results and resource contents for prompt
injection with a deterministic rule engine, masks PII on the way through,
applies per-tool and per-role access rules, pins each server's tool definitions
so a rug-pull cannot happen quietly, and writes every decision to a hash-chained,
tamper-evident audit log. No code change on either side: point your MCP client at
McpGuard instead of the server.

> **Not published to npm yet.** Everything below works from a clone
> (`npm install && npm run build`, then `node packages/cli/dist/main.js …`). The
> single source of truth for scope is `../.ssot/PRD.md`; the decisions behind it
> are in `../.ssot/ADR.md`.

## The headline numbers, as measured

All from the committed benchmarks, run against the real engine — not a design
document. See [Honest caveats](#honest-caveats) for what "in-sample" means here.

| | |
| --- | --- |
| Injection catch rate | **100%** on the committed corpus (in-sample) |
| False positive rate | **0.0%** |
| Corpus | 700 labelled content items · 300 positive across 12 attack families · 400 negative |
| Scan latency | **p95 < 20 ms up to ~64 KB**; ~0.2 ms at the corpus's median item size |
| Determinism | byte-identical verdict on every platform (integer score path, no model) |

## Quickstart

### 1. Write a policy

```sh
node packages/cli/dist/main.js init      # writes a safe starter guardpolicy.yaml
```

The starter is observe mode: every decision is computed and recorded, nothing is
blocked, PII is masked, and the audit log is on. Measure your own traffic, then
tighten.

### 2. Put the guard in front of one server

```sh
node packages/cli/dist/main.js wrap -- node your-mcp-server.mjs
```

### 3. Point your MCP client at it

Replace the server command in your client's MCP config with the `mcpguard wrap`
command above. One wrapped child is one connection is one session; nothing else
changes.

### 4. Ask why something flagged, without a running proxy

```sh
node packages/cli/dist/main.js scan a-tool-result.txt
```

### 5. Prove the audit log was not tampered with

```sh
node packages/cli/dist/main.js audit verify
```

## What it does

- **Injection scanning** — a deterministic tier-1 engine over tool results and
  resource contents: signature rules (data, versioned separately), imperative
  mood, hidden Unicode, encoded payloads decoded and re-scanned, egress beacons,
  chat-frame injection. Turkish and English, with a fold that survives
  deasciified spellings and homoglyphs.
- **PII masking** — Turkish national id, tax number, IBAN, card (checksum-gated),
  phone and e-mail, masked to `[KIND:***]` with an optional keyed correlation
  tag. On its own axis from the injection action. An opt-in `pii.profile: health`
  adds hospital and insurer reference numbers, clinical dates, medicine-pack
  serials, US SSN and Medicare ids; diagnosis (`icd10`) and drug class (`atc`)
  codes are available only by name. Names and addresses are not recognised: there
  is no deterministic way to, and the tier-1 engine has no model.
- **Access control** — per-tool `allow`/`deny` with roles, and dangerous-
  capability combinations ("read a file" *and* "reach the network").
- **Manifest pinning** — trust-on-first-use, then a hash lock, so a server that
  changes a tool between sessions is caught.
- **A tamper-evident audit log** — hash-chained JSONL; the record holds masked
  content and a keyed fingerprint of the raw, never the raw itself.
- **A tier-2 judge** — opt-in, off by default, a local model server asked about
  what tier 1 could not settle. It can only raise a decision, never lower one or
  touch the content. See [The tier-2 judge](#the-tier-2-judge-opt-in).
- **Telemetry** — optional, off by default, hand-written OTLP under the
  `tunedness.*` namespace.

## The tier-2 judge (opt-in)

Tier 1 is deterministic and has no model. Tier 2 is an optional second look from a
model you run yourself: any local OpenAI-compatible server (Ollama, llama-server,
vLLM). It is **off by default**; with it off nothing connects anywhere and no model
runtime is installed.

```yaml
judge:
  enabled: true
  endpoint: http://127.0.0.1:11434/v1/chat/completions
  model: your-model-name        # McpGuard recommends none; you pick one
  model_revision: "sha256:..."  # optional: the digest you pinned, written to every record
  timeout: 5000ms               # the default; see "Defaults" below
  max_inflight: 1               # the default: one call at a time
  reasoning_effort: none        # the default; for models that think first (Gemma 4, Qwen 3)
  band_from: 40                 # optional; default is each tool's flag_at
```

A model that thinks before it answers (Gemma 4, Qwen 3, gpt-oss) spends the judge's
small token budget on the thinking and returns nothing. `reasoning_effort` defaults to
`none`, which Ollama honours; raise `max_tokens` if your server cannot switch thinking
off. **If your server does not know `reasoning_effort`, set `reasoning_effort: omit`**: the
field is then left out of the request altogether. A server that rejects the field answers
every call with an error, which the audit record shows as `reason: http_400` (or whatever
status it sent); McpGuard does not retry or guess, tier 1's decision stands, and the
circuit breaker opens after five in a row. A model that ran out of tokens shows as
`reason: output_truncated`.

**Defaults, and what they rest on.** `timeout: 5000ms`, `max_inflight: 1`,
`reasoning_effort: none`, a circuit breaker that opens after 5 consecutive failures for
30 s. They come from **one measurement on one setup**: `gemma4:12b` (Q4_K_M) through Ollama,
on the author's machine, one request at a time. Over 68 calls the latency was p50 2.9 s,
p95 3.1 s, p99 3.9 s; over a second run of 124 calls, p50 2.7 s, p95 3.3 s, p99 3.6 s,
max 3.7 s. A 1.5 s timeout would have timed out every call. Someone with a faster model or
server can set `timeout` much lower, and should measure rather than copy these.
Concurrency is the model server's, not McpGuard's: Ollama runs one request at a time and
queues the rest, and at two concurrent calls 67 of 68 timed out because the queued call
waits inside the timeout. Raise `max_inflight` only as far as your server runs requests in
parallel.

**What it caught, on that same setup.** Of the 64 paraphrased injections
(`bench/src/judge/paraphrases.ts`) the model called 61 injection (95.3%; English 31/32,
Turkish 30/32), 2 benign and 1 timed out. Of 60 benign corpus items it called 0 injection
(0.0%). Sixty items cannot exclude a false-positive rate of a few percent (the 95% upper
bound for 0 of 60 is about 5%), the sample is the corpus the ruleset was calibrated against
(every sixth item, hard negatives included but not separated), and the paraphrases were
written by one person; this is one model's behaviour on a small set, not a rate. Reproduce:
`npm run bench:judge -- --endpoint http://127.0.0.1:11434/v1/chat/completions --model
gemma4:12b --reasoning-effort none --concurrency 1 --timeout 5000 --benign-limit 60`.

- **Which items.** Those scoring in `[band_from, block_at)`, and a score at or above
  `block_at` that tier 1 could not confirm with a second family. Degraded items never go.
- **What it can change.** It only raises. An `injection` answer flags an item tier 1
  let through, and on a tool set to `action: block` it is the second family that turns a
  flag into a block. A `benign` answer, a timeout, an error or an answer that is not
  exactly `{"label", "confidence"}` leaves tier 1's decision as it was. The bytes
  forwarded are always tier 1's. Talking the judge round gains an attacker nothing;
  the worst case is that their own content is flagged.
- **What it sees.** The text as your policy masks it, in an envelope with a random
  per-request boundary: with PII masking on (the default) never the raw value. **With
  `pii.enabled: false`, or `servers.<name>.pii.enabled: false`, nothing is masked and the
  judge sees the raw text; a judge on this machine still runs that way, but a remote one
  is refused.** The endpoint must be on this machine; a remote one needs `allow_remote:
  true` and `https`, and then the masked text leaves the machine. With masking off, a
  remote judge (`allow_remote: true`, or an endpoint that is not loopback) is refused at
  start-up, by `wrap`, `serve` and `validate` alike, with exit code 3: turn masking on,
  or point the judge at this machine.
- **When it is slow or gone.** One bounded wait (`timeout`), no retry, no queue
  (`max_inflight` calls at once, the rest skip), a circuit breaker, and a small cache.
  Tier 1's decision is always ready first.
- **What the log can prove.** A record written after a judge call carries the model,
  revision, and, for each judged item, its own tier-1 score and action, the outcome,
  confidence and effect (`judge.items` when a call had more than one, otherwise
  `judge` itself), plus the call's tier-1 action. The final action is the worst of the
  tier-1 action and `applyJudge` run on each item, so an auditor reproduces it byte for
  byte. What no record can say is whether the model would answer the same today.

**What the default band does not reach.** `bench/judge/distribution.md` scores
64 paraphrased injections with tier 1: 57 score exactly 0 and none reach `flag_at`.
The default band starts at `flag_at`, so it never sees them; only `band_from: 0`
does, which sends every tool result to the model, at the latency above per result.
`band_from: 0` is opt-in and is not the default.

## Chaining with AgentFuse

[AgentFuse](../../AgentFuse) is the sibling tool, and the two chain. The division
is clean and enforced in code:

| | McpGuard | AgentFuse |
| --- | --- | --- |
| Decides **whether a call happens** | per-tool / per-role permission | loops, budgets, human approval |
| **Rewrites** content in flight | PII masking, injection strip | never |
| **Content / egress** control | injection scanning, manifest pinning, audit | out of scope |

McpGuard is the outermost proxy, so it injects the `tunedness.session-id` baggage
member that AgentFuse adopts; both emit into the same `tunedness.*` namespace, so
one collector sees one story.

## Honest caveats

- **The 100% is in-sample.** The corpus and the ruleset were written by the same
  hands from the same sources; the holdout split separates the operating point
  but not the rules. Read it as *caught every attack family the corpus contains
  at ruleset 0.1.0; unknown against phrasings nobody wrote a rule for.* A rule
  engine cannot close the paraphrase gap — that is ADR-003's tier-2 judge (P1).
- **The latency budget is for the reference workload.** Tool results are mostly
  small (corpus median 188 bytes); p95 there is a fifth of a millisecond. A
  128 KB result costs ~33 ms; above 256 KB an item is sampled and marked
  degraded rather than scanned in full. `bench/latency/results.md` has the curve.

## What is deliberately not in v0.1.0

- **The guarded HTTP gateway (`serve`).** Protection is in `wrap` mode; the
  multi-upstream HTTP gateway is P1 (`../.ssot/PRD.md`). `serve` refuses to run
  and says so, rather than pretending to guard.
- **Health-data PHI redaction.** The MVP claim is identifier masking, not PHI
  redaction; the health recognisers are P1 behind a `profile: health`.
- **A local SLM judge.** ADR-003's tier-2 judge is P1 (opt-in, see above); tier 1
  is fully deterministic and needs no model.

## Packages

| Package | Published as | Role |
| --- | --- | --- |
| `packages/core` | `@tunedness/mcpguard-core` | Pure decision engine: policy, access control, manifest pinning, the audit chain. |
| `packages/detect` | `@tunedness/mcpguard-detect` | Pure tier-1 detection engine: injection detectors, PII recognisers, scoring, strip. |
| `packages/ruleset` | `@tunedness/mcpguard-ruleset` | The rules, as data, versioned on their own cadence. No dependencies. |
| `packages/proxy` | `@tunedness/mcpguard-proxy` | The MCP adapter: the `Server`/`Client` pair and the three guarded methods. |
| `packages/cli` | `@tunedness/mcpguard` (bin `mcpguard`) | The command line and the host. What `npx` will download. |
| `bench` | *never published* | The labelled corpus, the detection harness, the latency harness. |

## Development

Node.js **≥ 20.19**. npm workspaces — not pnpm.

```sh
npm install
npm run build
```

The gate, verbatim. A change is not finished until these are green:

```sh
npm run lint
npm run typecheck
npm run build
npm test
npm run schema:check
```

**Reaching green never means relaxing tsconfig strictness, disabling a lint rule
or lowering a coverage threshold. The code gets fixed instead.**

`docs/implementation-status.md` is the phase-by-phase handover log, in Turkish —
written for whoever picks the work up next, and it records the contradictions
each phase found as well as what it built.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
