# McpGuard

[![Designed & Maintained with Tan](https://www.muhammetsafak.com.tr/badges/designed-maintained-with-tan.svg)](https://www.muhammetsafak.com.tr/en/tan/)

**A security proxy that sits between an AI client and its MCP servers.** It sees
every tool call and every result, scans results and resource contents for prompt
injection with a deterministic rule engine, masks PII on the way through,
applies per-tool and per-role access rules, pins each server's tool definitions
so a rug-pull cannot happen quietly, and writes every decision to a hash-chained,
tamper-evident audit log. No code change on either side: point your MCP client at
McpGuard instead of the server, over stdio (`wrap`) or over HTTP (`serve`).

> **Not published to npm yet.** Everything below works from a clone
> (`npm install && npm run build`, then `node packages/cli/dist/main.js …`). The
> single source of truth for scope is `../.ssot/PRD.md`; the decisions behind it
> are in `../.ssot/ADR.md`.

## The headline numbers, as measured

All from the committed benchmarks, run against the real engine — not a design
document. Reproduce them with `npm run bench:injection`, `npm run bench:latency`,
`npm run bench:latency:http` and `npm run bench:phi`. See [Honest caveats](#honest-caveats) for what "in-sample" means here.

| | |
| --- | --- |
| Injection catch rate | **100%** on the committed corpus (in-sample) |
| False positive rate | **0.0%** |
| Corpus | 700 labelled content items · 300 positive across 12 attack families · 400 negative |
| Scan latency | **p95 < 20 ms up to 32 KB** in every run; at 1 KB p95 is 0.23 to 0.27 ms. Past 32 KB it depends on the machine, see [Honest caveats](#honest-caveats) |
| `serve` overhead | gateway-added p95 at 1 KB: 0.5 to 1.9 ms across runs, both protocol eras; the gate is 20 ms |
| Health recognisers (opt-in) | all six gated recognisers meet their ADR-012 gate on the synthetic corpus (**in-sample**); on the holdout of non-clinical collisions 48 of 48 items were still masked |
| Determinism | byte-identical verdict on every platform (integer score path, no model) |

## Quickstart

### 1. Write a policy

```sh
node packages/cli/dist/main.js init      # writes a safe starter guardpolicy.yaml
```

The starter is observe mode (`mode: flag`): every decision is computed and
recorded, nothing is blocked, PII is masked, and the audit log is on. Measure your
own traffic, then tighten (`mode: enforce`).

### 2. Put the guard in front of one server

```sh
node packages/cli/dist/main.js wrap -- node your-mcp-server.mjs
```

### 3. Point your MCP client at it

Replace the server command in your client's MCP config with the `mcpguard wrap`
command above. One wrapped child is one connection is one session; nothing else
changes. Tell the guard who the caller is with `--identity <name>`, see
[Who is calling](#who-is-calling-the-identity-ladder).

### 4. Or serve it over HTTP

```sh
node packages/cli/dist/main.js serve -- node your-mcp-server.mjs
```

The guarded server is then at `http://127.0.0.1:8766/mcp/server`. See
[The HTTP gateway](#the-http-gateway-serve) for what it will and will not do.

### 5. Pin what the server is, and approve changes

```sh
node packages/cli/dist/main.js lock --accept -- node your-mcp-server.mjs
```

See [The manifest lock](#the-manifest-lock) for the whole flow.

### 6. Ask why something flagged, without a running proxy

```sh
node packages/cli/dist/main.js scan a-tool-result.txt
```

`scan` exits 0 when the file is allowed and 5 when it is flagged or blocked.

### 7. Prove the audit log was not tampered with

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
- **Access control** — per-tool `allow`/`deny` with roles, per-server `roles`
  that decide who may reach a server at all, and dangerous-capability
  combinations ("read a file" *and* "reach the network"). Roles are mapped from a
  caller identity, which has [its own ladder](#who-is-calling-the-identity-ladder).
- **Manifest pinning** — trust-on-first-use, then a hash lock, so a server that
  changes a tool between sessions is caught and stays refused until you approve
  it. See [The manifest lock](#the-manifest-lock).
- **A guarded HTTP gateway** — `mcpguard serve` puts the same three gates in front
  of several servers at once, one path each. See
  [The HTTP gateway](#the-http-gateway-serve).
- **A tamper-evident audit log** — hash-chained JSONL; the record holds masked
  content and a keyed fingerprint of the raw, never the raw itself. The chain head
  can be sent to stderr or to syslog as a checkpoint; see
  [Audit checkpoints](#audit-checkpoints).
- **A tier-2 judge** — opt-in, off by default, a local model server asked about
  what tier 1 could not settle. It can only raise a decision, never lower one or
  touch the content. See [The tier-2 judge](#the-tier-2-judge-opt-in).
- **Telemetry** — optional, off by default, hand-written OTLP under the
  `tunedness.*` namespace. A request's W3C `traceparent` becomes the log record's
  `traceId` and `spanId`, so McpGuard's events join the caller's trace.

## Who is calling: the identity ladder

Role mapping needs to know who is calling, and stdio carries no such field. The
identity is resolved on a ladder, and the audit record and the `security_event`
say which rung answered and whether it was exact.

| Rung | Where it comes from | Exact? |
| --- | --- | --- |
| `--identity <name>` (`flag`) | the person who set up the guard | yes |
| `MCPGUARD_IDENTITY` (`env`) | the person who set up the guard | yes |
| `clientInfo.name` (`client_info`) | the client's own `initialize`, legacy era only | **no**: a client can call itself anything |
| none | | no identity; no roles; the policy's defaults apply |

A caller that no rung names is never promoted to a role. In `serve`, a bearer
token (`auth.tokens`) is the exact rung. The session id is a different thing: it
ties records together and is never used as an identity.

```sh
node packages/cli/dist/main.js wrap --identity alice -- node your-mcp-server.mjs
```

With `servers.<name>.roles` set, only a caller holding one of those roles may send
that server any request. Under `mode: enforce` the others get an error; under
`mode: flag` they are flagged and let through. A policy with a `servers` section
also has to name the server you run: `wrap` and `serve` stop with exit code 3
under `mode: enforce` when `--name` (or `server`, the default) is not one of its
keys.

## Sessions, and chaining with a trace

A stdio `wrap` session is exact: one child, one connection. Over HTTP the session
is resolved on a ladder: the trace id of `_meta.traceparent`, then the
`tunedness.session-id` baggage member, then `Mcp-Session-Id` (legacy era only),
then a best-effort guess from `clientInfo` and the remote address. The record says
which rung answered; a guess is never shown as exact.

The trace rung is strict. A `traceparent` that is not well-formed W3C (a
zero span id, version `ff`, a non-hex flags field) **no longer names
a session**: the ladder moves on to the next rung. The telemetry reads the header
with the same parser, so a session named by a trace id is always a record that
carries that trace. A malformed `traceparent` is ignored and never raises an error.
The trace context is for correlation only: no decision reads it and the audit
record does not hold it.

## The manifest lock

`guardlock.json` pins what each server's tools are. It belongs in version control,
so a change to a tool shows up in code review.

1. **First contact.** With `lock.on_first_use: write` (the default) the first
   `tools/list` is pinned and passes. `require` stops the traffic for a server with
   no entry and writes nothing.
2. **Every session after.** The tool list is compared with the pin. On a mismatch,
   `lock.on_mismatch: halt` (the default) refuses `tools/list` **and** `tools/call`;
   `flag` lets them through and records the difference. The error to the client
   names neither the tool nor its description, because those are the server's words.
3. **The halt is sticky.** A later list that happens to match the pin does not lift
   it. A server that alternates between two lists cannot reopen the gate that way.
   Only `lock --accept`, or restarting the process, lifts it.
4. **Descriptions are scanned too.** A rug-pull is often in the description rather
   than the result, so tool titles, descriptions and annotations go through the same
   scan; findings are written into the lock and the tool is flagged, not removed.

```sh
# see how the server differs from the pin; exits 5 when it differs or is not pinned
node packages/cli/dist/main.js lock --diff -- node your-mcp-server.mjs

# approve it: pin the tools as they are now. --expect refuses unless the set hash
# is the one --diff printed, so you approve exactly what you reviewed.
node packages/cli/dist/main.js lock --accept --expect <set-hash> -- node your-mcp-server.mjs

node packages/cli/dist/main.js lock show
```

For a server the policy defines under `servers.<name>.upstream`, leave off the
`--` command and name it with `--server <name>`.

## The HTTP gateway (`serve`)

```sh
node packages/cli/dist/main.js serve -- node your-mcp-server.mjs       # one server, from the command line
node packages/cli/dist/main.js serve --upstream https://mcp.example.com/mcp
node packages/cli/dist/main.js serve                                   # servers from the policy
```

Each server is reached at `/mcp/<name>`, with its own rules, its own `guardlock.json`
entry and its own connections. Tool names, URIs and capabilities pass through
untouched: there is no merging and no name prefix. Servers are declared in the
policy as `servers.<name>.upstream` (`{ url }` or `{ command, args }`).

- **Both protocol eras, no translation.** The legacy era (sessions) and the modern
  era (none) are served side by side; a request whose era the upstream does not
  speak is refused rather than converted.
- **Defaults are conservative.** It binds `127.0.0.1` on port 8766. Host and Origin
  are always checked, no CORS header is written, a POST that is not JSON gets `415`,
  and the body, upstream response and in-flight request limits are on. Binding
  anywhere but loopback refuses to start (exit code 3) without `auth.tokens` and
  `http.allowed_hosts` in the policy.
- **Identity is a bearer token.** `auth.tokens` holds the SHA-256 of each token with
  the identity it stands for; with tokens defined a request without a valid one gets
  `401`. The token is never written to a log.
- **No TLS.** The gateway speaks plain HTTP and says so at start-up. Keep it on
  loopback, or terminate TLS in front of it.
- **It does not retry a `tools/call`.** Legacy sessions live in the process's
  memory, so scaling out needs sticky routing.
- **"Exact" is the caller's declaration, not proof.** The threat model is an injected
  model, not a malicious client: a client that wants to dodge a combination rule can
  split its steps across trace ids.
- **A modern multi-round-trip (`input_required`) result does not pass through.**
  The shared upstream connection has no way to ask the downstream client, so the
  call fails. A test pins this.

## Audit checkpoints

`audit.checkpoint_to` sends the audit chain's head out of the process, so a log
rewritten from the start can be told from the original. `stderr` is the default.
`syslog` sends an RFC 5424 line to `audit.syslog.target`, which is **required**
and has no default:

```yaml
audit:
  checkpoint_to: syslog
  syslog:
    target: tcp://logs.example.com:514   # or udp://127.0.0.1:514, unix:///run/mcpguard/syslog.sock
```

**UDP gives no delivery guarantee.** With nothing listening, a checkpoint can be
lost. Use `tcp://` or `unix://` when it has to arrive. (`unix://` is a stream
socket; `/dev/log` is a datagram socket Node cannot open.) For every transport a
failure never stops a call and is never silent: each checkpoint that was refused,
dropped or not delivered is written to stderr as `checkpoint_error` and emitted as a
`security_event`. `validate` and start-up refuse a syslog policy with no target.

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
  engine cannot close the paraphrase gap. The tier-2 judge above is the opt-in
  answer, and it only sees what its band sends it.
- **The latency budget is for the reference workload, and the size where it
  stops depends on the machine.** Tool results are mostly small (corpus median 188
  bytes, 95th percentile 485); at 1 KB p95 was 0.23, 0.24 and 0.27 ms in three runs.
  `npm run bench:latency` printed `budget holds up to ~32000 bytes` in both runs
  made while writing this, and the committed `bench/latency/results.md` shows
  p95 7.7 ms at 32 KB. Above that the runs disagree: p95 at 64 KB was 15.4, 26.9
  and 33.2 ms, and at 128 KB 32.5, 33.8 and 202.4 ms (the 202 ms run also had a
  220 ms outlier at 64 KB, so the machine was noisy). Do not read "p95 < 20 ms" as
  holding beyond 32 KB. Above 256 KB an item is sampled and marked degraded rather
  than scanned in full. `bench/latency/results.md` has the curve and the `serve`
  table.
- **The health recognisers' numbers are in-sample too.** `npm run bench:phi`
  scores 1,959 synthetic items; each gated recogniser finds 100% of its labelled
  spans. The corpus, the recognisers and the keyword lists were written together, so
  that is a ceiling. Two numbers say what the lists cost:
  - A second family of non-clinical collisions, in wording the exclusion lists do
    not carry, is reported and not gated. All 48 of its items were still masked
    (46 as the intended kind, 2 as another): on text like that, `health_ref` and
    `health_date` over-mask. In health data that is the chosen side of the trade.
  - The same lists cost recall: the ambiguous-anchor positives (`takip no`, `dosya
    no`, bare `admission`, beside a word like `kargo`) are all unmasked, 0 of 36.
    And `The claim number N was filed with the courier` is masked, a false positive
    the benchmark keeps: 6 of 816 negatives (0.7%).

  Names, addresses, URLs and IP addresses are not recognised at all.
- **The judge's numbers are one model on one machine.** See the tier-2 section;
  they were not re-measured for this release.

## What is deliberately not covered

- **Three surfaces are scanned and nothing else is** (ADR-008): `tools/call`
  results, `resources/read` contents and `tools/list`. Everything else is forwarded
  untouched, and that is the product's boundary rather than a gap being closed. In
  particular `prompts/get`, `sampling/createMessage` and elicitation are **not
  scanned**, and neither is any method outside the spec, present or future.
- **OAuth token exchange and identity federation.** `serve` knows static bearer
  tokens only. mTLS and trusted-header identity are not implemented.
- **The Tunedness Control Plane.** Policy lives in a file next to each guard; there
  is no central policy, event dashboard or compliance report.
- **TLS in `serve`.** Plain HTTP only; see above.
- **Detecting names and addresses.** There is no deterministic way to, and the
  tier-1 engine has no model.

## Packages

| Package | Published as | Role |
| --- | --- | --- |
| `packages/core` | `@tunedness/mcpguard-core` | Pure decision engine: policy, access control, manifest pinning, the audit chain. |
| `packages/detect` | `@tunedness/mcpguard-detect` | Pure tier-1 detection engine: injection detectors, PII recognisers, scoring, strip. |
| `packages/ruleset` | `@tunedness/mcpguard-ruleset` | The rules, as data, versioned on their own cadence. No dependencies. |
| `packages/proxy` | `@tunedness/mcpguard-proxy` | The MCP adapter: the `Server`/`Client` pair and the three guarded methods. |
| `packages/cli` | `@tunedness/mcpguard` (bin `mcpguard`) | The command line and the host. What `npx` will download. |
| `bench` | *never published* | The labelled corpora (injection and PHI), the detection harnesses, the latency harnesses (scan and `serve`), the judge harness. |

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
