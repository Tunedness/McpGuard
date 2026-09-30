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
  tag. On its own axis from the injection action.
- **Access control** — per-tool `allow`/`deny` with roles, and dangerous-
  capability combinations ("read a file" *and* "reach the network").
- **Manifest pinning** — trust-on-first-use, then a hash lock, so a server that
  changes a tool between sessions is caught.
- **A tamper-evident audit log** — hash-chained JSONL; the record holds masked
  content and a keyed fingerprint of the raw, never the raw itself.
- **Telemetry** — optional, off by default, hand-written OTLP under the
  `tunedness.*` namespace.

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
- **A local SLM judge.** ADR-003's tier-2 judge is P1; tier 1 is fully
  deterministic and needs no model.

## Packages

| Package | Published as | Role |
| --- | --- | --- |
| `packages/core` | `@mcpguard/core` | Pure decision engine: policy, access control, manifest pinning, the audit chain. |
| `packages/detect` | `@mcpguard/detect` | Pure tier-1 detection engine: injection detectors, PII recognisers, scoring, strip. |
| `packages/ruleset` | `@mcpguard/ruleset` | The rules, as data, versioned on their own cadence. No dependencies. |
| `packages/proxy` | `@mcpguard/proxy` | The MCP adapter: the `Server`/`Client` pair and the three guarded methods. |
| `packages/cli` | `mcpguard` | The command line and the host. What `npx` will download. |
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
