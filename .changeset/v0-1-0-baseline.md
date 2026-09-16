---
'@mcpguard/core': minor
'@mcpguard/detect': minor
'@mcpguard/ruleset': minor
'@mcpguard/proxy': minor
'mcpguard': minor
---

McpGuard v0.1.0 — a security proxy between an AI client and its MCP servers.

`mcpguard wrap -- <server>` puts a transparent guard in front of one stdio MCP
server. It scans tool results and resource contents for prompt injection with a
deterministic rule engine, masks PII on the way through, applies per-tool and
per-role access rules, pins each server's tool definitions against a rug-pull,
and writes every decision to a hash-chained, tamper-evident audit log. The
default posture is observe mode: every decision is computed and recorded and
nothing is blocked, so an operator can measure what enforcement would do to
their own traffic before switching it on.

**Injection detection** is tier-1 and deterministic: signature rules shipped as
a separately-versioned data package, plus imperative-mood, hidden-Unicode,
encoded-payload, egress-beacon and chat-frame detectors, in Turkish and English.
The score path is integer arithmetic, so the verdict is byte-identical on every
platform and a committed snapshot pins it with no tolerance. Measured against the
committed 700-item corpus: **100% catch, 0% false positives** — stated plainly
as an in-sample ceiling, because the corpus and the ruleset share an author; the
paraphrase gap a rule engine cannot close is what ADR-003's tier-2 judge is for.

**PII masking** covers Turkish national id, tax number, IBAN and card
(checksum-gated), phone and e-mail, on its own axis from the injection action.
**The audit log** never stores raw content — only masked content and a keyed
fingerprint of the raw. **Manifest pinning** is trust-on-first-use plus a hash
lock. **Telemetry** is optional, off by default, and hand-written OTLP with no
OpenTelemetry dependency in the tree.

Latency: added scan cost is **p95 < 20 ms on the reference workload** (the corpus
median item is 188 bytes, where p95 is a fifth of a millisecond); the cost curve
by size is published, and a result above ~64 KB costs more, with items over
256 KB sampled rather than scanned in full.

**Not in this release:** the guarded HTTP gateway (`serve` is deferred to P1;
protection is in `wrap` mode), health-data PHI redaction (the claim is identifier
masking), and the local SLM judge (tier 1 is fully deterministic).
