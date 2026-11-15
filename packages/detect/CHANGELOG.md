# @tunedness/mcpguard-detect

## 0.1.1

### Patch Changes

- 45c36fd: The ruleset digest now covers the lexicons as well as the rules. The imperative
  and encoding detectors read the lexicons and they move the score, so two
  rulesets with the same rules and different lexicons used to carry the same
  digest and could decide differently. Every ruleset's digest changes with this
  release. Audit records written by an earlier engine version carry the old
  formula; reproduce them with that engine version, which ADR-009 already
  requires.
- The packages are published under the `tunedness` npm organisation: the command
  line tool as `@tunedness/mcpguard` (the binary is still `mcpguard`, so
  `npx @tunedness/mcpguard` and `mcpguard wrap -- <server>` work as before) and
  the libraries as `@tunedness/mcpguard-core`, `@tunedness/mcpguard-detect`,
  `@tunedness/mcpguard-ruleset` and `@tunedness/mcpguard-proxy`. There is no
  unscoped `mcpguard` package and no `@mcpguard` scope.
  
  Packaging fixes that came with it: the `./testing` export of core and detect and
  the `pii/` entries of the ruleset package pointed at files that do not exist and
  are gone; the packages declare their repository, so provenance-signed
  publishing is accepted; the internal dependencies are real ranges instead of
  `*` (the CLI pins core, detect and proxy to its own version; the ruleset stays a
  caret range so rule updates can ship without an engine release); and every
  package's version constant is checked against its manifest by a test.

## 0.1.0

> Not published to npm; the first published version is 0.1.1.

### Minor Changes

- 1d5bdf6: McpGuard v0.1.0 — a security proxy between an AI client and its MCP servers.
  
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
