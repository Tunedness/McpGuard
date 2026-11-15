# @tunedness/mcpguard

## 0.1.1

### Patch Changes

- Four behaviours that v0.1.0 described but did not do now work and are locked by
  tests. The audit fingerprint is a keyed HMAC of the raw upstream text (it was
  computed from the byte count), and still never stores the raw text. The
  correlation key comes from the environment variable named by the new
  `pii.correlation_key_env` policy field and is bound to the masking. The caller
  identity ladder (`wrap --identity`, `MCPGUARD_IDENTITY`, then the client name on
  the legacy protocol era) feeds access decisions and is recorded as
  `callerIdentity` on audit records and as `tunedness.identity*` attributes on
  telemetry events; records written without the field still verify. `mcpguard
  validate` and `wrap` refuse to start when correlation tags are on without a key,
  and when `checkpoint_to: syslog` is configured, which is not implemented yet.
- The manifest gate is wired into `tools/list`, so a changed tool definition now
  halts instead of passing through. The first contact with a server pins its tools
  in `guardlock.json` (`on_first_use: write`, or refuses with `require`); later
  sessions compare against the pin and either `halt` (the default) or `flag`
  (`on_mismatch`). Tool descriptions are scanned and findings are written to the
  lock without removing the tool. A paged `tools/list` is compared as a whole, and
  a `tools/call` is refused while the last list was rejected or could not be
  verified. The new `mcpguard lock show | --diff | --accept` command shows the
  difference and records an explicit acceptance for one server.
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
- Three gaps in `wrap` closed. A modern-era MCP client could not connect because
  `wrap` only served the legacy era: it now serves whichever era the client opens
  with and refuses a mismatch between the client's and the upstream server's era
  instead of translating. The client's capabilities (roots, sampling and the like)
  now reach the upstream server, on `initialize` in the legacy era and on every
  request in the modern one. The combination rules (tools that are dangerous only when both are called
  within a time window) are evaluated on every call; they were defined and never
  run. With `deny` and enforce mode the completing call is refused, otherwise it is
  flagged and recorded.
- Updated dependencies [45c36fd]
  - @tunedness/mcpguard-core@0.1.1
  - @tunedness/mcpguard-proxy@0.1.1
  - @tunedness/mcpguard-detect@0.1.1
  - @tunedness/mcpguard-ruleset@0.1.1

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

### Patch Changes

- Updated dependencies [1d5bdf6]
  - @tunedness/mcpguard-core@0.1.0
  - @tunedness/mcpguard-detect@0.1.0
  - @tunedness/mcpguard-ruleset@0.1.0
  - @tunedness/mcpguard-proxy@0.1.0
