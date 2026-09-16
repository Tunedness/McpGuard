# McpGuard

**A security proxy that sits between an AI client and its MCP servers.** It sees
every tool call and every result, scans results and resource contents for prompt
injection with a deterministic rule engine, masks PII on the way through,
applies per-tool and per-role access rules, pins each server's tool definitions
so a rug-pull cannot happen quietly, and writes every decision to a hash-chained
append-only audit log. No code change on either side: point your MCP client at
McpGuard instead of the server.

> **Nothing is published yet, and most of this is not built yet.** The repository
> is at phase 1 of 12 — the skeleton. This README describes what the product
> requirements ask for; the sections below say plainly what exists today. The
> single source of truth for scope is `../.ssot/PRD.md`, and the decisions
> behind it are in `../.ssot/ADR.md`.

## What exists today

The monorepo, the build, the gate, and a CLI that knows its own commands and
refuses them honestly. Five packages:

| Package | Published as | Role |
| --- | --- | --- |
| `packages/core` | `@mcpguard/core` | The pure decision engine: policy, access control, manifest pinning, the audit record and its hash chain. |
| `packages/detect` | `@mcpguard/detect` | The pure tier-1 detection engine: injection detectors, PII recognisers, scoring, strip. Separate from `core` because ADR-002 requires the hot path to be movable to a native module. |
| `packages/ruleset` | `@mcpguard/ruleset` | The rules, as data, versioned on their own cadence. No dependencies at all. |
| `packages/proxy` | `@mcpguard/proxy` | The MCP adapter: the `Server`/`Client` pair and the three guarded methods. |
| `packages/cli` | `mcpguard` | The command line and the host: file I/O, policy loading, the audit writer, process lifecycle. |
| `bench` | *never published* | The labelled corpus, the replay and sweep harness, the latency harness. |

## What it is not, and will not be

The boundary with the sibling tool is deliberate, and keeping it sharp is what
lets the two sit in one pipeline without fighting over ownership of the message:

| | McpGuard | [AgentFuse](../../AgentFuse) |
| --- | --- | --- |
| Decides **whether a call happens** | per-tool and per-role permission | loops, budgets, human approval |
| **Rewrites** content in flight | PII masking, injection strip | never |
| **Content** and egress control | injection scanning, manifest pinning, audit log | out of scope |

Loop detection, budgets and approval flows are AgentFuse's job and this tool
does not do them. The contract between the two is one baggage member,
`tunedness.session-id`: the outermost proxy resolves the session and injects it,
inner proxies adopt it. McpGuard is the one that injects (ADR-006).

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
```

**Reaching green never means relaxing tsconfig strictness, disabling a lint rule
or lowering the coverage threshold. The code gets fixed instead.** The one
permitted escape is a lint rule that genuinely conflicts with a justified
pattern, disabled on that line, with a comment saying why.

`docs/implementation-status.md` is the phase-by-phase handover log, in Turkish.
It is written for whoever picks the work up next, and it records the
contradictions each phase found as well as what it built.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
