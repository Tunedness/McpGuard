---
'@tunedness/mcpguard': minor
'@tunedness/mcpguard-core': minor
'@tunedness/mcpguard-proxy': minor
---

`servers.<name>.roles` now decides access. It was in the policy schema and was
silently ignored. When it names any role, only a caller holding one of them may
send that server a request at all: `tools/list`, `tools/call`, `resources/*`,
`prompts/*` and every other request that would be forwarded. A caller with no
identity, or none of those roles, gets a JSON-RPC error under `mode: enforce`
(`tools/call` keeps its `isError` result) and is flagged and let through under
`mode: flag`, in `wrap` and in `serve` alike. `initialize`, `ping` and
`server/discover` are connection-level and not covered. It combines with the
`tools` rules and the stricter wins. An empty or unset list leaves the server
open to everyone, as before.

Two changes in this release are breaking:

- **A server name the policy does not carry now stops the start under
  `mode: enforce`.** The rules under `servers.<name>` are looked up by the name
  the server runs under, so a name that matches nothing used to run without them,
  roles included. When the policy has a `servers` section, `mcpguard wrap` and
  `mcpguard serve` (for its command-line upstream, `--upstream` included) now exit
  with code 3 if the name (`--name`, or `server` by default) is not one of its
  keys. A setup that worked yesterday, such as `mcpguard wrap -- node server.js`
  against a policy that only has `servers.x.pii`, will not start until you either
  pass `--name <key>` or add an empty entry for the server to the policy:
  `servers: { <name>: {} }`. Under `mode: flag` nothing stops: the start goes on
  with a `server_unmatched` line on stderr and a `security_event` of that kind.
  A policy with no `servers` section is not affected.
- **`@tunedness/mcpguard-proxy`: `Gates` has a new required member, `onRequest`.**
  It is the gate for every request that has no gate of its own (`resources/list`,
  `prompts/get`, and so on). Code that builds its own `Gates` for `createBridge` or
  the HTTP gateway must add it, for instance `onRequest: (request, forward) => forward()`
  to let everything through.
