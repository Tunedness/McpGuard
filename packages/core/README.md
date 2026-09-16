# @mcpguard/core

The pure decision engine behind [McpGuard](../../README.md): policy and access
control, dangerous-capability combinations, manifest pinning, and the
hash-chained audit record.

It does **no I/O** — no transport, no MCP SDK, no filesystem. Its only runtime
dependency is `zod`; the only Node builtin it touches is `node:crypto`, for
SHA-256 and HMAC. That is what makes a decision it made reproducible by whoever
audits it later, and it is enforced by a test, not a convention.

## License

Apache-2.0. See [NOTICE](NOTICE).
