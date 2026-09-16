# @mcpguard/proxy

The MCP adapter for [McpGuard](../../README.md): a `Server`/`Client` pair that
guards `tools/call`, `tools/list` and `resources/read`, and forwards everything
else untouched.

`bridge`, `era`, `remap` and `diagnostics` import neither engine, so the
transport skeleton stays liftable into a shared package later; `guard` is the one
engine-facing file, where McpGuard rewrites the message its sibling only decides
whether to forward.

## License

Apache-2.0. See [NOTICE](NOTICE).
