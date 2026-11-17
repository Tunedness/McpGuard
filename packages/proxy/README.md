# @tunedness/mcpguard-proxy

The MCP adapter for [McpGuard](../../README.md): a `Server`/`Client` pair that
guards `tools/call`, `tools/list` and `resources/read`, and forwards everything
else untouched. The same three guards are served over HTTP by `http-gateway`, a
single Fetch handler that carries both protocol eras side by side (one upstream
connection per server for the modern era, one per downstream session for the
legacy era) without translating between them.

`bridge`, `era`, `remap` and `diagnostics` import neither engine, so the
transport skeleton stays liftable into a shared package later; `guard` is the one
engine-facing file, where McpGuard rewrites the message its sibling only decides
whether to forward.

## License

Apache-2.0. See [NOTICE](NOTICE).
