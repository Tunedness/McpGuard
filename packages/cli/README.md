# mcpguard

The command line for [McpGuard](../../README.md), a security proxy for MCP
servers.

```sh
mcpguard init                       # write a safe starter policy
mcpguard wrap -- node server.mjs    # guard one stdio MCP server
mcpguard serve -- node server.mjs   # guard servers behind an HTTP gateway, at /mcp/<name>
mcpguard scan result.txt            # scan a file, no server needed
mcpguard validate                   # check a policy
mcpguard lock --accept -- node server.mjs   # pin (or re-pin) what the server's tools are
mcpguard audit verify               # check the audit log's hash chain
```

`wrap` takes `--identity <name>` (or `MCPGUARD_IDENTITY`) to say who the caller is,
for role mapping; without either, the client's own `initialize` name is used and
the record marks it as not exact. `lock --diff` shows how a server differs from
its pin and `lock --accept --expect <set-hash>` approves exactly what `--diff`
showed. `serve` binds `127.0.0.1:8766` by default and speaks plain HTTP: anything
but loopback needs `auth.tokens` and `http.allowed_hosts` in the policy.

Exit codes: `0` ok, `2` usage, `3` policy, `4` ruleset, `5` integrity (a changed
manifest, a broken audit chain, a scan that is not `allow`), `70` the run failed.

## License

Apache-2.0. See [NOTICE](NOTICE).
