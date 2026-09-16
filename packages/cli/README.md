# mcpguard

The command line for [McpGuard](../../README.md), a security proxy for MCP
servers.

```sh
mcpguard init                       # write a safe starter policy
mcpguard wrap -- node server.mjs    # guard one stdio MCP server
mcpguard scan result.txt            # scan a file, no server needed
mcpguard validate                   # check a policy
mcpguard audit verify               # check the audit log's hash chain
```

## License

Apache-2.0. See [NOTICE](NOTICE).
