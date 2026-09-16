# @mcpguard/detect

The pure tier-1 detection engine behind [McpGuard](../../README.md):
prompt-injection detectors, PII recognisers, integer scoring, and the strip
action.

Deterministic by construction — the score path is integer arithmetic and the
ruleset is data with a digest, so the same content scanned with the same ruleset
produces the same verdict on every platform, byte for byte. It performs no I/O
and takes the ruleset as an already-parsed object; `@mcpguard/ruleset` ships the
data.

## License

Apache-2.0. See [NOTICE](NOTICE).
