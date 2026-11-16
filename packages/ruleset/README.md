# @tunedness/mcpguard-ruleset

The detection ruleset for [McpGuard](../../README.md): injection signatures,
lexicons and PII recogniser configuration, as data, versioned on their own
cadence so an answer to a new attack shape ships without an engine release.

`pii/` holds the keyword lists the PII recognisers read — anchor and context words
per locale, and which recognisers the `health` profile switches on. They are
words, never patterns: the candidate shapes and validators are code in
`@tunedness/mcpguard-detect`. They are digested on their own (`piiDigest`), apart
from the ruleset's `digest`.

The package declares **no dependencies**. `@tunedness/mcpguard-detect` validates, digests
and compiles what it finds here; nothing is executed from this package.

## License

Apache-2.0. See [NOTICE](NOTICE).
