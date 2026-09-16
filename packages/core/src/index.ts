/**
 * `@mcpguard/core` — the decision engine.
 *
 * ## The purity invariant
 *
 * This package does **no I/O**. It never imports a transport, an MCP SDK,
 * `node:fs`, `node:net` or `node:child_process`. Its only runtime dependency is
 * `zod`; the only Node builtin it touches is `node:crypto`, for SHA-256 and
 * HMAC — computation, not I/O.
 *
 * That is not tidiness for its own sake. A security proxy's decisions have to
 * be reproducible by whoever audits them six months later, and a decision that
 * reads a clock, a file or an environment variable is not. Time arrives through
 * an injected `Clock`, identity through an `IdGenerator`, and the audit key
 * through the caller. `purity.test.ts` enforces all of it on every source file.
 */
export { CORE_VERSION } from './version.js';
