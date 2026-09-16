/**
 * `@mcpguard/ruleset` — the detection ruleset, as data.
 *
 * ADR-003 keeps the rules out of the code and versions them separately, so an
 * answer to a new attack shape ships without waiting for an engine release.
 * The package therefore declares **no dependencies at all**: it is JSON plus
 * the few lines needed to point at it. `@mcpguard/detect` validates, digests
 * and compiles what it finds here; nothing is executed from this package.
 */
export { RULESET_PACKAGE_VERSION } from './version.js';
