/**
 * `@mcpguard/detect` — the tier-1 detection engine.
 *
 * Deterministic by construction, and that word is load-bearing here rather than
 * decorative: the score path is integer arithmetic, the ruleset is data with a
 * digest, and the same content scanned with the same ruleset on any platform
 * produces the same verdict, byte for byte. A committed verdict snapshot is
 * what proves it (see ADR-009).
 *
 * The package is pure for the same reason `@mcpguard/core` is, and is separate
 * from it because ADR-002 says the hot path must be able to move to a native
 * module without dragging the rest of the engine along.
 */
export { DETECT_VERSION } from './version.js';
