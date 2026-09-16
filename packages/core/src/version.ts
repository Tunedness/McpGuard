/**
 * Version of `@mcpguard/core`.
 *
 * A hand-maintained constant rather than a read of `package.json`: nothing in
 * this package touches the filesystem, and the purity test is what says so.
 * `packaging.test.ts` in the CLI fails the build if this diverges from the
 * manifest.
 */
export const CORE_VERSION = '0.0.0';
