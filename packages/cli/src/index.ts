/**
 * The library face of the `mcpguard` package: the version banner and the types
 * a test or an embedder needs.
 */
import { CORE_VERSION } from '@mcpguard/core';
import { DETECT_VERSION } from '@mcpguard/detect';
import { PROXY_VERSION } from '@mcpguard/proxy';

/** Version of the `mcpguard` command line tool. */
export const CLI_VERSION = '0.0.0';

/** What `mcpguard --version` prints. */
export function versionBanner(): string {
  return `mcpguard ${CLI_VERSION} (core ${CORE_VERSION}, detect ${DETECT_VERSION}, proxy ${PROXY_VERSION})`;
}

export { CliError, EXIT, formatCliError, messageOf } from './errors.js';
export type { CliContext, Writer } from './io.js';
export { StringWriter, writeLine, writeLines } from './io.js';
