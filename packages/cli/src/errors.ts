/**
 * Exit codes and the one error class every command throws.
 *
 * An error the user can act on carries prose and hints; a stack trace is
 * reserved for McpGuard's own bugs, where it is the useful thing to see.
 */

export const EXIT = {
  ok: 0,
  /** The user asked for something impossible: bad flag, missing file, typo. */
  usage: 2,
  /** A policy file that does not validate. */
  policy: 3,
  /** A ruleset that does not validate, or whose digest does not match. */
  ruleset: 4,
  /** The guarded server changed its manifest, or the audit chain is broken. */
  integrity: 5,
  /** The guarded server or the run itself failed. */
  runtime: 70,
} as const;

/** An error with something the user can do about it. */
export class CliError extends Error {
  readonly exitCode: number;
  readonly hints: readonly string[];

  constructor(
    message: string,
    options: { exitCode?: number; hints?: readonly string[]; cause?: unknown } = {},
  ) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'CliError';
    this.exitCode = options.exitCode ?? EXIT.usage;
    this.hints = options.hints ?? [];
  }
}

/** Normalises a thrown non-Error into something printable. */
export function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Renders a {@link CliError} the way the user sees it. */
export function formatCliError(error: CliError): string {
  const hints = error.hints.map((hint) => `  ${hint}\n`).join('');
  return `mcpguard: ${error.message}\n${hints}`;
}
