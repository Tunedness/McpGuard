/**
 * Parsing `wrap`'s own flags without eating the child's.
 *
 * Everything after the first bare `--` is the server command and its arguments,
 * handed on untouched. A parser that owned the whole argv would swallow the
 * child's flags, which is why this stops at the `--`.
 */
export interface WrapArgs {
  readonly policy: string | undefined;
  readonly name: string | undefined;
  /**
   * The caller identity, exact by construction (ADR-010). An empty string means
   * the flag was given with no value; the command refuses that rather than let
   * it fall through to the heuristic rung.
   */
  readonly identity: string | undefined;
  readonly help: boolean;
  readonly command: string | undefined;
  readonly args: readonly string[];
}

export function parseWrapArgs(argv: readonly string[]): WrapArgs {
  let policy: string | undefined;
  let name: string | undefined;
  let identity: string | undefined;
  let help = false;
  let i = 0;
  for (; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') {
      i++;
      break;
    }
    if (arg === '--help' || arg === '-h') help = true;
    else if (arg === '--policy' || arg === '-p') policy = argv[++i];
    else if (arg === '--name' || arg === '-n') name = argv[++i];
    else if (arg === '--identity') {
      // A missing value must not swallow the `--` that starts the child command,
      // nor the next flag: both are reported as an empty identity.
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('-')) identity = '';
      else identity = argv[++i];
    }
  }
  const rest = argv.slice(i);
  return { policy, name, identity, help, command: rest[0], args: rest.slice(1) };
}
