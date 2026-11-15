/**
 * Parsing `serve`'s own flags without eating the child's.
 *
 * As with `wrap`, everything after the first bare `--` is a server command and
 * its arguments, handed on untouched. Before it, `--upstream` names an HTTP
 * upstream instead; a command and a URL together is a mistake, not a choice.
 */
export interface ServeArgs {
  readonly policy: string | undefined;
  readonly name: string | undefined;
  readonly upstream: string | undefined;
  readonly host: string | undefined;
  readonly port: string | undefined;
  readonly help: boolean;
  readonly command: string | undefined;
  readonly args: readonly string[];
  /** Flags that were not understood, so the command can name them instead of ignoring them. */
  readonly unknown: readonly string[];
}

/** Reads a flag's value, or `''` when it has none (the next token is a flag or absent). */
function valueAt(argv: readonly string[], index: number): string {
  const value = argv[index];
  return value === undefined || value.startsWith('-') ? '' : value;
}

export function parseServeArgs(argv: readonly string[]): ServeArgs {
  let policy: string | undefined;
  let name: string | undefined;
  let upstream: string | undefined;
  let host: string | undefined;
  let port: string | undefined;
  let help = false;
  const unknown: string[] = [];
  let i = 0;
  for (; i < argv.length; i++) {
    const arg = argv[i] as string;
    if (arg === '--') {
      i++;
      break;
    }
    const take = (): string => {
      const value = valueAt(argv, i + 1);
      if (value !== '') i++;
      return value;
    };
    if (arg === '--help' || arg === '-h') help = true;
    else if (arg === '--policy' || arg === '-p') policy = take();
    else if (arg === '--name' || arg === '-n') name = take();
    else if (arg === '--upstream' || arg === '-u') upstream = take();
    else if (arg === '--host') host = take();
    else if (arg === '--port') port = take();
    else unknown.push(arg);
  }
  const rest = argv.slice(i);
  return {
    policy,
    name,
    upstream,
    host,
    port,
    help,
    command: rest[0],
    args: rest.slice(1),
    unknown,
  };
}
