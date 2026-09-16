/**
 * The command table and the dispatcher.
 *
 * Hand-written, with no argument-parsing dependency. Two reasons, and the first
 * is not stylistic: `mcpguard wrap -- node server.mjs --verbose` has to hand the
 * child its own flags untouched, and a parser that owns the whole argv will eat
 * them. The second is that per-command flag declarations turn an unknown flag
 * into a typo suggestion rather than a silent no-op.
 */
import { CliError, EXIT, formatCliError } from './errors.js';
import { versionBanner } from './index.js';
import { type CliContext, writeLines } from './io.js';

export const COMMANDS = ['wrap', 'serve', 'init', 'validate', 'lock', 'audit', 'scan'] as const;
export type Command = (typeof COMMANDS)[number];

function isCommand(value: string): value is Command {
  return (COMMANDS as readonly string[]).includes(value);
}

/** The `--help` text, as lines. */
export function usage(): string[] {
  return [
    'mcpguard — a security proxy for MCP servers',
    '',
    'Usage: mcpguard <command> [options]',
    '',
    'Commands:',
    '  wrap      Guard one stdio MCP server: mcpguard wrap -- <server-cmd>',
    '  serve     Guarded HTTP gateway in front of N servers',
    '  init      Write a starter guardpolicy.yaml',
    '  validate  Check a policy file and print what it resolves to',
    '  lock      Inspect, create or update guardlock.json',
    '  audit     Verify the audit chain, or read records back',
    '  scan      Scan a file with the ruleset, without a server in the way',
    '',
    'Run `mcpguard <command> --help` for a command.',
  ];
}

/** Runs one invocation and returns its exit code. Never throws a `CliError`. */
export async function run(context: CliContext): Promise<number> {
  try {
    return await dispatch(context);
  } catch (error) {
    if (error instanceof CliError) {
      context.stderr.write(formatCliError(error));
      return error.exitCode;
    }
    // A bug in McpGuard keeps its stack: that is the useful thing to see.
    throw error;
  }
}

async function dispatch(context: CliContext): Promise<number> {
  const [first] = context.argv;
  if (first === undefined) {
    writeLines(context.stdout, usage());
    return EXIT.usage;
  }
  if (first === '--version' || first === '-v') {
    writeLines(context.stdout, [versionBanner()]);
    return EXIT.ok;
  }
  if (first === '--help' || first === '-h') {
    writeLines(context.stdout, usage());
    return EXIT.ok;
  }
  if (!isCommand(first)) {
    throw new CliError(`unknown command: ${first}`, {
      hints: [`known commands: ${COMMANDS.join(', ')}`],
    });
  }

  // No `default`: the switch is exhaustive over `Command`, so adding an entry
  // to `COMMANDS` fails the build until it is wired up here.
  switch (first) {
    case 'wrap':
    case 'serve':
    case 'init':
    case 'validate':
    case 'lock':
    case 'audit':
    case 'scan':
      throw new CliError(`\`${first}\` is not implemented yet`, {
        exitCode: EXIT.usage,
        hints: ['This is the phase 1 skeleton; the commands arrive in phases 8 and 11.'],
      });
  }
}
