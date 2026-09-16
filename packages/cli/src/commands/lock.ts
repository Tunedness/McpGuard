/**
 * `mcpguard lock show`: inspect the manifest lock.
 *
 * The lock is written on first contact by `wrap` (trust-on-first-use) and
 * checked on every later run. This command reads it back so an operator can see
 * what is pinned, and — with `diff` against a live server — what changed. The
 * live diff needs a running server, so in this phase `lock` reads and prints;
 * the write and the TOFU check happen inside `wrap`.
 */
import { readFileSync } from 'node:fs';
import type { GuardLock } from '@mcpguard/core';
import { loadPolicy } from '../config.js';
import { CliError, EXIT } from '../errors.js';
import { type CliContext, writeLines } from '../io.js';

/** The `lock` help text. */
export function lockHelp(): string[] {
  return ['Usage: mcpguard lock show [--policy <path>]', '', 'Prints the pinned server manifests.'];
}

/** Runs the lock command. */
export function runLock(context: CliContext, argv: readonly string[]): number {
  const [sub] = argv;
  if (sub === undefined || sub === '--help' || sub === '-h') {
    writeLines(context.stdout, lockHelp());
    return sub === undefined ? EXIT.usage : EXIT.ok;
  }
  if (sub !== 'show') {
    throw new CliError(`unknown lock subcommand: ${sub}`, {
      hints: ['`show` is the only one today'],
    });
  }

  const loaded = loadPolicy(context.cwd, context.env, undefined);
  const path = loaded.policy.lock.path.startsWith('/')
    ? loaded.policy.lock.path
    : `${loaded.dir}/${loaded.policy.lock.path}`;
  let lock: GuardLock;
  try {
    lock = JSON.parse(readFileSync(path, 'utf8')) as GuardLock;
  } catch {
    throw new CliError(`no lock file at ${path}`, {
      exitCode: EXIT.usage,
      hints: ['it is written on the first `wrap` run'],
    });
  }

  const lines = [`lock: ${path}`];
  for (const [server, entry] of Object.entries(lock.servers)) {
    lines.push(`  ${server}: ${entry.tools.length} tool(s), set ${entry.toolsHash.slice(0, 12)}`);
    for (const tool of entry.tools) lines.push(`    ${tool.name} ${tool.hash.slice(0, 12)}`);
  }
  writeLines(context.stdout, lines);
  return EXIT.ok;
}
