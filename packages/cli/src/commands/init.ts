/**
 * `mcpguard init`: write a starter policy.
 *
 * The starter is deliberately the safe posture: observe mode, nothing blocked,
 * PII masking on, audit on. It is a policy an operator can drop in and measure
 * with, then tighten — not one that surprises them by blocking traffic on the
 * first run.
 */
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { CliError, EXIT } from '../errors.js';
import { type CliContext, writeLines } from '../io.js';

const STARTER = `# McpGuard policy. Starts safe: observe mode, nothing blocked, PII masked.
# Tighten once you have measured your own traffic — see \`mcpguard validate\`.
version: 1

# 'flag' observes and records without blocking; switch to 'enforce' to let
# deny / block / strip actually happen.
mode: flag

scan:
  default:
    action: flag        # flag | strip | block  (block is opt-in, per-tool)
    flag_at: 40
    block_at: 70
  # Per-tool overrides, keyed by <server>__<tool> glob:
  # tools:
  #   "mail__send": { action: block }

pii:
  enabled: true
  strict_checksum: true # false also masks a keyworded checksum failure (KVKK)

audit:
  enabled: true
  path: .mcpguard/audit.jsonl

lock:
  enabled: true
  path: guardlock.json
`;

/** The `init` help text. */
export function initHelp(): string[] {
  return [
    'Usage: mcpguard init [--force]',
    '',
    'Writes a starter guardpolicy.yaml in the current directory.',
  ];
}

/** Runs the init command. */
export function runInit(context: CliContext, argv: readonly string[]): number {
  if (argv[0] === '--help' || argv[0] === '-h') {
    writeLines(context.stdout, initHelp());
    return EXIT.ok;
  }
  const force = argv.includes('--force');
  const target = join(context.cwd, 'guardpolicy.yaml');
  if (existsSync(target) && !force) {
    throw new CliError('guardpolicy.yaml already exists', {
      hints: ['pass --force to overwrite it'],
    });
  }
  writeFileSync(target, STARTER);
  writeLines(context.stdout, [
    `wrote ${target}`,
    'Review it, then: mcpguard wrap -- <your-server-command>',
  ]);
  return EXIT.ok;
}
