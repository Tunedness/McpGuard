/**
 * `mcpguard audit verify|show`: read the audit log back and check its chain.
 *
 * `verify` is the command that answers "was this log tampered with" — it walks
 * the hash chain and names the first record that does not hold. `show` prints
 * the records a human can read, masked content and all.
 */
import { readFileSync } from 'node:fs';
import { type AuditRecord, verifyChain } from '@mcpguard/core';
import { loadPolicy } from '../config.js';
import { CliError, EXIT } from '../errors.js';
import { type CliContext, writeLines } from '../io.js';

/** The `audit` help text. */
export function auditHelp(): string[] {
  return [
    'Usage: mcpguard audit <verify|show> [--policy <path>] [path]',
    '',
    '  verify   Walk the hash chain and report the first break, if any.',
    '  show     Print the records.',
  ];
}

/** Runs the audit command. */
export function runAudit(context: CliContext, argv: readonly string[]): number {
  const [sub, ...rest] = argv;
  if (sub === undefined || sub === '--help' || sub === '-h') {
    writeLines(context.stdout, auditHelp());
    return sub === undefined ? EXIT.usage : EXIT.ok;
  }
  if (sub !== 'verify' && sub !== 'show') {
    throw new CliError(`unknown audit subcommand: ${sub}`, { hints: ['use `verify` or `show`'] });
  }

  const path = auditPath(context, rest);
  const records = readRecords(path);

  if (sub === 'verify') {
    const result = verifyChain(records);
    if (result.ok) {
      writeLines(context.stdout, [
        `audit chain intact: ${records.length} record(s)`,
        `head: ${result.head}`,
      ]);
      return EXIT.ok;
    }
    writeLines(context.stderr, [
      `audit chain broken at record ${result.brokeAt}: ${result.reason}`,
      'the log was altered after it was written',
    ]);
    return EXIT.integrity;
  }

  writeLines(
    context.stdout,
    records.map(
      (r) =>
        `#${r.seq} ${new Date(r.at).toISOString()} ${r.serverName}__${r.toolName ?? '-'} ${r.action}` +
        (r.score !== undefined ? ` score=${r.score}` : '') +
        (r.findings.length > 0 ? ` findings=${r.findings.join(',')}` : ''),
    ),
  );
  return EXIT.ok;
}

function auditPath(context: CliContext, rest: readonly string[]): string {
  const flagIndex = rest.indexOf('--policy');
  const explicitPolicy = flagIndex >= 0 ? rest[flagIndex + 1] : undefined;
  const positional = rest.filter((a, i) => a !== '--policy' && rest[i - 1] !== '--policy');
  if (positional[0] !== undefined) {
    return positional[0].startsWith('/') ? positional[0] : `${context.cwd}/${positional[0]}`;
  }
  const loaded = loadPolicy(context.cwd, context.env, explicitPolicy);
  const path = loaded.policy.audit.path;
  return path.startsWith('/') ? path : `${loaded.dir}/${path}`;
}

function readRecords(path: string): AuditRecord[] {
  let source: string;
  try {
    source = readFileSync(path, 'utf8');
  } catch {
    throw new CliError(`audit log not found: ${path}`, { exitCode: EXIT.usage });
  }
  const lines = source.split('\n').filter((line) => line.trim() !== '');
  return lines.map((line, i) => {
    try {
      return JSON.parse(line) as AuditRecord;
    } catch {
      throw new CliError(`audit log line ${i + 1} is not valid JSON`, { exitCode: EXIT.integrity });
    }
  });
}
