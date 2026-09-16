/**
 * `mcpguard scan <file>`: scan a file with the ruleset, no server in the way.
 *
 * Both a debugging aid and the tool a ruleset author reaches for: it runs the
 * real scanner over a file's contents and prints the verdict, so "why did this
 * flag" has an answer that does not need a running proxy.
 */
import { readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { compilePolicy } from '@mcpguard/core';
import { scanContent } from '@mcpguard/detect';
import { loadPolicy } from '../config.js';
import { CliError, EXIT } from '../errors.js';
import { type CliContext, writeLines } from '../io.js';
import { loadShippedRuleset } from '../ruleset.js';
import { scanOptionsFor } from '../runtime.js';

/** The `scan` help text. */
export function scanHelp(): string[] {
  return [
    'Usage: mcpguard scan [--policy <path>] <file>',
    '',
    'Scans a file with the ruleset and prints the verdict.',
  ];
}

/** Runs the scan command. */
export function runScan(context: CliContext, argv: readonly string[]): number {
  const [flag, maybePolicy, ...rest] = argv;
  let policyPath: string | undefined;
  let file: string | undefined;
  if (flag === '--help' || flag === '-h') {
    writeLines(context.stdout, scanHelp());
    return EXIT.ok;
  }
  if (flag === '--policy' || flag === '-p') {
    policyPath = maybePolicy;
    file = rest[0];
  } else {
    file = flag;
  }
  if (file === undefined) {
    throw new CliError('scan needs a file to scan', {
      hints: ['example: mcpguard scan result.txt'],
    });
  }

  const path = isAbsolute(file) ? file : resolve(context.cwd, file);
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw new CliError(`file not found: ${file}`, { exitCode: EXIT.usage });
  }

  const loaded = loadPolicy(context.cwd, context.env, policyPath);
  const compiled = compilePolicy(loaded.policy);
  const ruleset = loadShippedRuleset();
  const options = scanOptionsFor(loaded.policy, compiled, 'scan', 'file');
  const verdict = scanContent(
    { id: file, text, kind: 'tool_result', mimeType: mimeOf(file) },
    ruleset,
    options,
  );

  writeLines(context.stdout, [
    `file: ${file}`,
    `ruleset: ${verdict.rulesetVersion} (${verdict.rulesetDigest.slice(0, 12)})`,
    `score: ${verdict.score}`,
    `action: ${verdict.action}`,
    `findings: ${verdict.findings.length === 0 ? 'none' : ''}`,
    ...verdict.findings.map(
      (f) => `  ${f.family} ${f.ruleId} (weight ${f.weight}) — ${f.evidence}`,
    ),
    `pii: ${verdict.piiFindings.length === 0 ? 'none' : verdict.piiFindings.map((p) => p.kind).join(', ')}`,
  ]);
  return verdict.action === 'allow' ? EXIT.ok : EXIT.integrity;
}

function mimeOf(file: string): string {
  if (file.endsWith('.md')) return 'text/markdown';
  if (file.endsWith('.json')) return 'application/json';
  if (file.endsWith('.html')) return 'text/html';
  return 'text/plain';
}
