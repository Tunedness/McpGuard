/**
 * `mcpguard validate`: check a policy file and print what it resolves to.
 *
 * The answer to "is this policy valid, and what does it actually mean" without
 * starting a proxy. A misspelled key is a security control that silently did not
 * apply, so this is the command that catches it before an incident does.
 */
import { compilePolicy } from '@mcpguard/core';
import { loadPolicy } from '../config.js';
import { EXIT } from '../errors.js';
import { type CliContext, writeLines } from '../io.js';

/** The `validate` help text. */
export function validateHelp(): string[] {
  return [
    'Usage: mcpguard validate [--policy <path>]',
    '',
    'Validates the policy and prints its resolved form.',
  ];
}

/** Runs the validate command. */
export function runValidate(context: CliContext, argv: readonly string[]): number {
  const [flag, value] = argv;
  if (flag === '--help' || flag === '-h') {
    writeLines(context.stdout, validateHelp());
    return EXIT.ok;
  }
  const policyPath = flag === '--policy' || flag === '-p' ? value : undefined;
  const loaded = loadPolicy(context.cwd, context.env, policyPath);
  // Compiling is the second half of validation: a policy that parses can still
  // carry a glob that does not compile.
  compilePolicy(loaded.policy);
  const p = loaded.policy;

  writeLines(context.stdout, [
    `policy: ${loaded.path ?? '(defaults — no file found)'}`,
    `mode: ${p.mode}`,
    `scan: action=${p.scan.default.action} flag_at=${p.scan.default.flag_at} block_at=${p.scan.default.block_at}`,
    `pii: ${p.pii.enabled ? `on (strict_checksum=${p.pii.strict_checksum})` : 'off'}`,
    `audit: ${p.audit.enabled ? `on → ${p.audit.path}` : 'off'}`,
    `lock: ${p.lock.enabled ? `on → ${p.lock.path}` : 'off'}`,
    `tools: ${p.tools.length} rule(s)`,
    `combinations: ${p.combinations.length} rule(s)`,
    'policy is valid.',
  ]);
  return EXIT.ok;
}
