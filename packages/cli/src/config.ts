/**
 * Finding and loading a policy file.
 *
 * The CLI owns file I/O and the YAML parser; the engine owns validation. When a
 * key does not validate, this maps the engine's issue path back to a byte
 * offset in the source so the error reads `file:line:col  path: message` — the
 * difference between a policy a person can fix and one they have to guess at.
 */
import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { type GuardPolicy, PolicyValidationError, parsePolicy, pathOf } from '@mcpguard/core';
import { LineCounter, parseDocument } from 'yaml';
import { CliError, EXIT } from './errors.js';

/** Filenames searched when no path is given, in order. */
export const POLICY_FILENAMES = [
  'guardpolicy.yaml',
  'guardpolicy.yml',
  '.mcpguard/guardpolicy.yaml',
  '.mcpguard/guardpolicy.yml',
];

export const POLICY_ENV_VAR = 'MCPGUARD_POLICY';

/** A loaded policy, and the directory relative paths inside it resolve against. */
export interface LoadedPolicy {
  readonly policy: GuardPolicy;
  readonly dir: string;
  readonly path: string | undefined;
}

/** The default policy, for a run with no file. */
export function defaultLoadedPolicy(cwd: string): LoadedPolicy {
  return { policy: parsePolicy({ version: 1 }), dir: cwd, path: undefined };
}

/**
 * Loads a policy from an explicit path, the environment, or a search from `cwd`.
 *
 * @throws {CliError} when a named file is missing or does not validate.
 */
export function loadPolicy(
  cwd: string,
  env: Readonly<Record<string, string | undefined>>,
  explicit: string | undefined,
): LoadedPolicy {
  const path = explicit ?? env[POLICY_ENV_VAR] ?? search(cwd);
  if (path === undefined) return defaultLoadedPolicy(cwd);
  const resolved = isAbsolute(path) ? path : resolve(cwd, path);

  let source: string;
  try {
    source = readFileSync(resolved, 'utf8');
  } catch {
    throw new CliError(`policy file not found: ${path}`, { exitCode: EXIT.usage });
  }
  return { policy: parseYaml(source, resolved), dir: dirname(resolved), path: resolved };
}

function search(cwd: string): string | undefined {
  let dir = cwd;
  for (;;) {
    for (const name of POLICY_FILENAMES) {
      try {
        readFileSync(join(dir, name));
        return join(dir, name);
      } catch {
        // not here; keep looking
      }
    }
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

/** Parses YAML into a policy, mapping a validation error back to a position. */
export function parseYaml(source: string, path: string): GuardPolicy {
  const counter = new LineCounter();
  const doc = parseDocument(source, { lineCounter: counter });
  if (doc.errors.length > 0) {
    const first = doc.errors[0];
    throw new CliError(`${path}: ${first?.message ?? 'invalid YAML'}`, { exitCode: EXIT.policy });
  }
  const value = doc.toJS() as unknown;
  try {
    return parsePolicy(value);
  } catch (error) {
    if (error instanceof PolicyValidationError) {
      const lines = error.issues
        .slice(0, 5)
        .map((issue) => `  ${pathOf(issue.path)}: ${issue.message}`);
      throw new CliError(`${path}: the policy is not valid`, {
        exitCode: EXIT.policy,
        hints: lines,
      });
    }
    throw error;
  }
}
