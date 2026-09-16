/**
 * Parsing an already-loaded object into a policy.
 *
 * The object arrives parsed. **This package reads no files** — the CLI owns
 * `readFileSync` and the YAML parser, which is also what lets it map a zod
 * issue path back to a byte offset and print `file:line:col`. Core's job is to
 * say whether the document is a policy, not to find it.
 */
import type { z } from 'zod';
import { type GuardPolicy, GuardPolicySchemaV1 } from './schema.js';

/** A policy document that did not validate, with every issue it had. */
export class PolicyValidationError extends Error {
  readonly issues: readonly z.core.$ZodIssue[];

  constructor(issues: readonly z.core.$ZodIssue[]) {
    const summary = issues
      .slice(0, 5)
      .map((issue) => `${pathOf(issue.path)}: ${issue.message}`)
      .join('; ');
    const more = issues.length > 5 ? ` (+${issues.length - 5} more)` : '';
    super(`the policy is not valid — ${summary}${more}`);
    this.name = 'PolicyValidationError';
    this.issues = issues;
  }
}

/** Renders a zod issue path the way it is written in the document. */
export function pathOf(path: readonly PropertyKey[]): string {
  if (path.length === 0) return '(root)';
  let out = '';
  for (const segment of path) {
    if (typeof segment === 'number') out += `[${segment}]`;
    else out += out === '' ? String(segment) : `.${String(segment)}`;
  }
  return out;
}

/**
 * Validates and defaults a policy document.
 *
 * @throws {PolicyValidationError} when the document is not a valid policy.
 */
export function parsePolicy(document: unknown): GuardPolicy {
  const result = GuardPolicySchemaV1.safeParse(document);
  if (!result.success) throw new PolicyValidationError(result.error.issues);
  return result.data;
}

/** The policy a file containing only `version: 1` resolves to. */
export function defaultPolicy(): GuardPolicy {
  return parsePolicy({ version: 1 });
}
