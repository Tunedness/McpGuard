/**
 * The checks a policy must pass before it is allowed to run.
 *
 * A policy can parse and compile and still ask for something this build cannot
 * honour: a correlation tag with no key to compute it, a checkpoint sink that
 * does not exist yet. Dropping either silently would be a security control that
 * reads as applied and is not, so `validate` and `wrap` both refuse up front.
 */
import type { GuardPolicy } from '@mcpguard/core';
import { CliError, EXIT } from './errors.js';

/** The environment a key is read from. */
export type Env = Readonly<Record<string, string | undefined>>;

/** Reads a non-empty value from the environment variable a policy names. */
export function readKey(env: Env, name: string | undefined): string | undefined {
  if (name === undefined) return undefined;
  const value = env[name];
  return value === undefined || value === '' ? undefined : value;
}

/**
 * Refuses a policy that asks for something it cannot deliver.
 *
 * @throws {CliError} with the policy exit code, naming the key and the fix.
 */
export function assertPolicyRunnable(policy: GuardPolicy, env: Env): void {
  if (policy.pii.enabled && policy.pii.correlation_tags) {
    const name = policy.pii.correlation_key_env;
    if (name === undefined) {
      throw new CliError('pii.correlation_tags is on but pii.correlation_key_env is not set', {
        exitCode: EXIT.policy,
        hints: [
          'name the environment variable that holds the tag key: pii.correlation_key_env',
          'or turn pii.correlation_tags off',
        ],
      });
    }
    if (readKey(env, name) === undefined) {
      throw new CliError(`pii.correlation_tags needs a key, but $${name} is not set or is empty`, {
        exitCode: EXIT.policy,
        hints: [`export ${name}=<secret> before running, or turn pii.correlation_tags off`],
      });
    }
  }

  if (policy.audit.checkpoint_to === 'syslog') {
    throw new CliError('audit.checkpoint_to: syslog is not supported yet (P1, Faz 23)', {
      exitCode: EXIT.policy,
      hints: ['use checkpoint_to: stderr or none until the syslog sink lands'],
    });
  }
}
