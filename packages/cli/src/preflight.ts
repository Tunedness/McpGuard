/**
 * The checks a policy must pass before it is allowed to run.
 *
 * A policy can parse and compile and still ask for something this build cannot
 * honour: a correlation tag with no key to compute it, a checkpoint sink that
 * does not exist yet. Dropping either silently would be a security control that
 * reads as applied and is not, so `validate` and `wrap` both refuse up front.
 */
import type { GuardPolicy } from '@tunedness/mcpguard-core';
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
  // A server may turn masking on for itself under a policy that has it off, and its
  // tags need the same key.
  const masks =
    policy.pii.enabled ||
    Object.values(policy.servers).some((server) => server.pii?.enabled === true);
  if (masks && policy.pii.correlation_tags) {
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

  // The judge is shown the text as the policy masks it, and with masking off that
  // is the raw text. Raw text may stay on this machine, to a judge on this machine;
  // it must not leave it (ADR-012 item 7).
  if (policy.judge.enabled && judgeIsRemote(policy) && maskingIsOff(policy)) {
    throw new CliError(
      'the judge is remote, but PII masking is off, so it would be sent the raw text',
      {
        exitCode: EXIT.policy,
        hints: [
          'turn masking on: pii.enabled: true (and no servers.<name>.pii.enabled: false)',
          'or use a judge on this machine: a loopback endpoint and judge.allow_remote: false',
        ],
      },
    );
  }

  // A judge that names a headers variable and finds it empty would send every
  // request unauthenticated and fail every one of them, quietly.
  if (policy.judge.enabled && policy.judge.headers_env !== undefined) {
    if (readKey(env, policy.judge.headers_env) === undefined) {
      throw new CliError(
        `judge.headers_env names $${policy.judge.headers_env}, but it is not set or is empty`,
        {
          exitCode: EXIT.policy,
          hints: [
            `export ${policy.judge.headers_env}='Name=value' before running, or remove judge.headers_env`,
          ],
        },
      );
    }
  }

  if (policy.audit.checkpoint_to === 'syslog') {
    throw new CliError('audit.checkpoint_to: syslog is not supported yet (P1, Faz 23)', {
      exitCode: EXIT.policy,
      hints: ['use checkpoint_to: stderr or none until the syslog sink lands'],
    });
  }
}

/** Whether the judge's text would leave this machine: a remote allowance, or an endpoint that is not loopback. */
function judgeIsRemote(policy: GuardPolicy): boolean {
  if (policy.judge.allow_remote) return true;
  if (policy.judge.endpoint === undefined) return false;
  const host = new URL(policy.judge.endpoint).hostname;
  return host !== 'localhost' && host !== '127.0.0.1' && host !== '[::1]';
}

/** Whether any server, or the policy as a whole, would scan without masking. */
function maskingIsOff(policy: GuardPolicy): boolean {
  return (
    !policy.pii.enabled ||
    Object.values(policy.servers).some((server) => server.pii?.enabled === false)
  );
}
