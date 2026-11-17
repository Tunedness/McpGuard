import { parsePolicy } from '@tunedness/mcpguard-core';
import { describe, expect, it } from 'vitest';
import { CliError, EXIT } from '../errors.js';
import { assertPolicyRunnable } from '../preflight.js';

/** The start-up check for a judge that names a headers variable it cannot read. */
describe('assertPolicyRunnable and judge.headers_env', () => {
  const policy = (judge: Record<string, unknown>) =>
    parsePolicy({
      version: 1,
      judge: { enabled: true, endpoint: 'http://127.0.0.1:11434/v1/x', model: 'm', ...judge },
    });

  it('refuses to start when the variable is unset or empty', () => {
    for (const env of [{}, { JUDGE_HEADERS: '' }]) {
      try {
        assertPolicyRunnable(policy({ headers_env: 'JUDGE_HEADERS' }), env);
        expect.unreachable();
      } catch (error) {
        expect(error).toBeInstanceOf(CliError);
        expect((error as CliError).exitCode).toBe(EXIT.policy);
        expect((error as CliError).message).toContain('$JUDGE_HEADERS');
      }
    }
  });

  it('starts when it is set, when none is named, and when the judge is off', () => {
    expect(() =>
      assertPolicyRunnable(policy({ headers_env: 'JUDGE_HEADERS' }), { JUDGE_HEADERS: 'A=b' }),
    ).not.toThrow();
    expect(() => assertPolicyRunnable(policy({}), {})).not.toThrow();
    expect(() =>
      assertPolicyRunnable(policy({ enabled: false, headers_env: 'JUDGE_HEADERS' }), {}),
    ).not.toThrow();
  });
});
