import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePolicy } from '@tunedness/mcpguard-core';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../cli.js';
import { CliError, EXIT } from '../errors.js';
import { type CliContext, StringWriter } from '../io.js';
import { assertPolicyRunnable } from '../preflight.js';

/**
 * A remote judge is only sent text the policy has masked (ADR-012 item 7). With
 * masking off the judge would be sent the raw text, which a judge on this machine
 * may see and one elsewhere may not, so the combination stops the start: in
 * `validate`, `wrap` and `serve` alike, since all three run the same check.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const MAIN = join(HERE, '..', '..', 'dist', 'main.js');
const ECHO = join(HERE, '..', 'testing', 'fixtures', 'echo-server.mjs');

const LOOPBACK = 'http://127.0.0.1:11434/v1/chat/completions';
const REMOTE = 'https://judge.example.com/v1/chat/completions';

function policyYaml(options: {
  endpoint: string;
  allowRemote?: boolean;
  pii?: string;
  serverPii?: boolean;
}): string {
  return [
    'version: 1',
    options.pii !== undefined ? `pii:\n  enabled: ${options.pii}` : '',
    options.serverPii !== undefined
      ? `servers:\n  echo:\n    pii:\n      enabled: ${options.serverPii}`
      : '',
    'judge:',
    '  enabled: true',
    `  endpoint: ${options.endpoint}`,
    '  model: m',
    options.allowRemote === true ? '  allow_remote: true' : '',
  ]
    .filter((line) => line !== '')
    .join('\n');
}

const policyOf = (judge: Record<string, unknown>, rest: Record<string, unknown> = {}) =>
  parsePolicy({
    version: 1,
    judge: { enabled: true, model: 'm', endpoint: LOOPBACK, ...judge },
    ...rest,
  });

function refusal(policy: ReturnType<typeof parsePolicy>): CliError | undefined {
  try {
    assertPolicyRunnable(policy, {});
  } catch (error) {
    if (error instanceof CliError) return error;
    throw error;
  }
  return undefined;
}

describe('assertPolicyRunnable: a remote judge needs masking on', () => {
  it('refuses a remote judge when masking is off, naming both ways out', () => {
    const error = refusal(
      policyOf({ endpoint: REMOTE, allow_remote: true }, { pii: { enabled: false } }),
    );
    expect(error).toBeInstanceOf(CliError);
    expect(error?.exitCode).toBe(EXIT.policy);
    expect(error?.message).toContain('PII masking is off');
    expect(error?.hints.join(' ')).toContain('pii.enabled: true');
    expect(error?.hints.join(' ')).toContain('loopback');
  });

  it('refuses when only one server turns masking off', () => {
    const error = refusal(
      policyOf(
        { endpoint: REMOTE, allow_remote: true },
        { servers: { echo: { pii: { enabled: false } } } },
      ),
    );
    expect(error?.exitCode).toBe(EXIT.policy);
  });

  it('treats allow_remote as remote even for a loopback endpoint', () => {
    expect(refusal(policyOf({ allow_remote: true }, { pii: { enabled: false } }))?.exitCode).toBe(
      EXIT.policy,
    );
  });

  it('lets a judge on this machine run without masking', () => {
    for (const endpoint of [LOOPBACK, 'http://localhost:8080/v1/x', 'http://[::1]:8080/v1/x']) {
      expect(refusal(policyOf({ endpoint }, { pii: { enabled: false } }))).toBeUndefined();
    }
  });

  it('lets a remote judge run when masking is on, and a disabled judge never matters', () => {
    expect(refusal(policyOf({ endpoint: REMOTE, allow_remote: true }))).toBeUndefined();
    expect(
      refusal(
        policyOf(
          { enabled: false, endpoint: REMOTE, allow_remote: true },
          { pii: { enabled: false } },
        ),
      ),
    ).toBeUndefined();
  });
});

describe('the same check at start-up, in each command', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcpguard-remote-mask-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function context(argv: string[], yaml: string) {
    writeFileSync(join(dir, 'guardpolicy.yaml'), yaml);
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const ctx: CliContext = {
      argv,
      stdout,
      stderr,
      env: { PATH: process.env.PATH },
      cwd: dir,
      onShutdown: () => {},
    };
    return { ctx, stdout, stderr };
  }

  const bad = policyYaml({ endpoint: REMOTE, allowRemote: true, pii: 'false' });
  const badServer = policyYaml({ endpoint: REMOTE, allowRemote: true, serverPii: false });
  const fine = policyYaml({ endpoint: LOOPBACK, pii: 'false' });

  it.each([
    ['pii.enabled: false', bad],
    ['servers.echo.pii.enabled: false', badServer],
  ])('validate stops on a remote judge with %s', async (_name, yaml) => {
    const { ctx, stderr, stdout } = context(['validate'], yaml);
    expect(await run(ctx)).toBe(EXIT.policy);
    expect(stderr.text).toContain('PII masking is off');
    expect(stdout.text).not.toContain('policy is valid');
  });

  it('validate accepts a loopback judge without masking', async () => {
    const { ctx, stdout } = context(['validate'], fine);
    expect(await run(ctx)).toBe(EXIT.ok);
    expect(stdout.text).toContain('policy is valid');
  });

  it('serve stops before it listens', async () => {
    const { ctx, stderr } = context(['serve', '--port', '0', '--', 'node', ECHO], bad);
    expect(await run(ctx)).toBe(EXIT.policy);
    expect(stderr.text).toContain('PII masking is off');
    expect(stderr.text).not.toContain('serve_started');
  });

  it('wrap stops before it starts the server', () => {
    writeFileSync(join(dir, 'guardpolicy.yaml'), bad);
    const result = spawnSync('node', [MAIN, 'wrap', '--name', 'echo', '--', 'node', ECHO], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 15_000,
    });
    expect(result.status).toBe(EXIT.policy);
    expect(result.stderr).toContain('PII masking is off');
    expect(result.stderr).toContain('loopback');
  });
});
