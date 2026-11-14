import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { run, usage } from './cli.js';
import { EXIT } from './errors.js';
import { versionBanner } from './index.js';
import { StringWriter } from './io.js';

/**
 * The dispatcher, which is the one piece of the CLI that exists in phase 1.
 *
 * Every case here is about a promise that outlives the skeleton: that a command
 * returns a code instead of killing the process, that an unrecognised word gets
 * an answer a person can act on, and that no command writes to a stream it was
 * not handed.
 */

function context(argv: readonly string[]) {
  const stdout = new StringWriter();
  const stderr = new StringWriter();
  return { ctx: { argv, stdout, stderr, env: {}, cwd: '/' }, stdout, stderr };
}

describe('run', () => {
  it('prints the usage and reports a usage code when given nothing', async () => {
    const { ctx, stdout, stderr } = context([]);

    await expect(run(ctx)).resolves.toBe(EXIT.usage);
    expect(stdout.lines[0]).toBe('mcpguard — a security proxy for MCP servers');
    expect(stderr.text).toBe('');
  });

  it.each(['--help', '-h'])('prints the usage and succeeds for %s', async (flag) => {
    const { ctx, stdout } = context([flag]);

    await expect(run(ctx)).resolves.toBe(EXIT.ok);
    expect(stdout.lines).toEqual(usage());
  });

  it.each(['--version', '-v'])('prints every package version for %s', async (flag) => {
    const { ctx, stdout } = context([flag]);

    await expect(run(ctx)).resolves.toBe(EXIT.ok);
    // The banner names core, detect and proxy as well: a bug report that quotes
    // one version number is a bug report missing three.
    expect(stdout.lines).toEqual([versionBanner()]);
  });

  it('answers an unknown command on stderr, with the known ones', async () => {
    const { ctx, stdout, stderr } = context(['wrpa']);

    await expect(run(ctx)).resolves.toBe(EXIT.usage);
    expect(stdout.text).toBe('');
    expect(stderr.text).toContain('unknown command: wrpa');
    expect(stderr.text).toContain('wrap');
  });

  it('refuses wrap with no server command, and says how to give one', async () => {
    const { ctx, stderr } = context(['wrap']);

    await expect(run(ctx)).resolves.toBe(EXIT.usage);
    expect(stderr.text).toContain('server command');
  });

  it('says plainly that serve is not built yet', async () => {
    // The one command that is honestly deferred: a skeleton that pretended to be
    // a guarded gateway would be worse than one that says it is not.
    const { ctx, stderr } = context(['serve']);

    await expect(run(ctx)).resolves.toBe(EXIT.usage);
    expect(stderr.text).toContain('not built yet');
  });

  it('runs a real command: validate reports the default posture', async () => {
    const { ctx, stdout } = context(['validate']);

    await expect(run(ctx)).resolves.toBe(EXIT.ok);
    expect(stdout.text).toContain('policy is valid');
  });
});

describe('run: a policy this build cannot honour stops at startup', () => {
  let dir: string | undefined;
  afterEach(() => {
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
  });

  function inDir(policy: string, argv: readonly string[], env: Record<string, string> = {}) {
    dir = mkdtempSync(join(tmpdir(), 'mcpguard-run-'));
    writeFileSync(join(dir, 'guardpolicy.yaml'), policy);
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    return { ctx: { argv, stdout, stderr, env, cwd: dir }, stderr };
  }

  it('exits non-zero from validate for checkpoint_to: syslog', async () => {
    const { ctx, stderr } = inDir('version: 1\naudit:\n  checkpoint_to: syslog\n', ['validate']);

    await expect(run(ctx)).resolves.toBe(EXIT.policy);
    expect(stderr.text).toContain('syslog is not supported yet');
  });

  it('exits non-zero from wrap for checkpoint_to: syslog, before spawning anything', async () => {
    const { ctx, stderr } = inDir('version: 1\naudit:\n  checkpoint_to: syslog\n', [
      'wrap',
      '--',
      'node',
      '-e',
      '0',
    ]);

    await expect(run(ctx)).resolves.toBe(EXIT.policy);
    expect(stderr.text).toContain('syslog is not supported yet');
  });

  it('exits non-zero from validate and wrap for correlation_tags without a key', async () => {
    const policy = 'version: 1\npii:\n  correlation_tags: true\n  correlation_key_env: TAG_KEY\n';
    const validate = inDir(policy, ['validate']);
    await expect(run(validate.ctx)).resolves.toBe(EXIT.policy);

    const wrap = inDir(policy, ['wrap', '--', 'node', '-e', '0']);
    await expect(run(wrap.ctx)).resolves.toBe(EXIT.policy);
    expect(wrap.stderr.text).toContain('$TAG_KEY');
  });

  it('refuses an empty MCPGUARD_IDENTITY rather than falling to clientInfo', async () => {
    for (const value of ['', '  ']) {
      const { ctx, stderr } = inDir('version: 1\n', ['wrap', '--', 'node', '-e', '0'], {
        MCPGUARD_IDENTITY: value,
      });

      await expect(run(ctx)).resolves.toBe(EXIT.usage);
      expect(stderr.text).toContain('MCPGUARD_IDENTITY is set but empty');
    }
  });

  it('does not stop on an empty MCPGUARD_IDENTITY when --identity is given', async () => {
    // The env rung is never read once the flag answers, so the stray export is
    // harmless. The start then fails on the server command, not on the env.
    const { ctx, stderr } = inDir(
      'version: 1\n',
      ['wrap', '--identity', 'alice', '--', 'mcpguard-no-such-command'],
      { MCPGUARD_IDENTITY: '' },
    );

    await expect(run(ctx)).resolves.not.toBe(EXIT.usage);
    expect(stderr.text).not.toContain('MCPGUARD_IDENTITY is set but empty');
  });

  it('refuses --identity followed by another flag, not taking the flag as the name', async () => {
    const { ctx, stderr } = inDir('version: 1\n', [
      'wrap',
      '--identity',
      '--name',
      'echo',
      '--',
      'node',
      '-e',
      '0',
    ]);

    await expect(run(ctx)).resolves.toBe(EXIT.usage);
    expect(stderr.text).toContain('--identity needs a value');
  });

  it('refuses --identity with no value rather than falling to a heuristic', async () => {
    const { ctx, stderr } = inDir('version: 1\n', ['wrap', '--identity', '--', 'node', '-e', '0']);

    await expect(run(ctx)).resolves.toBe(EXIT.usage);
    expect(stderr.text).toContain('--identity needs a value');
  });
});
