import { describe, expect, it } from 'vitest';
import { COMMANDS, run, usage } from './cli.js';
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

  it.each(COMMANDS)('says plainly that %s is not built yet', async (command) => {
    // Better than a silent success: a skeleton that pretends to guard something
    // is worse than one that refuses to.
    const { ctx, stderr } = context([command]);

    await expect(run(ctx)).resolves.toBe(EXIT.usage);
    expect(stderr.text).toContain('not implemented yet');
  });
});
