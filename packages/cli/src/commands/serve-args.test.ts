import { describe, expect, it } from 'vitest';
import { parseServeArgs } from './serve-args.js';

describe('parseServeArgs', () => {
  it('reads the flags before the `--` and hands the command after it on untouched', () => {
    const parsed = parseServeArgs([
      '--name',
      'echo',
      '--port',
      '9000',
      '--',
      'node',
      'server.mjs',
      '--port',
      '1',
      '--name',
      'inner',
    ]);
    expect(parsed).toMatchObject({
      name: 'echo',
      port: '9000',
      command: 'node',
      args: ['server.mjs', '--port', '1', '--name', 'inner'],
      unknown: [],
    });
  });

  it('reads an HTTP upstream and the short flags', () => {
    expect(
      parseServeArgs(['-p', 'p.yaml', '-n', 'x', '-u', 'https://a.example/mcp']),
    ).toMatchObject({
      policy: 'p.yaml',
      name: 'x',
      upstream: 'https://a.example/mcp',
      command: undefined,
    });
  });

  it('reports a flag with no value as empty, and does not swallow the next flag or the `--`', () => {
    expect(parseServeArgs(['--port', '--name', 'x'])).toMatchObject({ port: '', name: 'x' });
    expect(parseServeArgs(['--host', '--', 'node'])).toMatchObject({ host: '', command: 'node' });
    expect(parseServeArgs(['--upstream'])).toMatchObject({ upstream: '' });
  });

  it('names a flag it does not know instead of ignoring it', () => {
    expect(parseServeArgs(['--prot', '9', '--help']).unknown).toEqual(['--prot', '9']);
    expect(parseServeArgs(['-h']).help).toBe(true);
  });
});
