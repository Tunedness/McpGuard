import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePolicy, type SecurityEvent } from '@tunedness/mcpguard-core';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../cli.js';
import { CliError, EXIT } from '../errors.js';
import { type CliContext, StringWriter } from '../io.js';
import { checkServerName, reportUnmatchedServer } from '../server-name.js';

/**
 * A server name the policy's `servers` section does not carry: refused at start
 * under `mode: enforce`, reported and let through under `mode: flag`. The
 * refusals are tested here, in this process, for `wrap` and for `serve`; the
 * starts that go on are tested in real processes (`wrap-identity.test.ts`,
 * `serve-process.test.ts`).
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const ECHO = join(HERE, '..', 'testing', 'fixtures', 'echo-server.mjs');

const policyText = (mode: 'enforce' | 'flag', servers = 'servers:\n  fs:\n    roles: [admin]\n') =>
  `version: 1\nmode: ${mode}\n${servers}`;

describe('checkServerName', () => {
  const policy = (mode: 'enforce' | 'flag', servers: Record<string, unknown>) =>
    parsePolicy({ version: 1, mode, servers });

  it('has nothing to say when the policy has no servers section, in either mode', () => {
    expect(checkServerName(policy('enforce', {}), 'anything', 'wrap', true)).toBeUndefined();
    expect(checkServerName(policy('flag', {}), 'anything', 'wrap', true)).toBeUndefined();
  });

  it('has nothing to say about a name the section carries, an empty entry included', () => {
    const servers = { fs: { roles: ['admin'] }, other: {} };
    expect(checkServerName(policy('enforce', servers), 'fs', 'wrap', true)).toBeUndefined();
    expect(checkServerName(policy('enforce', servers), 'other', 'serve', true)).toBeUndefined();
  });

  it('refuses an unmatched name under enforce, naming it, the keys and the way out', () => {
    let caught: unknown;
    try {
      checkServerName(policy('enforce', { fs: { roles: ['admin'] } }), 'f', 'wrap', true);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(CliError);
    const error = caught as CliError;
    expect(error.exitCode).toBe(EXIT.policy);
    expect(error.message).toContain('"f"');
    expect(error.message).toContain('fs');
    expect(error.hints.join('\n')).toContain('servers: { f: {} }');
  });

  it('says there was no --name when none was given', () => {
    expect(() => checkServerName(policy('enforce', { fs: {} }), 'server', 'wrap', false)).toThrow(
      /"server" \(no --name given\)/,
    );
  });

  it('reports instead of refusing under flag', () => {
    const unmatched = checkServerName(policy('flag', { fs: {} }), 'f', 'serve', true);
    expect(unmatched).toMatchObject({ server: 'f', defined: ['fs'], via: 'serve' });
  });

  it.each(['constructor', 'toString', '__proto__', 'hasOwnProperty'])(
    'does not take %s, a property every object has, for a server the policy named',
    (name) => {
      expect(() => checkServerName(policy('enforce', { fs: {} }), name, 'wrap', true)).toThrow(
        CliError,
      );
    },
  );

  it('clips a long name and a long list of keys in what it reports', () => {
    const servers = Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`s${i}`, {}]));
    const unmatched = checkServerName(policy('flag', servers), 'x'.repeat(300), 'wrap', true);
    expect(unmatched?.server).toHaveLength(64);
    expect(unmatched?.defined).toHaveLength(20);
  });
});

describe('reportUnmatchedServer', () => {
  it('writes a diagnostic and a security_event, and says the start goes on', () => {
    const lines: Array<[string, Record<string, unknown>]> = [];
    const events: SecurityEvent[] = [];
    reportUnmatchedServer(
      { server: 'f', defined: ['fs'], via: 'wrap', hint: 'add servers: { f: {} }' },
      (event, detail) => lines.push([event, detail]),
      { emit: (event) => events.push(event) },
      () => 42,
      'SESSION',
    );

    expect(lines[0]?.[0]).toBe('server_unmatched');
    expect(lines[0]?.[1]).toMatchObject({ server: 'f', defined: ['fs'], action: 'flag' });
    expect(events).toEqual([
      expect.objectContaining({
        type: 'security_event',
        kind: 'server_unmatched',
        at: 42,
        sessionId: 'SESSION',
        serverName: 'f',
        action: 'flag',
        evidence: ['servers.f'],
      }),
    ]);
  });
});

describe('the start refused, in this process', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcpguard-server-name-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function start(argv: string[], policy: string) {
    writeFileSync(join(dir, 'guardpolicy.yaml'), policy);
    const stderr = new StringWriter();
    const ctx: CliContext = {
      argv,
      stdout: new StringWriter(),
      stderr,
      env: { PATH: process.env.PATH },
      cwd: dir,
      onShutdown: () => {},
    };
    return { ctx, stderr };
  }

  it.each([
    ['without --name', ['wrap', '--', 'node', ECHO], '"server" (no --name given)'],
    ['with a name that is a typo', ['wrap', '--name', 'f', '--', 'node', ECHO], '"f"'],
  ])('wrap under enforce, %s, stops with the policy exit code', async (_label, argv, shown) => {
    const { ctx, stderr } = start(argv, policyText('enforce'));

    expect(await run(ctx)).toBe(EXIT.policy);
    expect(stderr.text).toContain(shown);
    expect(stderr.text).toContain('it names: fs');
    expect(stderr.text).toContain('servers: {');
  });

  it.each([
    ['without --name', ['serve', '--port', '0', '--', 'node', ECHO], '"server" (no --name given)'],
    [
      'with a name that is a typo',
      ['serve', '--port', '0', '--name', 'f', '--upstream', 'http://127.0.0.1:9/mcp'],
      '"f"',
    ],
  ])(
    'serve under enforce, a command-line upstream %s, stops with the policy exit code',
    async (_label, argv, shown) => {
      const { ctx, stderr } = start(argv, policyText('enforce'));

      expect(await run(ctx)).toBe(EXIT.policy);
      expect(stderr.text).toContain(shown);
      expect(stderr.text).not.toContain('serve_started');
    },
  );
});
