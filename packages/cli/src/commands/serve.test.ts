import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { networkInterfaces, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../cli.js';
import { EXIT } from '../errors.js';
import { type CliContext, StringWriter } from '../io.js';
import { DEFAULT_HOST, DEFAULT_PORT, isLoopbackHost } from './serve.js';

/**
 * `serve`, in this process: what it refuses to start on, and what it binds when
 * it does. The refusals are the point — a gateway that starts is reachable, so a
 * configuration that would leave it open has to stop before it listens.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const ECHO = join(HERE, '..', 'testing', 'fixtures', 'echo-server.mjs');

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'mcpguard-serve-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function context(argv: string[], policy?: string) {
  if (policy !== undefined) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'guardpolicy.yaml'), policy);
  }
  const stdout = new StringWriter();
  const stderr = new StringWriter();
  let stop: () => void = () => {};
  const ctx: CliContext = {
    argv: ['serve', ...argv],
    stdout,
    stderr,
    env: { PATH: process.env.PATH },
    cwd: dir,
    onShutdown: (listener) => {
      stop = listener;
    },
  };
  return { ctx, stdout, stderr, stop: () => stop() };
}

const SHA = 'a'.repeat(64);

describe('isLoopbackHost', () => {
  it.each(['127.0.0.1', '127.1.2.3', 'localhost', '::1', '[::1]'])('%s is loopback', (host) => {
    expect(isLoopbackHost(host)).toBe(true);
  });

  it.each(['0.0.0.0', '::', '192.168.1.5', 'gateway.internal', '10.0.0.1', '127.0.0'])(
    '%s is not',
    (host) => {
      expect(isLoopbackHost(host)).toBe(false);
    },
  );
});

describe('what serve refuses to start on', () => {
  it('prints its help', async () => {
    const { ctx, stdout } = context(['--help']);
    expect(await run(ctx)).toBe(EXIT.ok);
    expect(stdout.text).toContain('--upstream <url>');
    expect(stdout.text).toContain(String(DEFAULT_PORT));
  });

  it.each([
    ['no upstream at all', [], 'serve needs an upstream'],
    ['a flag it does not know', ['--prot', '9', '--upstream', 'http://x.example/mcp'], '"--prot"'],
    [
      'both an upstream URL and a command',
      ['--upstream', 'http://x.example/mcp', '--', 'node', ECHO],
      'not both',
    ],
    ['an upstream that is not a URL', ['--upstream', 'not a url'], 'not a URL'],
    ['an upstream that is not http', ['--upstream', 'ftp://x.example/mcp'], 'http: or https:'],
    ['an upstream flag with no value', ['--upstream'], '--upstream needs a'],
    ['a port that is not a number', ['--port', 'eighty', '--', 'node', ECHO], 'not a port number'],
    ['a port out of range', ['--port', '70000', '--', 'node', ECHO], 'not a port number'],
    ['a name that cannot be a path segment', ['--name', 'a/b', '--', 'node', ECHO], 'URL path'],
    ['a command that is not there', ['--', 'no-such-command-anywhere'], 'not found'],
  ])('%s', async (_label, argv, message) => {
    const { ctx, stderr } = context(argv);
    expect(await run(ctx)).toBe(EXIT.usage);
    expect(stderr.text).toContain(message);
  });

  it('a bind that is reachable from the network, without a token and the hostnames it answers to', async () => {
    const { ctx, stderr } = context(['--host', '0.0.0.0', '--port', '0', '--', 'node', ECHO]);
    expect(await run(ctx)).toBe(EXIT.policy);
    expect(stderr.text).toContain('refusing to bind 0.0.0.0');
    expect(stderr.text).toContain('auth.tokens and http.allowed_hosts');
    // And nothing started: no start-up line.
    expect(stderr.text).not.toContain('serve_started');
  });

  it('a network bind with a token but no hostnames, naming only what is missing', async () => {
    const { ctx, stderr } = context(
      ['--host', '0.0.0.0', '--port', '0', '--', 'node', ECHO],
      `version: 1\nauth:\n  tokens:\n    - { identity: alice, token_sha256: "${SHA}" }\n`,
    );
    expect(await run(ctx)).toBe(EXIT.policy);
    expect(stderr.text).toContain('does not set http.allowed_hosts');
    expect(stderr.text).not.toContain('auth.tokens');
  });

  it('a network bind with hostnames but no token', async () => {
    const { ctx, stderr } = context(
      ['--host', '0.0.0.0', '--port', '0', '--', 'node', ECHO],
      'version: 1\nhttp:\n  allowed_hosts: [gw.example.com]\n',
    );
    expect(await run(ctx)).toBe(EXIT.policy);
    expect(stderr.text).toContain('does not set auth.tokens');
  });

  it('a name given an upstream both on the command line and in the policy', async () => {
    const { ctx, stderr } = context(
      ['--name', 'echo', '--port', '0', '--', 'node', ECHO],
      'version: 1\nservers:\n  echo:\n    upstream: { url: "http://other.example/mcp" }\n',
    );
    expect(await run(ctx)).toBe(EXIT.policy);
    expect(stderr.text).toContain('both here and in the policy');
  });

  it('a session.key the ladder does not implement', async () => {
    const { ctx, stderr } = context(
      ['--port', '0', '--', 'node', ECHO],
      'version: 1\nsession:\n  key: cookie\n',
    );
    expect(await run(ctx)).toBe(EXIT.policy);
    expect(stderr.text).toContain('session.key "cookie" is not supported');
  });

  it('a port that is already taken, as a runtime failure and not a crash', async () => {
    const first = context(['--port', '0', '--', 'node', ECHO]);
    const running = run(first.ctx);
    const started = await startedLine(first.stderr);
    const second = context(['--port', String(started.port), '--', 'node', ECHO]);
    expect(await run(second.ctx)).toBe(EXIT.runtime);
    expect(second.stderr.text).toContain('failed to bind');
    first.stop();
    expect(await running).toBe(EXIT.ok);
  });
});

/** Waits for the start-up line and parses it. */
async function startedLine(
  stderr: StringWriter,
): Promise<Record<string, unknown> & { port: number }> {
  for (let attempt = 0; attempt < 200; attempt++) {
    const line = stderr.lines.find((entry) => entry.includes('"serve_started"'));
    if (line !== undefined) return JSON.parse(line.replace('[mcpguard] ', ''));
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`serve did not start: ${stderr.text}`);
}

describe('what serve binds when it does start', () => {
  it('loopback only, by default: reachable there and refused everywhere else', async () => {
    const { ctx, stderr, stop } = context(['--name', 'echo', '--port', '0', '--', 'node', ECHO]);
    const running = run(ctx);
    const started = await startedLine(stderr);

    expect(DEFAULT_HOST).toBe('127.0.0.1');
    expect(started.host).toBe('127.0.0.1');
    expect(started.transport).toBe('plain-http');
    expect(started.auth).toBe('none');
    expect(started.url).toBe(`http://127.0.0.1:${started.port}/mcp/echo`);
    expect(started).not.toHaveProperty('warning');
    const health = await fetch(`http://127.0.0.1:${started.port}/healthz`);
    expect(health.status).toBe(200);

    // The machine's other addresses: a loopback-only listener does not answer on them.
    const others = Object.values(networkInterfaces())
      .flat()
      .filter((entry) => entry !== undefined && !entry.internal && entry.family === 'IPv4');
    for (const entry of others.slice(0, 2)) {
      const refused = await fetch(`http://${entry?.address}:${started.port}/healthz`, {
        signal: AbortSignal.timeout(2_000),
      }).then(
        () => false,
        () => true,
      );
      expect(refused, `${entry?.address} must not answer`).toBe(true);
    }

    stop();
    expect(await running).toBe(EXIT.ok);
    expect(stderr.text).toContain('serve_stopped');
  }, 30_000);

  it('a network bind, once it has what it needs, and says plainly that it is plain HTTP', async () => {
    const { ctx, stderr, stop } = context(
      ['--name', 'echo', '--host', '0.0.0.0', '--port', '0', '--', 'node', ECHO],
      `version: 1\nauth:\n  tokens:\n    - { identity: alice, token_sha256: "${SHA}" }\nhttp:\n  allowed_hosts: [gw.example.com]\n`,
    );
    const running = run(ctx);
    const started = await startedLine(stderr);
    expect(started.auth).toBe('token');
    expect(String(started.warning)).toContain('plain HTTP');
    // The token is a hash in the policy and appears nowhere in what serve says.
    expect(stderr.text).not.toContain('token_sha256');
    stop();
    expect(await running).toBe(EXIT.ok);
  }, 30_000);
});
