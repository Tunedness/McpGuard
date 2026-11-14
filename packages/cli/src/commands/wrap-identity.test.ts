import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { afterEach, describe, expect, it } from 'vitest';

/**
 * The identity ladder end to end (ADR-010), over a real pipe: the built binary
 * wraps a real server, and a real client calls through it. The flag, the env
 * and the `clientInfo` rung each decide a call, and each says in the audit
 * record which rung it was.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const MAIN = join(HERE, '..', '..', 'dist', 'main.js');
const SERVER = join(HERE, '..', 'testing', 'fixtures', 'echo-server.mjs');

const POLICY = `version: 1
mode: enforce
roles:
  alice: [readonly]
tools:
  - match: echo__*
    action: deny
    roles: [readonly]
`;

let dir: string | undefined;
let client: Client | undefined;

afterEach(async () => {
  await client?.close().catch(() => {});
  client = undefined;
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  dir = undefined;
});

async function callThrough(options: {
  wrapFlags?: string[];
  env?: Record<string, string>;
  clientName: string;
}): Promise<{ refused: boolean; record: Record<string, unknown> }> {
  dir = mkdtempSync(join(tmpdir(), 'mcpguard-identity-'));
  writeFileSync(join(dir, 'guardpolicy.yaml'), POLICY);
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] =>
        entry[1] !== undefined && entry[0] !== 'MCPGUARD_IDENTITY',
    ),
  );
  const transport = new StdioClientTransport({
    command: 'node',
    args: [MAIN, 'wrap', '--name', 'echo', ...(options.wrapFlags ?? []), '--', 'node', SERVER],
    cwd: dir,
    env: { ...inherited, ...options.env },
    stderr: 'ignore',
  });
  client = new Client({ name: options.clientName, version: '0.0.0' });
  await client.connect(transport);
  const result = await client.callTool({ name: 'echo', arguments: { text: 'hello' } });
  const log = readFileSync(join(dir, '.mcpguard', 'audit.jsonl'), 'utf8')
    .trim()
    .split('\n');
  return {
    refused: result.isError === true,
    record: JSON.parse(log[log.length - 1] ?? '{}') as Record<string, unknown>,
  };
}

describe('mcpguard wrap identity', () => {
  it('--identity denies the call and records source flag, exact', async () => {
    const { refused, record } = await callThrough({
      wrapFlags: ['--identity', 'alice'],
      clientName: 'some-agent',
    });

    expect(refused).toBe(true);
    expect(record.action).toBe('deny');
    expect(record.callerIdentity).toEqual({ identity: 'alice', source: 'flag', exact: true });
  }, 30_000);

  it('MCPGUARD_IDENTITY denies the call and records source env, exact', async () => {
    const { refused, record } = await callThrough({
      env: { MCPGUARD_IDENTITY: 'alice' },
      clientName: 'some-agent',
    });

    expect(refused).toBe(true);
    expect(record.callerIdentity).toEqual({ identity: 'alice', source: 'env', exact: true });
  }, 30_000);

  it('with no flag, clientInfo.name decides and the record says it is not exact', async () => {
    const { refused, record } = await callThrough({ clientName: 'alice' });

    expect(refused).toBe(true);
    expect(record.callerIdentity).toEqual({
      identity: 'alice',
      source: 'client_info',
      exact: false,
    });
  }, 30_000);

  it('an unmapped clientInfo name grants no role, and the call passes', async () => {
    const { refused, record } = await callThrough({ clientName: 'some-agent' });

    expect(refused).toBe(false);
    expect(record.callerIdentity).toEqual({
      identity: 'some-agent',
      source: 'client_info',
      exact: false,
    });
  }, 30_000);
});
