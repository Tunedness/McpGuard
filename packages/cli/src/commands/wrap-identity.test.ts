import { spawnSync } from 'node:child_process';
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
const CATALOG = join(HERE, '..', 'testing', 'fixtures', 'catalog-server.mjs');

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
  policy?: string;
  wrapFlags?: string[];
  env?: Record<string, string>;
  clientName: string;
}): Promise<{ refused: boolean; record: Record<string, unknown> }> {
  dir = mkdtempSync(join(tmpdir(), 'mcpguard-identity-'));
  writeFileSync(join(dir, 'guardpolicy.yaml'), options.policy ?? POLICY);
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

describe('mcpguard wrap with servers.<name>.roles', () => {
  const SERVER_POLICY = `version: 1
mode: enforce
roles:
  alice: [readonly]
  bob: [admin]
servers:
  echo:
    roles: [admin]
`;

  it('refuses a caller whose role the server list does not name, and records the field', async () => {
    const { refused, record } = await callThrough({
      policy: SERVER_POLICY,
      wrapFlags: ['--identity', 'alice'],
      clientName: 'some-agent',
    });

    expect(refused).toBe(true);
    expect(record).toMatchObject({
      action: 'deny',
      findings: ['servers.echo.roles'],
      callerIdentity: { identity: 'alice', source: 'flag', exact: true },
    });
  }, 30_000);

  it('refuses a call that carries no identity at all', async () => {
    const { refused, record } = await callThrough({
      policy: SERVER_POLICY,
      clientName: 'some-agent',
    });

    expect(refused).toBe(true);
    expect(record.findings).toEqual(['servers.echo.roles']);
  }, 30_000);

  it('admits the caller holding the role, and says a guessed one is a guess', async () => {
    const { refused, record } = await callThrough({
      policy: SERVER_POLICY,
      clientName: 'bob',
    });

    expect(refused).toBe(false);
    expect(record.callerIdentity).toEqual({ identity: 'bob', source: 'client_info', exact: false });
  }, 30_000);
});

describe('mcpguard wrap with servers.<name>.roles on every method', () => {
  const POLICY_ROLES = `version: 1
mode: enforce
roles:
  alice: [readonly]
  bob: [admin]
servers:
  catalog:
    roles: [admin]
`;
  const refused = /refused · the caller holds none of the roles this server admits/;

  async function connectAs(identity: string): Promise<{ client: Client; dir: string }> {
    dir = mkdtempSync(join(tmpdir(), 'mcpguard-server-roles-'));
    writeFileSync(join(dir, 'guardpolicy.yaml'), POLICY_ROLES);
    const inherited = Object.fromEntries(
      Object.entries(process.env).filter(
        (entry): entry is [string, string] =>
          entry[1] !== undefined && entry[0] !== 'MCPGUARD_IDENTITY',
      ),
    );
    const transport = new StdioClientTransport({
      command: 'node',
      args: [MAIN, 'wrap', '--name', 'catalog', '--identity', identity, '--', 'node', CATALOG],
      cwd: dir,
      env: inherited,
      stderr: 'ignore',
    });
    client = new Client({ name: 'some-agent', version: '0.0.0' });
    await client.connect(transport);
    return { client, dir };
  }

  it('answers a refused caller with an error on each method family, and keeps the connection', async () => {
    const { client: alice, dir: where } = await connectAs('alice');

    // Connection-level: not the server's, so not refused.
    await alice.ping();
    await expect(alice.listTools()).rejects.toThrow(refused);
    expect((await alice.callTool({ name: 'echo', arguments: { text: 'hi' } })).isError).toBe(true);
    await expect(alice.listResources()).rejects.toThrow(refused);
    await expect(alice.listResourceTemplates()).rejects.toThrow(refused);
    await expect(alice.readResource({ uri: 'note://hello' })).rejects.toThrow(refused);
    await expect(alice.listPrompts()).rejects.toThrow(refused);
    await expect(alice.getPrompt({ name: 'greet', arguments: { name: 'x' } })).rejects.toThrow(
      refused,
    );

    const records = readFileSync(join(where, '.mcpguard', 'audit.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(records.map((r) => r.kind).sort()).toEqual(
      expect.arrayContaining(['access_denied', 'resource_read', 'tool_call', 'tool_list']),
    );
    for (const record of records) {
      expect(record).toMatchObject({
        action: 'deny',
        findings: ['servers.catalog.roles'],
        callerIdentity: { identity: 'alice', source: 'flag', exact: true },
      });
    }
  }, 30_000);

  it('lets the admitted caller through on each of them', async () => {
    const { client: bob } = await connectAs('bob');

    expect((await bob.listTools()).tools).toHaveLength(1);
    expect((await bob.callTool({ name: 'echo', arguments: { text: 'hi' } })).isError).not.toBe(
      true,
    );
    expect((await bob.listResources()).resources).toHaveLength(1);
    expect((await bob.listResourceTemplates()).resourceTemplates).toHaveLength(1);
    expect((await bob.readResource({ uri: 'note://hello' })).contents).toHaveLength(1);
    expect((await bob.listPrompts()).prompts).toHaveLength(1);
    expect(
      (await bob.getPrompt({ name: 'greet', arguments: { name: 'x' } })).messages,
    ).toHaveLength(1);
  }, 30_000);

  async function startUnnamed(policy: string): Promise<string> {
    dir = mkdtempSync(join(tmpdir(), 'mcpguard-server-roles-'));
    writeFileSync(join(dir, 'guardpolicy.yaml'), policy);
    const transport = new StdioClientTransport({
      command: 'node',
      args: [MAIN, 'wrap', '--', 'node', CATALOG],
      cwd: dir,
      stderr: 'pipe',
    });
    let stderr = '';
    transport.stderr?.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
    });
    client = new Client({ name: 'some-agent', version: '0.0.0' });
    await client.connect(transport);
    // Whatever the policy made of the name, the wrapped server answers.
    expect((await client.listTools()).tools).toHaveLength(1);
    await client.close();
    return stderr;
  }

  it('under flag, goes on with a name the policy does not carry, and says so on stderr', async () => {
    const stderr = await startUnnamed(POLICY_ROLES.replace('mode: enforce', 'mode: flag'));

    expect(stderr).toContain('"event":"server_unmatched"');
    expect(stderr).toContain('"server":"server"');
    expect(stderr).toContain('"defined":["catalog"]');
  }, 30_000);

  it('under enforce, starts when the policy names the server with an empty entry', async () => {
    const stderr = await startUnnamed(`${POLICY_ROLES}  server: {}\n`);

    expect(stderr).not.toContain('server_unmatched');
  }, 30_000);

  it('under enforce, a name the policy does not carry stops the process with the policy exit code', async () => {
    dir = mkdtempSync(join(tmpdir(), 'mcpguard-server-roles-'));
    writeFileSync(join(dir, 'guardpolicy.yaml'), POLICY_ROLES);
    const result = spawnSync('node', [MAIN, 'wrap', '--', 'node', CATALOG], {
      cwd: dir,
      input: '',
      encoding: 'utf8',
      timeout: 20_000,
    });

    expect(result.status).toBe(3);
    expect(result.stderr).toContain('"server" (no --name given)');
    expect(result.stderr).toContain('servers: { server: {} }');
  }, 30_000);
});
