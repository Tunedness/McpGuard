import {
  compilePolicy,
  hmacSha256,
  type IdentityResolution,
  parsePolicy,
  type SecurityEvent,
  verifyChain,
} from '@mcpguard/core';
import { describe, expect, it } from 'vitest';
import { AuditWriter } from './audit-writer.js';
import { loadShippedRuleset } from './ruleset.js';
import { buildGates, MAX_CLIENT_NAME_LENGTH, resolveIdentity } from './runtime.js';

/**
 * The runtime's promises, tested through the gates the bridge calls: what the
 * audit fingerprint is computed over, whether a correlation tag reaches the
 * mask, and who an access decision is made about.
 */

const RULESET = loadShippedRuleset();
const AUDIT_KEY = 'audit-key-for-tests';
const RAW = 'Musteri kimlik 10000000146 kayitli.';

type Gates = ReturnType<typeof buildGates>;

interface Rig {
  gates: Gates;
  lines: string[];
  events: SecurityEvent[];
  records: () => Array<Record<string, unknown>>;
}

function rig(options: {
  policy?: Record<string, unknown>;
  identity?: IdentityResolution;
  correlationKey?: string;
}): Rig {
  const policy = parsePolicy({ version: 1, ...options.policy });
  const lines: string[] = [];
  const events: SecurityEvent[] = [];
  const audit = new AuditWriter({
    path: '/unused',
    auditKey: AUDIT_KEY,
    checkpointEvery: 1000,
    checkpoint: undefined,
    append: (_path, line) => {
      lines.push(line);
    },
  });
  const gates = buildGates({
    policy,
    compiledPolicy: compilePolicy(policy),
    ruleset: RULESET,
    serverName: 'echo',
    sessionId: '01TESTSESSION',
    sessionExact: true,
    resolveIdentity: () => options.identity ?? resolveIdentity({}),
    correlationKey: options.correlationKey,
    audit,
    clock: () => 1_000,
    onEvent: () => {},
    telemetry: { emit: (event) => events.push(event) },
  });
  return {
    gates,
    lines,
    events,
    records: () => lines.map((line) => JSON.parse(line) as Record<string, unknown>),
  };
}

const callRequest = { method: 'tools/call', params: { name: 'echo', arguments: {} } } as never;
const textResult = (text: string) => async () => ({ content: [{ type: 'text', text }] }) as never;

describe('audit fingerprint', () => {
  it('is the HMAC of the raw upstream text, not of anything derived from it', async () => {
    const { gates, records } = rig({});
    await gates.onCall(callRequest, textResult(RAW));

    const [record] = records();
    expect(record?.contentFingerprint).toBe(hmacSha256(AUDIT_KEY, RAW));
    // The v0.1.0 bug: the fingerprint was taken over the byte counts.
    const byteCount = String(new TextEncoder().encode(RAW).length);
    expect(record?.contentFingerprint).not.toBe(hmacSha256(AUDIT_KEY, byteCount));
  });

  it('never stores the raw text in the record', async () => {
    const { gates, lines } = rig({});
    await gates.onCall(callRequest, textResult(RAW));

    expect(lines.join('')).not.toContain('10000000146');
    expect(lines.join('')).toContain('[TCKN:***]');
  });

  it('joins several text blocks with a newline before fingerprinting', async () => {
    const { gates, records } = rig({});
    await gates.onCall(
      callRequest,
      async () =>
        ({
          content: [
            { type: 'text', text: 'first block' },
            { type: 'image', data: 'AAAA', mimeType: 'image/png' },
            { type: 'text', text: 'second block' },
          ],
        }) as never,
    );

    expect(records()[0]?.contentFingerprint).toBe(
      hmacSha256(AUDIT_KEY, 'first block\nsecond block'),
    );
  });

  it('is computed over the raw text on a resource read too', async () => {
    const { gates, records } = rig({});
    await gates.onRead(
      { method: 'resources/read', params: { uri: 'file:///a.txt' } } as never,
      async () => ({ contents: [{ uri: 'file:///a.txt', type: 'text', text: RAW }] }) as never,
    );

    const [record] = records();
    expect(record?.kind).toBe('resource_read');
    expect(record?.contentFingerprint).toBe(hmacSha256(AUDIT_KEY, RAW));
  });

  it('still verifies as a chain', async () => {
    const { gates, records } = rig({});
    await gates.onCall(callRequest, textResult(RAW));
    await gates.onCall(callRequest, textResult('clean'));

    expect(verifyChain(records() as never).ok).toBe(true);
  });
});

describe('correlation tags', () => {
  const policy = { pii: { correlation_tags: true, correlation_key_env: 'TAG_KEY' } };
  const textOf = (result: unknown): string =>
    ((result as { content: Array<{ text: string }> }).content[0] as { text: string }).text;

  it('puts a stable tag on the mask when the key is wired through', async () => {
    const { gates } = rig({ policy, correlationKey: 'tag-key-one' });
    const first = textOf(await gates.onCall(callRequest, textResult(RAW)));
    const second = textOf(await gates.onCall(callRequest, textResult(RAW)));

    expect(first).toMatch(/\[TCKN:\*\*\*#[0-9a-f]{4}\]/);
    expect(second).toBe(first);
  });

  it('leaves the mask untagged when no key reaches the runtime', async () => {
    const { gates } = rig({ policy });
    const text = textOf(await gates.onCall(callRequest, textResult(RAW)));

    expect(text).toContain('[TCKN:***]');
    expect(text).not.toContain('#');
  });
});

describe('resolveIdentity', () => {
  it('prefers the flag, then the env, then clientInfo', () => {
    expect(resolveIdentity({ flag: 'f', env: 'e', clientName: 'c' })).toEqual({
      identity: 'f',
      source: 'flag',
      exact: true,
    });
    expect(resolveIdentity({ env: 'e', clientName: 'c' })).toEqual({
      identity: 'e',
      source: 'env',
      exact: true,
    });
    expect(resolveIdentity({ clientName: 'c' })).toEqual({
      identity: 'c',
      source: 'client_info',
      exact: false,
    });
  });

  it('answers none, and not exact, when no rung speaks', () => {
    expect(resolveIdentity({})).toEqual({ identity: undefined, source: 'none', exact: false });
    expect(resolveIdentity({ flag: '', env: '  ' })).toEqual({
      identity: undefined,
      source: 'none',
      exact: false,
    });
  });
});

describe('resolveIdentity hardening', () => {
  it('trims a trailing newline off an exact identity', () => {
    expect(resolveIdentity({ env: 'alice\n' })).toEqual({
      identity: 'alice',
      source: 'env',
      exact: true,
    });
    expect(resolveIdentity({ flag: ' alice ' }).identity).toBe('alice');
  });

  it('refuses an over-long or control-laden clientInfo.name and says so', () => {
    const rejected = {
      identity: undefined,
      source: 'none',
      exact: false,
      note: 'client_info_rejected',
    };
    expect(resolveIdentity({ clientName: 'a'.repeat(MAX_CLIENT_NAME_LENGTH + 1) })).toEqual(
      rejected,
    );
    expect(resolveIdentity({ clientName: 'ali\u2028ce' })).toEqual(rejected);
    expect(resolveIdentity({ clientName: 'ali\u202ece' })).toEqual(rejected);
    expect(resolveIdentity({ clientName: 'a'.repeat(MAX_CLIENT_NAME_LENGTH) }).source).toBe(
      'client_info',
    );
  });

  it('does not apply the clientInfo limits to an exact identity', () => {
    expect(resolveIdentity({ flag: 'a'.repeat(300) }).source).toBe('flag');
  });

  it('applies a role-scoped deny to a flag identity with a trailing newline', async () => {
    const policy = {
      mode: 'enforce',
      roles: { alice: ['readonly'] },
      tools: [{ match: 'echo__*', action: 'deny', roles: ['readonly'] }],
    };
    const { gates } = rig({ policy, identity: resolveIdentity({ flag: 'alice\n' }) });
    const result = await gates.onCall(callRequest, textResult('x'));

    expect((result as { isError?: boolean }).isError).toBe(true);
  });
});

describe('access decisions use the caller identity', () => {
  const policy = {
    mode: 'enforce',
    roles: { alice: ['readonly'] },
    tools: [{ match: 'echo__*', action: 'deny', roles: ['readonly'] }],
  };
  const isRefused = (result: unknown): boolean =>
    (result as { isError?: boolean }).isError === true;

  it('denies a call by the flagged identity and records source flag, exact', async () => {
    const identity = resolveIdentity({ flag: 'alice' });
    const { gates, records, events } = rig({ policy, identity });
    let forwarded = false;
    const result = await gates.onCall(callRequest, async () => {
      forwarded = true;
      return { content: [] } as never;
    });

    expect(isRefused(result)).toBe(true);
    expect(forwarded).toBe(false);
    const [record] = records();
    expect(record?.action).toBe('deny');
    expect(record?.callerIdentity).toEqual({ identity: 'alice', source: 'flag', exact: true });
    expect(events[0]?.callerIdentity).toEqual({ identity: 'alice', source: 'flag', exact: true });
  });

  it('denies via clientInfo as well, but records that it is not exact', async () => {
    const identity = resolveIdentity({ clientName: 'alice' });
    const { gates, records } = rig({ policy, identity });
    const result = await gates.onCall(callRequest, textResult('x'));

    expect(isRefused(result)).toBe(true);
    expect(records()[0]?.callerIdentity).toEqual({
      identity: 'alice',
      source: 'client_info',
      exact: false,
    });
  });

  it('grants no role to an unidentified caller, and says so in the record', async () => {
    const { gates, records } = rig({ policy });
    const result = await gates.onCall(callRequest, textResult('x'));

    expect(isRefused(result)).toBe(false);
    expect(records()[0]?.callerIdentity).toEqual({ source: 'none', exact: false });
  });

  it('does not take the session id for an identity', async () => {
    // The v0.1.0 bug: the ULID was handed to the access decision. A policy that
    // names the session id as an identity must therefore grant it nothing.
    const sessionPolicy = { ...policy, roles: { '01TESTSESSION': ['readonly'] } };
    const { gates } = rig({ policy: sessionPolicy });
    const result = await gates.onCall(callRequest, textResult('x'));

    expect(isRefused(result)).toBe(false);
  });
});
