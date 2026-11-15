import { CLIENT_INFO_META_KEY, TRACEPARENT_META_KEY } from '@modelcontextprotocol/server';
import { describe, expect, it } from 'vitest';
import { BAGGAGE_META_KEY, SESSION_BAGGAGE_KEY } from './remap.js';
import {
  clientAddressKey,
  isSupportedSessionKey,
  MAX_SESSION_ID_LENGTH,
  SessionKeyResolver,
  traceIdOf,
} from './session-ladder.js';

/**
 * The ADR-006 ladder: what attributes an HTTP request to a session, and how much
 * the answer is worth. The order is the contract, so the order is what is tested.
 */

const TRACE_ID = '4bf92f3577b34da6a3ce929d0e0e4736';
const TRACEPARENT = `00-${TRACE_ID}-00f067aa0ba902b7-01`;
const baggage = (value: string): Record<string, string> => ({
  [BAGGAGE_META_KEY]: `${SESSION_BAGGAGE_KEY}=${encodeURIComponent(value)}`,
});

function resolver(
  overrides: Partial<ConstructorParameters<typeof SessionKeyResolver>[0]> = {},
  now: { at: number } = { at: 0 },
): SessionKeyResolver {
  let counter = 0;
  return new SessionKeyResolver({
    key: 'auto',
    idleTimeoutMs: 1_000,
    maxBindings: 4,
    clock: () => now.at,
    newId: () => `minted-${++counter}`,
    ...overrides,
  });
}

describe('traceIdOf', () => {
  it('takes the trace id of a well-formed traceparent', () => {
    expect(traceIdOf(TRACEPARENT)).toBe(TRACE_ID);
  });

  it.each([
    undefined,
    '',
    'garbage',
    `00-${'0'.repeat(32)}-00f067aa0ba902b7-01`,
    `00-${TRACE_ID.toUpperCase()}-00f067aa0ba902b7-01`,
    `00-${TRACE_ID.slice(1)}-00f067aa0ba902b7-01`,
    `00-${TRACE_ID}`,
  ])('refuses %s', (value) => {
    expect(traceIdOf(value)).toBeUndefined();
  });
});

describe('the auto ladder, top to bottom', () => {
  it('prefers the trace id over everything below it', () => {
    const resolution = resolver().resolve({
      meta: { [TRACEPARENT_META_KEY]: TRACEPARENT, ...baggage('chained') },
      mcpSessionId: 'header-id',
      remoteAddress: '10.0.0.1',
    });
    expect(resolution).toEqual({ sessionId: TRACE_ID, source: 'traceparent', exact: true });
  });

  it('then the baggage member an outer proxy injected', () => {
    const resolution = resolver().resolve({
      meta: baggage('chained'),
      mcpSessionId: 'header-id',
      remoteAddress: '10.0.0.1',
    });
    expect(resolution).toEqual({ sessionId: 'chained', source: 'baggage', exact: true });
  });

  it('then the Mcp-Session-Id the gateway minted', () => {
    const resolution = resolver().resolve({ mcpSessionId: 'header-id', remoteAddress: '10.0.0.1' });
    expect(resolution).toEqual({ sessionId: 'header-id', source: 'mcp-session-id', exact: true });
  });

  it('and last a guess from clientInfo and the address, which says it is a guess', () => {
    const resolution = resolver().resolve({
      meta: { [CLIENT_INFO_META_KEY]: { name: 'agent', version: '1' } },
      remoteAddress: '10.0.0.1',
    });
    expect(resolution).toEqual({ sessionId: 'minted-1', source: 'client-address', exact: false });
  });

  it('has nothing to say when there is nothing to go on', () => {
    expect(resolver().resolve({})).toBeUndefined();
  });

  it('does not take a baggage session id that is huge or carries control characters', () => {
    const huge = 'x'.repeat(MAX_SESSION_ID_LENGTH + 1);
    expect(resolver().resolve({ meta: baggage(huge), remoteAddress: '10.0.0.1' })?.source).toBe(
      'client-address',
    );
    expect(resolver().resolve({ meta: baggage('a b'), remoteAddress: '10.0.0.1' })?.source).toBe(
      'client-address',
    );
    expect(resolver().resolve({ meta: baggage('a‮b'), remoteAddress: '10.0.0.1' })?.source).toBe(
      'client-address',
    );
  });
});

describe('the strict keys', () => {
  it('traceparent answers only from the trace id', () => {
    const strict = resolver({ key: 'traceparent' });
    expect(strict.resolve({ meta: { [TRACEPARENT_META_KEY]: TRACEPARENT } })?.sessionId).toBe(
      TRACE_ID,
    );
    expect(strict.resolve({ meta: baggage('chained'), mcpSessionId: 'x' })).toBeUndefined();
  });

  it('baggage:<name> answers only from that member', () => {
    const strict = resolver({ key: 'baggage:task.id' });
    const meta = { [BAGGAGE_META_KEY]: 'task.id=t-7,other=1' };
    expect(strict.resolve({ meta })).toEqual({ sessionId: 't-7', source: 'baggage', exact: true });
    expect(strict.resolve({ meta: baggage('chained') })).toBeUndefined();
  });

  it('connection answers only from the Mcp-Session-Id', () => {
    const strict = resolver({ key: 'connection' });
    expect(strict.resolve({ mcpSessionId: 'h' })?.source).toBe('mcp-session-id');
    expect(strict.resolve({ meta: { [TRACEPARENT_META_KEY]: TRACEPARENT } })).toBeUndefined();
  });

  it('refuses a key it does not implement, at construction', () => {
    expect(() => resolver({ key: 'cookie' })).toThrow(/not supported/);
    expect(isSupportedSessionKey('baggage:')).toBe(false);
    expect(isSupportedSessionKey('baggage:x')).toBe(true);
    expect(isSupportedSessionKey('auto')).toBe(true);
  });
});

describe('the bottom rung needs memory, and the memory is bounded', () => {
  const caller = (name: string, address: string) => ({
    meta: { [CLIENT_INFO_META_KEY]: { name } },
    remoteAddress: address,
  });

  it('gives one caller one session across requests', () => {
    const ladder = resolver();
    const first = ladder.resolve(caller('agent', '10.0.0.1'));
    expect(ladder.resolve(caller('agent', '10.0.0.1'))?.sessionId).toBe(first?.sessionId);
    expect(ladder.resolve(caller('agent', '10.0.0.2'))?.sessionId).not.toBe(first?.sessionId);
    expect(ladder.resolve(caller('other', '10.0.0.1'))?.sessionId).not.toBe(first?.sessionId);
  });

  it('forgets a caller that has been idle past the timeout, against the injected clock', () => {
    const now = { at: 0 };
    const ladder = resolver({}, now);
    const first = ladder.resolve(caller('agent', '10.0.0.1'));
    now.at = 999;
    expect(ladder.resolve(caller('agent', '10.0.0.1'))?.sessionId).toBe(first?.sessionId);
    now.at = 999 + 1_000;
    expect(ladder.resolve(caller('agent', '10.0.0.1'))?.sessionId).not.toBe(first?.sessionId);
  });

  it('never holds more than maxBindings, dropping the one idle longest', () => {
    const now = { at: 0 };
    const ladder = resolver({ maxBindings: 3 }, now);
    const ids = ['a', 'b', 'c'].map((n) => {
      now.at += 1;
      return ladder.resolve(caller(n, '10.0.0.1'))?.sessionId;
    });
    // `a` is touched again, so `b` is the oldest.
    now.at += 1;
    ladder.resolve(caller('a', '10.0.0.1'));
    now.at += 1;
    ladder.resolve(caller('d', '10.0.0.1'));
    expect(ladder.size).toBe(3);
    expect(ladder.resolve(caller('a', '10.0.0.1'))?.sessionId).toBe(ids[0]);
    expect(ladder.resolve(caller('b', '10.0.0.1'))?.sessionId).not.toBe(ids[1]);
  });

  it('sweeps and clears', () => {
    const now = { at: 0 };
    const ladder = resolver({}, now);
    ladder.resolve(caller('agent', '10.0.0.1'));
    now.at = 5_000;
    expect(ladder.sweep()).toBe(1);
    ladder.resolve(caller('agent', '10.0.0.1'));
    ladder.clear();
    expect(ladder.size).toBe(0);
  });

  it('keys the guess on name, version and address with a separator no value can contain', () => {
    expect(clientAddressKey({ name: 'a', version: 'bc' }, '1')).not.toBe(
      clientAddressKey({ name: 'ab', version: 'c' }, '1'),
    );
    expect(clientAddressKey(undefined, undefined)).toBeUndefined();
  });
});
