import { CLIENT_INFO_META_KEY, TRACEPARENT_META_KEY } from '@modelcontextprotocol/server';
import { describe, expect, it } from 'vitest';
import {
  BAGGAGE_META_KEY,
  baggageEntry,
  clientInfoOf,
  injectSession,
  SESSION_BAGGAGE_KEY,
  traceparentOf,
} from './remap.js';

/**
 * The half of the AgentFuse chaining contract that falls to McpGuard: it is the
 * outermost proxy, so it injects the session baggage member rather than only
 * reading it (ADR-006).
 */

describe('injectSession', () => {
  it('adds the session member to an empty _meta', () => {
    const meta = injectSession(undefined, 'sess-1');
    expect(baggageEntry(meta, SESSION_BAGGAGE_KEY)).toBe('sess-1');
  });

  it('merges into an existing baggage list rather than replacing it', () => {
    const meta = injectSession({ [BAGGAGE_META_KEY]: 'trace=abc' }, 'sess-1');
    const raw = meta[BAGGAGE_META_KEY] as string;
    expect(raw).toContain('trace=abc');
    expect(baggageEntry(meta, SESSION_BAGGAGE_KEY)).toBe('sess-1');
  });

  it('leaves an already-present session member untouched', () => {
    // An inner proxy would see this; the outer proxy's answer wins and
    // re-injecting is a no-op.
    const meta = injectSession({ [BAGGAGE_META_KEY]: `${SESSION_BAGGAGE_KEY}=outer` }, 'inner');
    expect(baggageEntry(meta, SESSION_BAGGAGE_KEY)).toBe('outer');
  });

  it('replaces an existing session member when asked, keeping the rest of the list', () => {
    const meta = injectSession(
      {
        [BAGGAGE_META_KEY]: `a=1,${SESSION_BAGGAGE_KEY}=outer, ${SESSION_BAGGAGE_KEY}=%E0%A4%A,b=2`,
      },
      'resolved',
      { replace: true },
    );
    expect(meta[BAGGAGE_META_KEY]).toBe(`a=1,b=2,${SESSION_BAGGAGE_KEY}=resolved`);
  });

  it('replaces into an empty list and a missing one alike', () => {
    expect(
      injectSession({ [BAGGAGE_META_KEY]: `${SESSION_BAGGAGE_KEY}=x` }, 'r', { replace: true })[
        BAGGAGE_META_KEY
      ],
    ).toBe(`${SESSION_BAGGAGE_KEY}=r`);
    expect(injectSession(undefined, 'r', { replace: true })[BAGGAGE_META_KEY]).toBe(
      `${SESSION_BAGGAGE_KEY}=r`,
    );
  });

  it('url-encodes a session id with awkward characters', () => {
    const meta = injectSession(undefined, 'a b,c');
    expect(baggageEntry(meta, SESSION_BAGGAGE_KEY)).toBe('a b,c');
  });
});

describe('baggageEntry', () => {
  it('skips a member whose value is not valid percent-encoding instead of throwing', () => {
    const meta = {
      [BAGGAGE_META_KEY]: `${SESSION_BAGGAGE_KEY}=%E0%A4%A,${SESSION_BAGGAGE_KEY}=ok`,
    };
    expect(baggageEntry(meta, SESSION_BAGGAGE_KEY)).toBe('ok');
  });

  it('returns undefined for a missing member', () => {
    expect(baggageEntry({ [BAGGAGE_META_KEY]: 'other=1' }, SESSION_BAGGAGE_KEY)).toBeUndefined();
  });

  it('tolerates a malformed neighbour', () => {
    const meta = { [BAGGAGE_META_KEY]: `broken,,${SESSION_BAGGAGE_KEY}=ok` };
    expect(baggageEntry(meta, SESSION_BAGGAGE_KEY)).toBe('ok');
  });
});

describe('traceparentOf and clientInfoOf', () => {
  it('reads the traceparent off _meta', () => {
    const value = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
    expect(traceparentOf({ [TRACEPARENT_META_KEY]: value })).toBe(value);
    expect(traceparentOf({ [TRACEPARENT_META_KEY]: '' })).toBeUndefined();
    expect(traceparentOf({ [TRACEPARENT_META_KEY]: 7 })).toBeUndefined();
    expect(traceparentOf(undefined)).toBeUndefined();
  });

  it('reads a well-formed clientInfo and refuses the rest', () => {
    const key = CLIENT_INFO_META_KEY;
    expect(clientInfoOf({ [key]: { name: 'agent', version: '2' } })).toEqual({
      name: 'agent',
      version: '2',
    });
    expect(clientInfoOf({ [key]: { name: 'agent' } })).toEqual({ name: 'agent' });
    expect(clientInfoOf({ [key]: { name: '' } })).toBeUndefined();
    expect(clientInfoOf({ [key]: { name: 3 } })).toBeUndefined();
    expect(clientInfoOf({ [key]: ['agent'] })).toBeUndefined();
    expect(clientInfoOf({ [key]: 'agent' })).toBeUndefined();
    expect(clientInfoOf(undefined)).toBeUndefined();
  });
});
