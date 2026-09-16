import { describe, expect, it } from 'vitest';
import { BAGGAGE_META_KEY, baggageEntry, injectSession, SESSION_BAGGAGE_KEY } from './remap.js';

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

  it('url-encodes a session id with awkward characters', () => {
    const meta = injectSession(undefined, 'a b,c');
    expect(baggageEntry(meta, SESSION_BAGGAGE_KEY)).toBe('a b,c');
  });
});

describe('baggageEntry', () => {
  it('returns undefined for a missing member', () => {
    expect(baggageEntry({ [BAGGAGE_META_KEY]: 'other=1' }, SESSION_BAGGAGE_KEY)).toBeUndefined();
  });

  it('tolerates a malformed neighbour', () => {
    const meta = { [BAGGAGE_META_KEY]: `broken,,${SESSION_BAGGAGE_KEY}=ok` };
    expect(baggageEntry(meta, SESSION_BAGGAGE_KEY)).toBe('ok');
  });
});
