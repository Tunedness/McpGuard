import { TRACEPARENT_META_KEY } from '@modelcontextprotocol/server';
import { describe, expect, it } from 'vitest';
import { type DropReason, type PooledSession, SessionPool } from './session-pool.js';

/**
 * The gateway's session bounds, against a fake clock: what is dropped when it
 * has been idle, what is never dropped, and what is refused instead of evicted.
 * Nothing here waits; time is a number the test moves.
 */

const TRACEPARENT = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

interface Held extends PooledSession {
  readonly label: string;
}

const held = (label: string, owner?: string): Held => ({
  label,
  owner,
  inflight: 0,
  lastSeenAt: 0,
});

function pool(
  options: {
    idleTimeoutMs?: number;
    maxBindings?: number;
    maxConnections?: number;
    sweepEveryMs?: number;
  } = {},
) {
  const now = { at: 0 };
  const dropped: { label: string; why: DropReason }[] = [];
  const sessions = new SessionPool({
    key: 'auto',
    idleTimeoutMs: options.idleTimeoutMs ?? 1_000,
    maxBindings: options.maxBindings ?? 4,
    clock: () => now.at,
    ...(options.sweepEveryMs !== undefined ? { sweepEveryMs: options.sweepEveryMs } : {}),
  });
  const connections = sessions.connections<Held>({
    maxConnections: options.maxConnections ?? 2,
    onDrop: (session, why) => dropped.push({ label: session.label, why }),
  });
  return { sessions, connections, now, dropped };
}

describe('a guessed session (the bottom rung of the ladder)', () => {
  const guess = { clientInfo: { name: 'agent', version: '1' }, remoteAddress: '10.0.0.5' };

  it('drops once it has been idle past the timeout, and the caller gets a new one', () => {
    const { sessions, now } = pool();
    const first = sessions.resolver.resolve(guess);
    expect(first).toMatchObject({ source: 'client-address', exact: false });

    now.at = 999;
    expect(sessions.resolver.resolve(guess)?.sessionId).toBe(first?.sessionId);

    // Touched at 999, so it lives until 1999.
    now.at = 1_998;
    expect(sessions.sweep()).toBe(0);
    now.at = 1_999;
    expect(sessions.sweep()).toBe(1);
    expect(sessions.resolver.size).toBe(0);
    expect(sessions.resolver.resolve(guess)?.sessionId).not.toBe(first?.sessionId);
  });

  it('is the only thing capped by maxBindings: the one idle longest goes first', () => {
    const { sessions, now } = pool({ maxBindings: 2 });
    const at = (address: string) =>
      sessions.resolver.resolve({ ...guess, remoteAddress: address })?.sessionId;
    const first = at('10.0.0.1');
    now.at = 1;
    at('10.0.0.2');
    now.at = 2;
    at('10.0.0.3');
    expect(sessions.resolver.size).toBe(2);
    expect(at('10.0.0.1')).not.toBe(first);
  });
});

describe('an exact session (declared by the caller)', () => {
  it('is never held by the attribution table, so nothing evicts or expires it', () => {
    const { sessions, now } = pool({ maxBindings: 1 });
    const exact = { meta: { [TRACEPARENT_META_KEY]: TRACEPARENT } };
    const first = sessions.resolver.resolve(exact);
    expect(first).toMatchObject({ source: 'traceparent', exact: true });
    expect(sessions.resolver.size).toBe(0);

    // However much guessing fills the table and however long it sits idle.
    sessions.resolver.resolve({ clientInfo: { name: 'a', version: '1' }, remoteAddress: 'x' });
    sessions.resolver.resolve({ clientInfo: { name: 'b', version: '1' }, remoteAddress: 'y' });
    now.at = 10_000_000;
    sessions.sweep();
    expect(sessions.resolver.resolve(exact)?.sessionId).toBe(first?.sessionId);
  });

  it('is shared by every server of the gateway, since the table is the gateway’s', () => {
    const { sessions } = pool();
    const a = sessions.resolver.resolve({ meta: { [TRACEPARENT_META_KEY]: TRACEPARENT } });
    const b = sessions.resolver.resolve({ meta: { [TRACEPARENT_META_KEY]: TRACEPARENT } });
    expect(a?.sessionId).toBe(b?.sessionId);
  });
});

describe('the connections of one server', () => {
  it('refuses the one that does not fit and evicts nobody', () => {
    const { connections, dropped } = pool({ maxConnections: 2 });
    const one = connections.reserve();
    expect(one).toBeDefined();
    const two = connections.reserve();
    expect(two).toBeDefined();
    // Two are being opened: a third finds no room, though nothing is held yet.
    expect(connections.reserve()).toBeUndefined();

    connections.add('a', held('a'));
    one?.();
    connections.add('b', held('b'));
    two?.();
    expect(connections.size).toBe(2);
    expect(connections.reserve()).toBeUndefined();
    expect(dropped).toEqual([]);
  });

  it('gives the room back when an opening fails, and only once however often it is released', () => {
    const { connections } = pool({ maxConnections: 1 });
    const release = connections.reserve();
    expect(connections.reserve()).toBeUndefined();
    release?.();
    release?.();
    expect(connections.size).toBe(0);
    expect(connections.reserve()).toBeDefined();
  });

  it('closes a connection that has been idle past the timeout, though its client never said goodbye', () => {
    const { connections, now, dropped } = pool();
    connections.add('a', held('a'));
    now.at = 999;
    expect(connections.sweep()).toBe(0);
    now.at = 1_000;
    expect(connections.sweep()).toBe(1);
    expect(dropped).toEqual([{ label: 'a', why: 'idle' }]);
    expect(connections.use('a', undefined)).toBeUndefined();
  });

  it('counts a connection in use as not idle, until the call has been read out', () => {
    const { connections, now, dropped } = pool();
    connections.add('a', held('a'));
    const lease = connections.use('a', undefined);
    now.at = 50_000;
    expect(connections.sweep()).toBe(0);

    lease?.done();
    lease?.done();
    expect(lease?.session.inflight).toBe(0);
    // Idle is counted from when the call ended, not from when it began.
    now.at = 50_999;
    expect(connections.sweep()).toBe(0);
    now.at = 51_000;
    expect(connections.sweep()).toBe(1);
    expect(dropped).toHaveLength(1);
  });

  it('answers an unknown id and another caller’s id the same way', () => {
    const { connections } = pool();
    connections.add('a', held('a', 'alice'));
    expect(connections.use('nope', 'alice')).toBeUndefined();
    expect(connections.use('a', 'bob')).toBeUndefined();
    expect(connections.use('a', undefined)).toBeUndefined();
    expect(connections.use('a', 'alice')).toBeDefined();
  });

  it('drops a connection once, and a stale handle to it not at all', () => {
    const { connections, dropped } = pool();
    const a = held('a');
    connections.add('a', a);
    expect(connections.drop('a', a, 'deleted')).toBe(true);
    expect(connections.drop('a', a, 'closed')).toBe(false);
    // Another connection under the same id is not the one that was dropped.
    const again = held('a-again');
    connections.add('a', again);
    expect(connections.drop('a', a, 'closed')).toBe(false);
    expect(connections.holds('a', again)).toBe(true);
    expect(dropped).toEqual([{ label: 'a', why: 'deleted' }]);
  });

  it('is its own server’s: one pool full leaves another with room', () => {
    const { sessions, connections } = pool({ maxConnections: 1 });
    const other = sessions.connections<Held>({ maxConnections: 1, onDrop: () => {} });
    connections.add('a', held('a'));
    expect(connections.reserve()).toBeUndefined();
    expect(other.reserve()).toBeDefined();
  });

  it('drains without reporting, for shutdown', () => {
    const { connections, dropped } = pool();
    connections.add('a', held('a'));
    connections.add('b', held('b'));
    expect(connections.drain().map((session) => session.label)).toEqual(['a', 'b']);
    expect(connections.size).toBe(0);
    expect(dropped).toEqual([]);
  });
});

describe('the sweeper', () => {
  it('sweeps guesses and every server’s connections in one pass', () => {
    const { sessions, connections, now } = pool();
    const other = sessions.connections<Held>({ maxConnections: 1, onDrop: () => {} });
    other.add('x', held('x'));
    connections.add('a', held('a'));
    sessions.resolver.resolve({ clientInfo: { name: 'a', version: '1' }, remoteAddress: 'z' });
    now.at = 1_000;
    expect(sessions.sweep()).toBe(3);
  });

  it('runs on its own once started, and not after it is closed', async () => {
    const { sessions, connections, now, dropped } = pool({ sweepEveryMs: 5 });
    connections.add('a', held('a'));
    sessions.start();
    sessions.start();
    now.at = 1_000;
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(dropped).toEqual([{ label: 'a', why: 'idle' }]);

    sessions.close();
    connections.add('b', held('b'));
    now.at = 5_000;
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(dropped).toHaveLength(1);
  });
});
