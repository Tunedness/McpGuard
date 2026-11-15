import type { Client } from '@modelcontextprotocol/client';
import { describe, expect, it } from 'vitest';
import { limitedFetch, SharedUpstream, UpstreamResponseTooLarge } from './upstream.js';

/** A stand-in for a connected client: all `SharedUpstream` needs of it is `close` and `onclose`. */
function fakeClient(): Client & { drop(): void; closed: boolean } {
  const client = {
    closed: false,
    onclose: undefined as (() => void) | undefined,
    async close() {
      client.closed = true;
    },
    drop() {
      client.onclose?.();
    },
  };
  return client as unknown as Client & { drop(): void; closed: boolean };
}

function bodyOf(chunks: number[]): ReadableStream<Uint8Array> {
  let index = 0;
  return new ReadableStream({
    pull(controller) {
      const size = chunks[index++];
      if (size === undefined) controller.close();
      else controller.enqueue(new Uint8Array(size));
    },
  });
}

describe('limitedFetch', () => {
  const answering = (
    body: ConstructorParameters<typeof Response>[0],
    headers: Record<string, string> = {},
  ) => (async () => new Response(body, { headers })) as typeof fetch;

  it('passes a response under the limit through unchanged', async () => {
    const wrapped = limitedFetch(100, answering('hello'));
    const response = await wrapped('http://upstream/mcp', { method: 'POST' });
    expect(await response.text()).toBe('hello');
  });

  it('refuses a response that declares itself too large without reading it', async () => {
    const wrapped = limitedFetch(10, answering('x'.repeat(50), { 'content-length': '50' }));
    await expect(wrapped('http://upstream/mcp', { method: 'POST' })).rejects.toBeInstanceOf(
      UpstreamResponseTooLarge,
    );
  });

  it('errors the stream the moment a body that never declared a length outgrows the limit', async () => {
    const wrapped = limitedFetch(10, answering(bodyOf([4, 4, 4, 4])));
    const response = await wrapped('http://upstream/mcp', { method: 'POST' });
    await expect(response.arrayBuffer()).rejects.toBeInstanceOf(UpstreamResponseTooLarge);
  });

  it('leaves the open-ended GET stream alone', async () => {
    const wrapped = limitedFetch(10, answering(bodyOf([8, 8, 8])));
    const response = await wrapped('http://upstream/mcp', { method: 'GET' });
    expect((await response.arrayBuffer()).byteLength).toBe(24);
  });

  it('names the limit it enforced', () => {
    expect(new UpstreamResponseTooLarge(1024).limit).toBe(1024);
  });
});

describe('SharedUpstream', () => {
  const clock = (now: { at: number }) => () => now.at;

  it('connects once for however many requests ask at once', async () => {
    let connects = 0;
    const client = fakeClient();
    const shared = new SharedUpstream({
      clock: () => 0,
      connect: async () => {
        connects += 1;
        await new Promise((resolve) => setTimeout(resolve, 10));
        return client;
      },
    });
    const clients = await Promise.all([shared.get(), shared.get(), shared.get()]);
    expect(connects).toBe(1);
    expect(new Set(clients).size).toBe(1);
    expect(shared.current()).toBe(client);
    expect(await shared.get()).toBe(client);
    expect(connects).toBe(1);
  });

  it('remembers a failed connect and does not retry until the back-off has passed', async () => {
    const now = { at: 0 };
    let connects = 0;
    const shared = new SharedUpstream({
      clock: clock(now),
      backoffMs: 100,
      maxBackoffMs: 250,
      connect: async () => {
        connects += 1;
        throw new Error(`down ${connects}`);
      },
    });
    await expect(shared.get()).rejects.toThrow('down 1');
    // Inside the window: the same failure, no new attempt.
    now.at = 99;
    await expect(shared.get()).rejects.toThrow('down 1');
    expect(connects).toBe(1);
    // After it: one more try, and the next window is twice as long.
    now.at = 100;
    await expect(shared.get()).rejects.toThrow('down 2');
    now.at = 100 + 199;
    await expect(shared.get()).rejects.toThrow('down 2');
    now.at = 100 + 200;
    await expect(shared.get()).rejects.toThrow('down 3');
    // Capped.
    now.at = 300 + 249;
    await expect(shared.get()).rejects.toThrow('down 3');
    now.at = 300 + 250;
    await expect(shared.get()).rejects.toThrow('down 4');
    expect(connects).toBe(4);
  });

  it('reconnects after an established connection drops, and says so', async () => {
    const events: string[] = [];
    const first = fakeClient();
    const second = fakeClient();
    const queue = [first, second];
    const shared = new SharedUpstream({
      clock: () => 0,
      connect: async () => queue.shift() as Client,
      onConnected: () => events.push('connected'),
      onLost: () => events.push('lost'),
    });
    expect(await shared.get()).toBe(first);
    first.drop();
    expect(shared.current()).toBeUndefined();
    expect(await shared.get()).toBe(second);
    expect(events).toEqual(['connected', 'lost', 'connected']);
  });

  it('closes its client and refuses further use', async () => {
    const client = fakeClient();
    const shared = new SharedUpstream({ clock: () => 0, connect: async () => client });
    await shared.get();
    await shared.close();
    expect(client.closed).toBe(true);
    await expect(shared.get()).rejects.toThrow(/shutting down/);
  });

  it('closes a connection that finished connecting after it was asked to close', async () => {
    const client = fakeClient();
    let finish: () => void = () => {};
    const shared = new SharedUpstream({
      clock: () => 0,
      connect: () =>
        new Promise<Client>((resolve) => {
          finish = () => resolve(client);
        }),
    });
    const pending = shared.get();
    const settled = pending.catch((error: Error) => error.message);
    await shared.close();
    finish();
    expect(await settled).toMatch(/shutting down/);
    expect(client.closed).toBe(true);
  });
});
