import { request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { type FetchHandler, type HttpEndpoint, startHttpEndpoint } from './node-http.js';

/**
 * The `node:http` ↔ Fetch bridge, on a real socket. Each property is one of the
 * things a hand-written bridge gets wrong, and each is a property of a socket
 * rather than of a value, so a socket is what is used.
 */

let endpoint: HttpEndpoint | undefined;
afterEach(async () => {
  await endpoint?.close();
  endpoint = undefined;
});

async function serve(
  handler: FetchHandler,
  options: { maxBodyBytes?: number; maxInflight?: number; errors?: Error[] } = {},
): Promise<string> {
  endpoint = await startHttpEndpoint({
    handler,
    host: '127.0.0.1',
    port: 0,
    ...(options.maxBodyBytes !== undefined ? { maxBodyBytes: options.maxBodyBytes } : {}),
    ...(options.maxInflight !== undefined ? { maxInflight: options.maxInflight } : {}),
    onError: (error) => options.errors?.push(error),
  });
  return `http://127.0.0.1:${endpoint.port}`;
}

/** A raw request line and headers, for the cases `fetch` will not send. */
function raw(port: number, text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, '127.0.0.1', () => socket.write(text));
    let received = '';
    socket.on('data', (chunk) => {
      received += chunk.toString('utf8');
    });
    socket.on('close', () => resolve(received));
    socket.on('error', reject);
  });
}

describe('node-http', () => {
  it('hands the handler a Request and writes its Response back', async () => {
    const base = await serve(async (request) => {
      const body = await request.text();
      return new Response(`${request.method} ${new URL(request.url).pathname} ${body}`, {
        status: 201,
        headers: { 'x-answer': 'yes' },
      });
    });
    const response = await fetch(`${base}/mcp/echo?x=1`, { method: 'POST', body: 'hello' });
    expect(response.status).toBe(201);
    expect(response.headers.get('x-answer')).toBe('yes');
    expect(await response.text()).toBe('POST /mcp/echo hello');
  });

  it('reports the peer address from the socket and ignores X-Forwarded-For', async () => {
    let seen: string | undefined;
    const base = await serve(async (_request, context) => {
      seen = context.remoteAddress;
      return new Response('ok');
    });
    await fetch(base, { headers: { 'x-forwarded-for': '203.0.113.9' } });
    expect(seen).toMatch(/127\.0\.0\.1$/);
  });

  it('refuses a body over the limit with 413 and never calls the handler', async () => {
    let called = false;
    const base = await serve(
      async () => {
        called = true;
        return new Response('ok');
      },
      { maxBodyBytes: 16 },
    );
    const response = await fetch(base, { method: 'POST', body: 'x'.repeat(17) });
    expect(response.status).toBe(413);
    expect(called).toBe(false);
    const small = await fetch(base, { method: 'POST', body: 'x'.repeat(16) });
    expect(small.status).toBe(200);
  });

  it('refuses an over-limit body that never declared its length', async () => {
    let called = false;
    const base = await serve(
      async () => {
        called = true;
        return new Response('ok');
      },
      { maxBodyBytes: 16 },
    );
    const answer = await raw(
      endpoint?.port ?? 0,
      'POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' +
        `${(40).toString(16)}\r\n${'x'.repeat(40)}\r\n0\r\n\r\n`,
    );
    expect(base).toContain('http://');
    expect(answer).toMatch(/^HTTP\/1\.1 413/);
    expect(called).toBe(false);
  });

  it('answers 503 with Retry-After beyond maxInflight, and does not queue', async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const base = await serve(
      async () => {
        await gate;
        return new Response('slow');
      },
      { maxInflight: 1 },
    );
    const first = fetch(base);
    await new Promise((resolve) => setTimeout(resolve, 50));
    const second = await fetch(base);
    expect(second.status).toBe(503);
    expect(second.headers.get('retry-after')).toBe('1');
    release();
    expect((await first).status).toBe(200);
    // The slot is free again.
    expect((await fetch(base)).status).toBe(200);
  });

  it('answers 500 when the handler throws, and reports it once', async () => {
    const errors: Error[] = [];
    const base = await serve(
      async () => {
        throw new Error('boom');
      },
      { errors },
    );
    const response = await fetch(base);
    expect(response.status).toBe(500);
    expect(await response.text()).not.toContain('boom');
    expect(errors.map((error) => error.message)).toEqual(['boom']);
  });

  it('answers 400 to a target that is not origin-form and to a Host it cannot build a URL from', async () => {
    await serve(async () => new Response('ok'));
    const port = endpoint?.port ?? 0;
    const absolute = await raw(
      port,
      'GET http://evil.example/x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n',
    );
    expect(absolute).toMatch(/^HTTP\/1\.1 400/);
    const badHost = await raw(
      port,
      'GET /x HTTP/1.1\r\nHost: bad host/with spaces\r\nConnection: close\r\n\r\n',
    );
    expect(badHost).toMatch(/^HTTP\/1\.1 400/);
  });

  it('streams a response as it is produced', async () => {
    const encoder = new TextEncoder();
    const base = await serve(async () => {
      let sent = 0;
      return new Response(
        new ReadableStream({
          async pull(controller) {
            if (sent === 3) return controller.close();
            controller.enqueue(encoder.encode(`frame ${sent++}\n`));
            await new Promise((resolve) => setTimeout(resolve, 30));
          },
        }),
        { headers: { 'content-type': 'text/event-stream' } },
      );
    });
    const response = await fetch(base);
    expect(await response.text()).toBe('frame 0\nframe 1\nframe 2\n');
  });

  it('aborts the handler when the peer goes away', async () => {
    let aborted: () => void = () => {};
    const sawAbort = new Promise<void>((resolve) => {
      aborted = resolve;
    });
    const base = await serve(async (request) => {
      request.signal.addEventListener('abort', () => aborted());
      let first = true;
      return new Response(
        new ReadableStream({
          async pull(controller) {
            if (!first) return new Promise<void>(() => {});
            first = false;
            controller.enqueue(new TextEncoder().encode('first frame\n'));
          },
        }),
      );
    });
    const url = new URL(base);
    await new Promise<void>((resolve) => {
      const outgoing = httpRequest(
        { host: url.hostname, port: url.port, path: '/' },
        (response) => {
          response.once('data', () => {});
          outgoing.destroy();
          resolve();
        },
      );
      outgoing.on('error', () => {});
      outgoing.end();
    });
    await expect(sawAbort).resolves.toBeUndefined();
  });
});
