import { request } from 'node:http';
import {
  Client,
  type ClientCapabilities,
  StreamableHTTPClientTransport,
} from '@modelcontextprotocol/client';
import { afterEach, describe, expect, it } from 'vitest';
import type { Gates } from './bridge.js';
import { type BearerToken, createBearerAuthenticator, hashToken } from './http-auth.js';
import {
  createHttpGateway,
  type GatewayCallInput,
  type GatewayTiming,
  type HttpGateway,
} from './http-gateway.js';
import { type HttpEndpoint, startHttpEndpoint } from './node-http.js';
import { BAGGAGE_META_KEY, baggageEntry, SESSION_BAGGAGE_KEY } from './remap.js';
import { startUpstream, type TestUpstream, type UpstreamEra } from './testing/upstream-server.js';

/**
 * The gateway against real upstreams, over real sockets, with real SDK clients in
 * both eras. The gates are recording stand-ins: what is under test here is the
 * transport — the era split, the session ladder, the credential, the limits —
 * and the context each call reaches its gate with. What the gates *do* with it is
 * `serve-process.test.ts`'s, through the real engines.
 */

const TRACE_A = '4bf92f3577b34da6a3ce929d0e0e4736';
const TRACE_B = '0af7651916cd43dd8448eb211c80319c';
const traceparent = (trace: string): string => `00-${trace}-00f067aa0ba902b7-01`;
const MODERN = { versionNegotiation: { mode: { pin: '2026-07-28' } } } as const;
const LEGACY_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05', '2024-10-07'];

interface Recorded {
  readonly tool: string;
  readonly args: Record<string, unknown> | undefined;
  readonly call: GatewayCallInput;
}

interface Rig {
  readonly gateway: HttpGateway;
  readonly base: string;
  readonly upstream: TestUpstream;
  readonly calls: Recorded[];
  readonly events: { event: string; detail: Record<string, unknown> }[];
  readonly errors: Error[];
  readonly timings: GatewayTiming[];
  readonly clock: { at: number };
}

const open: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  await Promise.allSettled(
    open
      .splice(0)
      .reverse()
      .map((close) => close()),
  );
});

async function rig(
  options: {
    era?: UpstreamEra;
    tokens?: BearerToken[];
    allowedHosts?: string[];
    maxUpstreamConnections?: number;
    maxUpstreamResponseBytes?: number;
    sessionKey?: string;
    idleTimeoutMs?: number;
    timing?: boolean;
    /** Point the gateway somewhere other than the test upstream. */
    target?: string;
  } = {},
): Promise<Rig> {
  const upstream = await startUpstream(options.era ?? 'both');
  open.push(() => upstream.close());
  const calls: Recorded[] = [];
  const events: Rig['events'] = [];
  const errors: Error[] = [];
  const timings: GatewayTiming[] = [];
  const clock = { at: 1_000_000 };

  const gates: Gates<GatewayCallInput> = {
    onCall: async (request, forward, call) => {
      calls.push({ tool: request.params.name, args: request.params.arguments, call });
      return forward();
    },
    onList: async (_request, forward) => forward(),
    onRead: async (_request, forward) => forward(),
  };
  const gateway = createHttpGateway<GatewayCallInput>({
    servers: [{ name: 'up', target: { url: options.target ?? upstream.url }, gates }],
    callContext: (input) => input,
    sessionOf: (call) => call.session.sessionId,
    auth: createBearerAuthenticator(options.tokens ?? []),
    allowedHosts: options.allowedHosts ?? [],
    allowedOrigins: [],
    session: {
      key: options.sessionKey ?? 'auto',
      idleTimeoutMs: options.idleTimeoutMs ?? 600_000,
      maxBindings: 64,
    },
    maxUpstreamConnections: options.maxUpstreamConnections ?? 8,
    maxBodyBytes: 1_000_000,
    maxUpstreamResponseBytes: options.maxUpstreamResponseBytes ?? 1_000_000,
    clientName: 'mcpguard-test',
    version: '9.9.9',
    clock: () => clock.at,
    onError: (error) => errors.push(error),
    onEvent: (event, detail) => events.push({ event, detail }),
    ...(options.timing === true ? { onTiming: (timing) => timings.push(timing) } : {}),
  });
  open.push(() => gateway.close());
  const endpoint: HttpEndpoint = await startHttpEndpoint({
    handler: gateway.fetch,
    host: '127.0.0.1',
    port: 0,
  });
  open.push(() => endpoint.close());
  return {
    gateway,
    base: `http://127.0.0.1:${endpoint.port}`,
    upstream,
    calls,
    events,
    errors,
    timings,
    clock,
  };
}

const transports = new WeakMap<Client, StreamableHTTPClientTransport>();

async function connect(
  rigged: Rig,
  options: {
    modern?: boolean;
    token?: string;
    name?: string;
    capabilities?: ClientCapabilities;
  } = {},
): Promise<Client> {
  const client = new Client(
    { name: options.name ?? 'agent', version: '1.0.0' },
    {
      ...(options.modern === true ? MODERN : {}),
      ...(options.capabilities !== undefined ? { capabilities: options.capabilities } : {}),
    },
  );
  const transport = new StreamableHTTPClientTransport(new URL(`${rigged.base}/mcp/up`), {
    ...(options.token !== undefined
      ? { requestInit: { headers: { authorization: `Bearer ${options.token}` } } }
      : {}),
  });
  await client.connect(transport);
  transports.set(client, transport);
  open.push(() => client.close());
  return client;
}

const text = (result: { content?: unknown }): string =>
  ((result.content as { text: string }[])[0] as { text: string }).text;

const post = (
  rigged: Pick<Rig, 'base'>,
  body: unknown,
  headers: Record<string, string> = {},
  path = '/mcp/up',
): Promise<Response> =>
  fetch(`${rigged.base}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...headers,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });

const INITIALIZE = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-11-25',
    capabilities: {},
    clientInfo: { name: 'raw', version: '1' },
  },
};

describe('the front door', () => {
  it('answers /healthz with a status and a version, and nothing about the policy or the servers', async () => {
    const r = await rig();
    const response = await fetch(`${r.base}/healthz`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: 'ok', version: '9.9.9' });
    expect((await fetch(`${r.base}/healthz`, { method: 'POST' })).status).toBe(405);
  });

  it('answers 404 to a path that is not /mcp/<name>, without echoing it', async () => {
    const r = await rig();
    for (const path of ['/', '/mcp', '/mcp/', '/mcp/other', '/mcp/up/extra', '/mcp/%E0%A4%A']) {
      const response = await post(r, {}, {}, path);
      expect(response.status, path).toBe(404);
      const body = await response.text();
      expect(body).toContain('unknown_server');
      if (path.length > 1) expect(body).not.toContain(path.slice(1));
    }
  });

  it('refuses a Host it does not serve, whatever else the request is', async () => {
    const r = await rig();
    // `fetch` will not let a caller choose `Host`; a raw request does.
    const status = await new Promise<number>((resolve, reject) => {
      const outgoing = request(
        {
          host: '127.0.0.1',
          port: new URL(r.base).port,
          path: '/mcp/up',
          method: 'POST',
          headers: { host: 'evil.example' },
        },
        (incoming) => {
          incoming.resume();
          resolve(incoming.statusCode ?? 0);
        },
      );
      outgoing.on('error', reject);
      outgoing.end('{}');
    });
    expect(status).toBe(403);
    expect(
      r.events.some((e) => e.event === 'request_rejected' && e.detail.reason === 'host_or_origin'),
    ).toBe(true);
  });

  it('refuses an Origin that is not localhost or listed, and writes no CORS header', async () => {
    const r = await rig();
    const bad = await post(r, {}, { origin: 'http://evil.example' });
    expect(bad.status).toBe(403);
    const nullOrigin = await post(r, {}, { origin: 'null' });
    expect(nullOrigin.status).toBe(403);
    const local = await post(r, {}, { origin: 'http://localhost:3000' });
    expect(local.status).not.toBe(403);
    for (const response of [bad, nullOrigin, local]) {
      expect(response.headers.get('access-control-allow-origin')).toBeNull();
    }
  });

  it('does not accept a localhost Origin once the gateway is served under its own host names', async () => {
    const r = await rig({ allowedHosts: ['gw.example'] });
    const statusOf = (origin: string): Promise<number> =>
      new Promise((resolve, reject) => {
        const outgoing = request(
          {
            host: '127.0.0.1',
            port: new URL(r.base).port,
            path: '/mcp/up',
            method: 'POST',
            headers: { host: 'gw.example', origin, 'content-type': 'application/json' },
          },
          (incoming) => {
            incoming.resume();
            resolve(incoming.statusCode ?? 0);
          },
        );
        outgoing.on('error', reject);
        outgoing.end('{}');
      });
    expect(await statusOf('http://localhost:3000')).toBe(403);
  });

  it('answers 415 to a POST that is not JSON, 405 to a method it does not serve', async () => {
    const r = await rig();
    const wrongType = await fetch(`${r.base}/mcp/up`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: 'hi',
    });
    expect(wrongType.status).toBe(415);
    const put = await fetch(`${r.base}/mcp/up`, { method: 'PUT' });
    expect(put.status).toBe(405);
    expect(put.headers.get('allow')).toBe('POST, GET, DELETE');
    const options = await fetch(`${r.base}/mcp/up`, { method: 'OPTIONS' });
    expect(options.status).toBe(405);
    expect(options.headers.get('access-control-allow-methods')).toBeNull();
  });

  it('answers 400 to a body that is not JSON', async () => {
    const r = await rig();
    const response = await post(r, '{not json');
    expect(response.status).toBe(400);
  });

  it('answers 413 to a body over the limit', async () => {
    const r = await rig();
    const response = await post(r, { pad: 'x'.repeat(1_100_000) });
    expect(response.status).toBe(413);
  });

  it('counts the limit in bytes, not characters', async () => {
    // 400,000 characters of three bytes each: under the 1,000,000 limit as text,
    // over it as bytes.
    const r = await rig();
    const response = await post(r, { pad: '\u20ac'.repeat(400_000) });
    expect(response.status).toBe(413);
  });
});

describe('the bearer token', () => {
  const tokens = [
    { identity: 'alice', tokenSha256: hashToken('alice-secret') },
    { identity: 'bob', tokenSha256: hashToken('bob-secret') },
  ];

  it('answers 401 with a challenge to a request with none, and does so before looking at the body', async () => {
    const r = await rig({ tokens });
    const response = await post(r, '{not json');
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toBe('Bearer');
    const wrong = await post(r, INITIALIZE, { authorization: 'Bearer nope' });
    expect(wrong.status).toBe(401);
    expect(r.events.filter((e) => e.detail.reason === 'unauthorized')).toHaveLength(2);
    // The token is not in any event, and neither is the one that was refused.
    expect(JSON.stringify(r.events)).not.toContain('nope');
  });

  it('gives each call the identity its token names, in either era', async () => {
    const r = await rig({ tokens });
    const legacy = await connect(r, { token: 'alice-secret' });
    const modern = await connect(r, { token: 'bob-secret', modern: true });
    await legacy.callTool({ name: 'echo', arguments: { text: 'a' } });
    await modern.callTool({ name: 'echo', arguments: { text: 'b' } });
    expect(r.calls.map((c) => c.call.tokenIdentity)).toEqual(['alice', 'bob']);
  });

  it('keeps a legacy session to the identity that opened it', async () => {
    const r = await rig({ tokens });
    const opened = await post(r, INITIALIZE, { authorization: 'Bearer alice-secret' });
    expect(opened.status).toBe(200);
    const sessionId = opened.headers.get('mcp-session-id') as string;
    expect(sessionId).toBeTruthy();
    const ping = { jsonrpc: '2.0', id: 2, method: 'ping' };
    const own = await post(r, ping, {
      authorization: 'Bearer alice-secret',
      'mcp-session-id': sessionId,
    });
    expect(own.status).toBe(200);
    // Bob holds a valid token and a session id he should not have: the answer is the
    // one an unknown session gets.
    const stolen = await post(r, ping, {
      authorization: 'Bearer bob-secret',
      'mcp-session-id': sessionId,
    });
    expect(stolen.status).toBe(404);
    const unknown = await post(r, ping, {
      authorization: 'Bearer bob-secret',
      'mcp-session-id': 'nope',
    });
    expect(unknown.status).toBe(404);
    expect(await stolen.text()).toBe(await unknown.text());
  });
});

describe('the modern leg', () => {
  it('serves tools, a call and a list through the gates, with no session at all', async () => {
    const r = await rig();
    const client = await connect(r, { modern: true });
    expect(client.getProtocolEra()).toBe('modern');
    expect((await client.listTools()).tools.map((t) => t.name)).toContain('echo');
    const result = await client.callTool({ name: 'echo', arguments: { text: 'hello' } });
    expect(text(result)).toBe('hello');
    expect(r.calls).toHaveLength(1);
    expect(r.calls[0]?.call.era).toBe('modern');
    expect(r.gateway.sessionCount()).toBe(0);
  });

  it('attributes a call to its trace id, exactly, and tells the upstream so', async () => {
    const r = await rig();
    const client = await connect(r, { modern: true });
    const result = await client.callTool({
      name: 'show_meta',
      arguments: {},
      _meta: { traceparent: traceparent(TRACE_A) },
    });
    expect(r.calls[0]?.call.session).toEqual({
      sessionId: TRACE_A,
      source: 'traceparent',
      exact: true,
    });
    const meta = JSON.parse(text(result)) as Record<string, string>;
    expect(meta[BAGGAGE_META_KEY]).toBe(`${SESSION_BAGGAGE_KEY}=${TRACE_A}`);
  });

  it('adopts a session an outer proxy already named', async () => {
    const r = await rig();
    const client = await connect(r, { modern: true });
    await client.callTool({
      name: 'show_meta',
      arguments: {},
      _meta: { [BAGGAGE_META_KEY]: `${SESSION_BAGGAGE_KEY}=outer-7,trace=1` },
    });
    expect(r.calls[0]?.call.session).toEqual({
      sessionId: 'outer-7',
      source: 'baggage',
      exact: true,
    });
    const meta = r.upstream.seenMeta[0] as Record<string, string>;
    expect(meta[BAGGAGE_META_KEY]).toContain('trace=1');
    expect(meta[BAGGAGE_META_KEY]).toContain(`${SESSION_BAGGAGE_KEY}=outer-7`);
  });

  it('tells the upstream the session it resolved, not a conflicting one the caller wrote', async () => {
    // ADR-006: two tools, one story. The traceparent outranks the baggage, so the
    // audit says TRACE_A; the upstream must hear TRACE_A too, not `foo`.
    const r = await rig();
    const client = await connect(r, { modern: true });
    await client.callTool({
      name: 'show_meta',
      arguments: {},
      _meta: {
        traceparent: traceparent(TRACE_A),
        [BAGGAGE_META_KEY]: `trace=1,${SESSION_BAGGAGE_KEY}=foo`,
      },
    });
    expect(r.calls[0]?.call.session.sessionId).toBe(TRACE_A);
    const meta = r.upstream.seenMeta[0] as Record<string, string>;
    expect(baggageEntry(meta, SESSION_BAGGAGE_KEY)).toBe(TRACE_A);
    expect(meta[BAGGAGE_META_KEY]).not.toContain('foo');
    expect(meta[BAGGAGE_META_KEY]).toContain('trace=1');
  });

  it('does not pass an unusable baggage session id on to the upstream', async () => {
    // The ladder skips a value over the length cap; the upstream must not be handed
    // the very value the ladder refused.
    const r = await rig();
    const client = await connect(r, { modern: true, name: 'plain-agent' });
    const oversized = 'x'.repeat(200);
    await client.callTool({
      name: 'show_meta',
      arguments: {},
      _meta: { [BAGGAGE_META_KEY]: `${SESSION_BAGGAGE_KEY}=${oversized}` },
    });
    const session = r.calls[0]?.call.session;
    expect(session?.source).toBe('client-address');
    const meta = r.upstream.seenMeta[0] as Record<string, string>;
    expect(baggageEntry(meta, SESSION_BAGGAGE_KEY)).toBe(session?.sessionId);
    expect(meta[BAGGAGE_META_KEY]).not.toContain(oversized);
  });

  it('falls to a guess from clientInfo and the address, and says it is a guess', async () => {
    const r = await rig();
    const client = await connect(r, { modern: true, name: 'plain-agent' });
    await client.callTool({ name: 'echo', arguments: { text: 'a' } });
    await client.callTool({ name: 'echo', arguments: { text: 'b' } });
    const [first, second] = r.calls.map((c) => c.call);
    expect(first?.session.source).toBe('client-address');
    expect(first?.session.exact).toBe(false);
    expect(first?.clientInfo?.name).toBe('plain-agent');
    expect(second?.session.sessionId).toBe(first?.session.sessionId);
  });

  it('writes the resolved session onto every request it forwards, not only the calls it guards', async () => {
    const r = await rig();
    const client = await connect(r, { modern: true });
    const result = await client.callTool({
      name: 'show_meta',
      arguments: {},
      _meta: { traceparent: traceparent(TRACE_B) },
    });
    expect(JSON.parse(text(result))[BAGGAGE_META_KEY]).toContain(TRACE_B);
  });

  it('keeps concurrent callers apart: each call reaches its gate with its own session', async () => {
    const r = await rig();
    const client = await connect(r, { modern: true });
    const traceOf = (index: number): string =>
      (index % 2 === 0 ? TRACE_A : TRACE_B).replace(/.$/, String(index % 10));
    const results = await Promise.all(
      Array.from({ length: 24 }, (_, index) =>
        client.callTool({
          name: 'echo',
          arguments: { text: `call-${index}` },
          _meta: { traceparent: traceparent(traceOf(index)) },
        }),
      ),
    );
    expect(results.map(text)).toEqual(Array.from({ length: 24 }, (_, i) => `call-${i}`));
    // Whatever order they interleaved in, every call reached its gate with the
    // trace its own request named, never a neighbour's.
    expect(r.calls).toHaveLength(24);
    for (const { args, call } of r.calls) {
      const index = Number(String(args?.text).replace('call-', ''));
      expect(call.session.sessionId).toBe(traceOf(index));
    }
  });

  it('forwards the client capabilities and clientInfo the request declared', async () => {
    const r = await rig();
    const client = await connect(r, { modern: true, capabilities: { elicitation: { form: {} } } });
    const result = await client.callTool({ name: 'show_client', arguments: {} });
    expect(JSON.parse(text(result))).toEqual({
      capabilities: { elicitation: { form: {} } },
      clientInfo: { name: 'agent', version: '1.0.0' },
    });
  });

  it('does not carry a modern multi-round-trip result: the call fails, and says why', async () => {
    // ADR-011 V2, pinned. The shared upstream client would have to fulfil the
    // upstream's `input_required` itself, with handlers it does not have, and the
    // downstream has no channel to be asked through. This is the same limit as
    // ADR-008's: a server-to-client exchange is not scanned, and here not carried.
    const r = await rig({ era: 'modern' });
    const client = await connect(r, { modern: true, capabilities: { elicitation: { form: {} } } });
    client.setRequestHandler('elicitation/create', async () => ({
      action: 'accept',
      content: { confirm: true },
    }));
    await expect(client.callTool({ name: 'deploy', arguments: { env: 'prod' } })).rejects.toThrow(
      /Cannot fulfil input request 'confirm'/,
    );
    // The gate was reached and never saw a result to let through.
    expect(r.calls.map((c) => c.tool)).toEqual(['deploy']);
  });
});

describe('which upstream connection a call is served by', () => {
  it('names the connection per legacy session and one for every modern call, and the server the same for all', async () => {
    const r = await rig({ era: 'both' });
    const a = await connect(r);
    const b = await connect(r);
    await a.callTool({ name: 'echo', arguments: { text: '1' } });
    await b.callTool({ name: 'echo', arguments: { text: '2' } });
    await a.callTool({ name: 'echo', arguments: { text: '3' } });
    const [a1, b1, a2] = r.calls.map((c) => c.call.connection);
    expect(a1).toBe(a2);
    expect(a1).not.toBe(b1);

    const m = await connect(r, { modern: true });
    const n = await connect(r, { modern: true });
    await m.callTool({ name: 'echo', arguments: { text: '4' } });
    await n.callTool({ name: 'echo', arguments: { text: '5' } });
    const [m1, n1] = r.calls.slice(3).map((c) => c.call.connection);
    expect(m1).toBe(n1);
    expect(m1).not.toBe(a1);

    // The server record a halt is held against: one, for every session of both eras.
    const kinds = new Set(r.calls.map((c) => c.call.upstream));
    expect([...kinds]).toEqual(['up']);
  });
});

describe('the legacy leg', () => {
  it('mints its own session id, and the upstream session id never reaches the client', async () => {
    const r = await rig({ era: 'legacy' });
    const opened = await post(r, INITIALIZE);
    const minted = opened.headers.get('mcp-session-id') as string;
    expect(minted).toMatch(/^[0-9a-f-]{36}$/);
    expect(r.gateway.sessionCount()).toBe(1);
    expect(r.upstream.sessions()).toBe(1);
    await opened.text();
    expect(r.events.some((e) => e.event === 'session_opened' && e.detail.session === minted)).toBe(
      true,
    );
  });

  it('serves a call through the gates and attributes it to the Mcp-Session-Id, exactly', async () => {
    const r = await rig({ era: 'legacy' });
    const client = await connect(r);
    expect(client.getProtocolEra()).toBe('legacy');
    const result = await client.callTool({ name: 'show_meta', arguments: {} });
    const [{ call }] = r.calls as [Recorded];
    expect(call.era).toBe('legacy');
    expect(call.session.source).toBe('mcp-session-id');
    expect(call.session.exact).toBe(true);
    expect(call.clientInfo).toMatchObject({ name: 'agent' });
    expect(JSON.parse(text(result))[BAGGAGE_META_KEY]).toBe(
      `${SESSION_BAGGAGE_KEY}=${call.session.sessionId}`,
    );
  });

  it('lets a trace id outrank the session header, as the ladder says', async () => {
    const r = await rig({ era: 'legacy' });
    const client = await connect(r);
    await client.callTool({
      name: 'echo',
      arguments: { text: 'x' },
      _meta: { traceparent: traceparent(TRACE_A) },
    });
    expect(r.calls[0]?.call.session).toEqual({
      sessionId: TRACE_A,
      source: 'traceparent',
      exact: true,
    });
  });

  it('gives each client its own upstream connection', async () => {
    const r = await rig({ era: 'legacy' });
    await connect(r, { name: 'one' });
    await connect(r, { name: 'two' });
    expect(r.gateway.sessionCount()).toBe(2);
    expect(r.upstream.sessions()).toBe(2);
  });

  it('closes both ends when the client deletes its session', async () => {
    const r = await rig({ era: 'legacy' });
    const client = await connect(r);
    expect(r.upstream.sessions()).toBe(1);
    await transports.get(client)?.terminateSession();
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(r.gateway.sessionCount()).toBe(0);
    expect(r.upstream.sessions()).toBe(0);
    expect(r.events.some((e) => e.event === 'session_closed' && e.detail.why === 'deleted')).toBe(
      true,
    );
  });

  it('answers 400 to a request with no session that is not an initialize, and 404 to an unknown one', async () => {
    const r = await rig({ era: 'legacy' });
    const ping = { jsonrpc: '2.0', id: 2, method: 'ping' };
    expect((await post(r, ping)).status).toBe(400);
    expect((await post(r, ping, { 'mcp-session-id': 'no-such-session' })).status).toBe(404);
    const get = await fetch(`${r.base}/mcp/up`, { headers: { accept: 'text/event-stream' } });
    expect(get.status).toBe(400);
  });

  it('refuses a new session with 503 and Retry-After once the upstream connections are full, and evicts nobody', async () => {
    const r = await rig({ era: 'legacy', maxUpstreamConnections: 2 });
    const first = await connect(r, { name: 'one' });
    await connect(r, { name: 'two' });
    const refused = await post(r, INITIALIZE);
    expect(refused.status).toBe(503);
    expect(refused.headers.get('retry-after')).toBe('5');
    expect(r.gateway.sessionCount()).toBe(2);
    // The sessions that exist still work.
    expect(text(await first.callTool({ name: 'echo', arguments: { text: 'still here' } }))).toBe(
      'still here',
    );
    expect(r.events.some((e) => e.detail.reason === 'upstream_connections_full')).toBe(true);
  });

  it('closes a session that has been idle past the timeout, against the injected clock', async () => {
    const r = await rig({ era: 'legacy', idleTimeoutMs: 60_000 });
    const idle = await post(r, INITIALIZE);
    const idleId = idle.headers.get('mcp-session-id') as string;
    await idle.text();
    expect(r.upstream.sessions()).toBe(1);

    r.clock.at += 61_000;
    // Any legacy request sweeps; an unrelated initialize does.
    const fresh = await post(r, INITIALIZE);
    await fresh.text();
    expect(r.gateway.sessionCount()).toBe(1);
    expect(r.events.some((e) => e.event === 'session_closed' && e.detail.why === 'idle')).toBe(
      true,
    );
    const gone = await post(
      r,
      { jsonrpc: '2.0', id: 2, method: 'ping' },
      { 'mcp-session-id': idleId },
    );
    expect(gone.status).toBe(404);
  });

  it('does not close a session in the middle of a call, however long it has been quiet', async () => {
    const r = await rig({ era: 'legacy', idleTimeoutMs: 60_000 });
    const client = await connect(r);
    const held = client.callTool({ name: 'hold', arguments: {} }, { timeout: 20_000 });
    await new Promise((resolve) => setTimeout(resolve, 150));

    r.clock.at += 3_600_000;
    await (await post(r, INITIALIZE)).text();
    expect(r.gateway.sessionCount()).toBe(2);

    r.upstream.release();
    expect(text(await held)).toBe('released');
  });

  it('reports a failed upstream as a JSON-RPC error, not a hung or dropped request', async () => {
    const dead = await startUpstream('legacy');
    const url = dead.url;
    await dead.close();
    const r = await rig({ era: 'legacy', target: url });
    const response = await post(r, INITIALIZE);
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      id: number;
      error: { code: number; data: Record<string, unknown> };
    };
    expect(body.id).toBe(1);
    expect(body.error.code).toBe(-32603);
    expect(body.error.data).toEqual({ reason: 'upstream_unavailable', server: 'up' });
    expect(r.gateway.sessionCount()).toBe(0);
  });
});

describe('era is never translated', () => {
  it('refuses a modern request to a legacy-only upstream, and lists the revisions it does serve', async () => {
    const r = await rig({ era: 'legacy' });
    const response = await post(r, {
      jsonrpc: '2.0',
      id: 5,
      method: 'server/discover',
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientInfo': { name: 'm', version: '1' },
          'io.modelcontextprotocol/clientCapabilities': {},
        },
      },
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as {
      id: number;
      error: { code: number; data: { supported: string[] } };
    };
    expect(body.id).toBe(5);
    expect(body.error.code).toBe(-32022);
    expect(body.error.data.supported).toEqual(LEGACY_VERSIONS);
  });

  it('lets a negotiating client fall back to the era the upstream does speak', async () => {
    const r = await rig({ era: 'legacy' });
    const client = new Client(
      { name: 'negotiator', version: '1' },
      { versionNegotiation: { mode: 'auto' } },
    );
    await client.connect(new StreamableHTTPClientTransport(new URL(`${r.base}/mcp/up`)));
    open.push(() => client.close());
    expect(client.getProtocolEra()).toBe('legacy');
    expect(text(await client.callTool({ name: 'echo', arguments: { text: 'fell back' } }))).toBe(
      'fell back',
    );
  });

  it('refuses a legacy initialize to a modern-only upstream', async () => {
    const r = await rig({ era: 'modern' });
    const response = await post(r, INITIALIZE);
    expect(response.status).toBe(400);
    const body = (await response.json()) as {
      error: { code: number; data: { supported: string[]; reason: string } };
    };
    expect(body.error.code).toBe(-32022);
    expect(body.error.data).toMatchObject({ supported: ['2026-07-28'], reason: 'era_mismatch' });
    expect(r.gateway.sessionCount()).toBe(0);
  });

  it('reports what the upstream speaks when asked', async () => {
    expect((await (await rig({ era: 'modern' })).gateway.probe())[0]?.era).toBe('modern');
    expect((await (await rig({ era: 'both' })).gateway.probe())[0]?.era).toBe('modern');
    expect((await (await rig({ era: 'legacy' })).gateway.probe())[0]?.era).toBe('legacy');
    const dead = await startUpstream('both');
    const url = dead.url;
    await dead.close();
    const probed = (await (await rig({ target: url })).gateway.probe())[0];
    expect(probed?.era).toBe('unavailable');
    expect(probed?.reason).toBeTruthy();
  });
});

describe('what an upstream can do to the gateway', () => {
  it('cannot make it buffer an unbounded response: the call fails and the oversize content is not delivered', async () => {
    const r = await rig({ maxUpstreamResponseBytes: 4_096 });
    const client = await connect(r, { modern: true });
    expect(text(await client.callTool({ name: 'big', arguments: { n: 100 } }))).toHaveLength(100);
    await expect(client.callTool({ name: 'big', arguments: { n: 20_000 } })).rejects.toThrow();
    // And the gateway is fine afterwards.
    expect(text(await client.callTool({ name: 'big', arguments: { n: 10 } }))).toHaveLength(10);
  });

  it('does not retry a call that failed', async () => {
    const r = await rig({ maxUpstreamResponseBytes: 4_096 });
    const client = await connect(r, { modern: true });
    await client.callTool({ name: 'big', arguments: { n: 20_000 } }).catch(() => {});
    expect(r.calls.filter((c) => c.tool === 'big')).toHaveLength(1);
  });
});

describe('measuring what the proxy adds', () => {
  it('is silent unless asked', async () => {
    const r = await rig();
    const client = await connect(r, { modern: true });
    await client.callTool({ name: 'echo', arguments: { text: 'x' } });
    expect(r.timings).toEqual([]);
  });

  it.each([
    ['modern', true],
    ['legacy', false],
  ])(
    'reports one timing per request in the %s era, split at the upstream call',
    async (_label, modern) => {
      const r = await rig({ timing: true, era: modern ? 'modern' : 'legacy' });
      const client = await connect(r, { modern });
      r.timings.length = 0;
      await client.callTool({ name: 'echo', arguments: { text: 'x' } });
      const call = r.timings.find((t) => t.method === 'tools/call');
      expect(call).toBeDefined();
      expect(call?.era).toBe(modern ? 'modern' : 'legacy');
      expect(call?.forwarded).toBe(true);
      expect(call?.ingressMs).toBeGreaterThanOrEqual(0);
      expect(call?.egressMs).toBeGreaterThanOrEqual(0);
      expect(call?.totalMs).toBeGreaterThanOrEqual((call?.ingressMs ?? 0) + (call?.egressMs ?? 0));
    },
  );
});

// ---------------------------------------------------------------------------
// several servers behind one gateway
// ---------------------------------------------------------------------------

interface MultiRig {
  readonly gateway: HttpGateway;
  readonly base: string;
  readonly upstreams: Record<string, TestUpstream>;
  /** What each server's own gates were asked, by server name. */
  readonly seen: Record<string, Recorded[]>;
  readonly events: { event: string; detail: Record<string, unknown> }[];
  readonly clock: { at: number };
}

/**
 * A gateway over several real upstreams. Each server's gates record into their
 * own list and, for the servers named in `refuse`, refuse the call, so a test can
 * tell whose gates a call went through.
 */
async function multiRig(
  servers: { name: string; era?: UpstreamEra; dead?: boolean }[],
  options: {
    maxUpstreamConnections?: number;
    refuse?: string[];
    tokens?: BearerToken[];
  } = {},
): Promise<MultiRig> {
  const upstreams: Record<string, TestUpstream> = {};
  const seen: Record<string, Recorded[]> = {};
  const events: MultiRig['events'] = [];
  const clock = { at: 1_000_000 };
  const defs = [];
  for (const server of servers) {
    const upstream = await startUpstream(server.era ?? 'both');
    upstreams[server.name] = upstream;
    seen[server.name] = [];
    const url = upstream.url;
    if (server.dead === true) await upstream.close();
    else open.push(() => upstream.close());
    const gates: Gates<GatewayCallInput> = {
      onCall: async (request, forward, call) => {
        (seen[server.name] as Recorded[]).push({
          tool: request.params.name,
          args: request.params.arguments,
          call,
        });
        if (options.refuse?.includes(server.name) === true) {
          return { isError: true, content: [{ type: 'text', text: `refused by ${server.name}` }] };
        }
        return forward();
      },
      onList: async (_request, forward) => forward(),
      onRead: async (_request, forward) => forward(),
    };
    defs.push({ name: server.name, target: { url }, gates });
  }
  const gateway = createHttpGateway<GatewayCallInput>({
    servers: defs,
    callContext: (input) => input,
    sessionOf: (call) => call.session.sessionId,
    auth: createBearerAuthenticator(options.tokens ?? []),
    allowedHosts: [],
    allowedOrigins: [],
    session: { key: 'auto', idleTimeoutMs: 600_000, maxBindings: 64 },
    maxUpstreamConnections: options.maxUpstreamConnections ?? 8,
    maxBodyBytes: 1_000_000,
    maxUpstreamResponseBytes: 1_000_000,
    clientName: 'mcpguard-test',
    version: '9.9.9',
    clock: () => clock.at,
    onEvent: (event, detail) => events.push({ event, detail }),
  });
  open.push(() => gateway.close());
  const endpoint = await startHttpEndpoint({ handler: gateway.fetch, host: '127.0.0.1', port: 0 });
  open.push(() => endpoint.close());
  return {
    gateway,
    base: `http://127.0.0.1:${endpoint.port}`,
    upstreams,
    seen,
    events,
    clock,
  };
}

async function connectTo(
  multi: MultiRig,
  server: string,
  options: { modern?: boolean; name?: string } = {},
): Promise<Client> {
  const client = new Client(
    { name: options.name ?? 'agent', version: '1.0.0' },
    options.modern === true ? MODERN : {},
  );
  await client.connect(new StreamableHTTPClientTransport(new URL(`${multi.base}/mcp/${server}`)));
  open.push(() => client.close());
  return client;
}

describe.each([
  ['legacy', false],
  ['modern', true],
] as const)('several servers behind one gateway, in the %s era', (era, modern) => {
  it('serves each at its own path, through its own gates, to its own upstream', async () => {
    const m = await multiRig([
      { name: 'alpha', era },
      { name: 'beta', era },
    ]);
    const alpha = await connectTo(m, 'alpha', { modern });
    const beta = await connectTo(m, 'beta', { modern });

    await alpha.callTool({ name: 'show_meta', arguments: {} });
    expect(m.seen.alpha?.map((c) => c.tool)).toEqual(['show_meta']);
    expect(m.seen.beta).toEqual([]);
    expect(m.upstreams.alpha?.seenMeta).toHaveLength(1);
    expect(m.upstreams.beta?.seenMeta).toHaveLength(0);

    await beta.callTool({ name: 'echo', arguments: { text: 'b' } });
    expect(m.seen.beta?.map((c) => c.tool)).toEqual(['echo']);
    expect(m.seen.alpha).toHaveLength(1);
    expect(m.seen.alpha?.[0]?.call.upstream).toBe('alpha');
    expect(m.seen.beta?.[0]?.call.upstream).toBe('beta');
  });

  it('lets one server’s gates refuse what the other server’s let through', async () => {
    const m = await multiRig(
      [
        { name: 'alpha', era },
        { name: 'beta', era },
      ],
      { refuse: ['alpha'] },
    );
    const alpha = await connectTo(m, 'alpha', { modern });
    const beta = await connectTo(m, 'beta', { modern });
    expect(text(await alpha.callTool({ name: 'echo', arguments: { text: 'x' } }))).toBe(
      'refused by alpha',
    );
    expect(text(await beta.callTool({ name: 'echo', arguments: { text: 'x' } }))).toBe('x');
  });

  it('keeps serving the others when one upstream is down, and answers the dead one with a named error', async () => {
    const m = await multiRig([
      { name: 'alpha', era, dead: true },
      { name: 'beta', era },
    ]);
    const beta = await connectTo(m, 'beta', { modern });
    expect(text(await beta.callTool({ name: 'echo', arguments: { text: 'alive' } }))).toBe('alive');

    await expect(connectTo(m, 'alpha', { modern })).rejects.toThrow();
    const response = await post(
      m,
      modern
        ? {
            jsonrpc: '2.0',
            id: 7,
            method: 'tools/list',
            params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } },
          }
        : INITIALIZE,
      modern ? { 'mcp-protocol-version': '2026-07-28' } : {},
      '/mcp/alpha',
    );
    const body = (await response.json()) as { error?: { data?: Record<string, unknown> } };
    expect(body.error?.data).toMatchObject({ reason: 'upstream_unavailable', server: 'alpha' });
    // And the live one is untouched by any of it.
    expect(text(await beta.callTool({ name: 'echo', arguments: { text: 'still' } }))).toBe('still');
  });

  it('keeps serving the others when an upstream goes away while the gateway runs', async () => {
    const m = await multiRig([
      { name: 'alpha', era },
      { name: 'beta', era },
    ]);
    const alpha = await connectTo(m, 'alpha', { modern });
    const beta = await connectTo(m, 'beta', { modern });
    await alpha.callTool({ name: 'echo', arguments: { text: 'before' } });

    await m.upstreams.alpha?.close();
    await expect(
      alpha.callTool({ name: 'echo', arguments: { text: 'after' } }, { timeout: 5_000 }),
    ).rejects.toThrow();
    expect(text(await beta.callTool({ name: 'echo', arguments: { text: 'unharmed' } }))).toBe(
      'unharmed',
    );
  });

  it('attributes one client talking to two servers to one session', async () => {
    const m = await multiRig([
      { name: 'alpha', era },
      { name: 'beta', era },
    ]);
    const trace = '4bf92f3577b34da6a3ce929d0e0e4736';
    const meta = { _meta: { traceparent: traceparent(trace) } };
    const alpha = await connectTo(m, 'alpha', { modern });
    const beta = await connectTo(m, 'beta', { modern });
    await alpha.callTool({ name: 'echo', arguments: { text: 'a' }, ...meta });
    await beta.callTool({ name: 'echo', arguments: { text: 'b' }, ...meta });
    expect(m.seen.alpha?.[0]?.call.session).toMatchObject({ sessionId: trace, exact: true });
    expect(m.seen.beta?.[0]?.call.session).toMatchObject({ sessionId: trace, exact: true });
  });
});

describe('several servers behind one gateway', () => {
  it('answers 404 to a server that is not served, and does not take another’s name', async () => {
    const m = await multiRig([{ name: 'alpha' }, { name: 'beta' }]);
    for (const path of ['/mcp/gamma', '/mcp/alpha/extra', '/mcp/', '/mcp', '/mcp/__proto__']) {
      expect((await post(m, INITIALIZE, {}, path)).status, path).toBe(404);
    }
    expect((await post(m, INITIALIZE, {}, '/mcp/ALPHA')).status).toBe(404);
  });

  it('decodes a percent-encoded name before looking it up, and still finds no server in a path that smuggles a slash', async () => {
    const m = await multiRig([{ name: 'alpha', era: 'legacy' }, { name: 'beta' }]);
    // `%61` is `a`: the name is looked up whole, as `alpha`.
    expect((await post(m, INITIALIZE, {}, '/mcp/%61lpha')).status).toBe(200);
    for (const path of ['/mcp/alpha%2F..', '/mcp/alpha%2Fbeta', '/mcp/%2e%2e', '/mcp/%']) {
      expect((await post(m, INITIALIZE, {}, path)).status, path).toBe(404);
    }
  });

  it('does not tell a caller without a token which servers exist: a served name and an unserved one answer alike', async () => {
    const tokens = [{ identity: 'alice', tokenSha256: hashToken('alice-secret') }];
    const m = await multiRig([{ name: 'alpha', era: 'legacy' }, { name: 'beta' }], { tokens });
    for (const path of ['/mcp/alpha', '/mcp/beta', '/mcp/gamma', '/mcp/__proto__', '/mcp/a/b']) {
      const response = await post(m, INITIALIZE, {}, path);
      expect(response.status, path).toBe(401);
      expect(response.headers.get('www-authenticate')).toBe('Bearer');
    }
    // With a token the difference is the caller's to see.
    const auth = { authorization: 'Bearer alice-secret' };
    expect((await post(m, INITIALIZE, auth, '/mcp/alpha')).status).toBe(200);
    expect((await post(m, INITIALIZE, auth, '/mcp/gamma')).status).toBe(404);
    // And the gateway's own health check stays open.
    expect((await fetch(`${m.base}/healthz`)).status).toBe(200);
  });

  it('knows a legacy session by the server that opened it: its id is no session on another path', async () => {
    const m = await multiRig([
      { name: 'alpha', era: 'legacy' },
      { name: 'beta', era: 'legacy' },
    ]);
    const opened = await post(m, INITIALIZE, {}, '/mcp/alpha');
    const id = opened.headers.get('mcp-session-id') as string;
    await opened.text();
    expect(id).toBeTruthy();

    const ping = { jsonrpc: '2.0', id: 2, method: 'ping' };
    const elsewhere = await post(m, ping, { 'mcp-session-id': id }, '/mcp/beta');
    expect(elsewhere.status).toBe(404);
    const home = await post(m, ping, { 'mcp-session-id': id }, '/mcp/alpha');
    expect(home.status).toBe(200);
    expect(m.gateway.sessionCount('alpha')).toBe(1);
    expect(m.gateway.sessionCount('beta')).toBe(0);
    expect(m.gateway.sessionCount()).toBe(1);
  });

  it('bounds the legacy connections of each server on its own', async () => {
    const m = await multiRig(
      [
        { name: 'alpha', era: 'legacy' },
        { name: 'beta', era: 'legacy' },
      ],
      { maxUpstreamConnections: 1 },
    );
    const first = await connectTo(m, 'alpha');
    const refused = await post(m, INITIALIZE, {}, '/mcp/alpha');
    expect(refused.status).toBe(503);
    expect(refused.headers.get('retry-after')).toBe('5');
    // Full for alpha, and nothing of beta's.
    const other = await connectTo(m, 'beta');
    expect(text(await other.callTool({ name: 'echo', arguments: { text: 'b' } }))).toBe('b');
    expect(text(await first.callTool({ name: 'echo', arguments: { text: 'a' } }))).toBe('a');
    expect(m.events.some((e) => e.detail.reason === 'upstream_connections_full')).toBe(true);
  });

  it('closes an idle session of one server and leaves a session of another that is in use', async () => {
    const m = await multiRig([
      { name: 'alpha', era: 'legacy' },
      { name: 'beta', era: 'legacy' },
    ]);
    const idle = await post(m, INITIALIZE, {}, '/mcp/alpha');
    await idle.text();
    const busy = await connectTo(m, 'beta');
    const held = busy.callTool({ name: 'hold', arguments: {} }, { timeout: 20_000 });
    await new Promise((resolve) => setTimeout(resolve, 150));

    m.clock.at += 3_600_000;
    await (await post(m, INITIALIZE, {}, '/mcp/alpha')).text();
    expect(m.gateway.sessionCount('beta')).toBe(1);
    expect(m.events.filter((e) => e.event === 'session_closed' && e.detail.why === 'idle')).toEqual(
      [{ event: 'session_closed', detail: { server: 'alpha', why: 'idle' } }],
    );
    m.upstreams.beta?.release();
    expect(text(await held)).toBe('released');
  });

  it('guesses one session for a client with no trace id talking to two servers (modern), so a combination can span them', async () => {
    const m = await multiRig([
      { name: 'alpha', era: 'modern' },
      { name: 'beta', era: 'modern' },
    ]);
    const alpha = await connectTo(m, 'alpha', { modern: true, name: 'same-agent' });
    const beta = await connectTo(m, 'beta', { modern: true, name: 'same-agent' });
    await alpha.callTool({ name: 'echo', arguments: { text: 'a' } });
    await beta.callTool({ name: 'echo', arguments: { text: 'b' } });
    const first = m.seen.alpha?.[0]?.call.session;
    const second = m.seen.beta?.[0]?.call.session;
    expect(first).toMatchObject({ source: 'client-address', exact: false });
    expect(second?.sessionId).toBe(first?.sessionId);
    // Another client is another guess.
    const other = await connectTo(m, 'beta', { modern: true, name: 'someone-else' });
    await other.callTool({ name: 'echo', arguments: { text: 'c' } });
    expect(m.seen.beta?.[1]?.call.session.sessionId).not.toBe(first?.sessionId);
  });

  it('names a connection once across servers', async () => {
    const m = await multiRig([{ name: 'alpha' }, { name: 'beta' }]);
    const alpha = await connectTo(m, 'alpha', { modern: true });
    const beta = await connectTo(m, 'beta', { modern: true });
    await alpha.callTool({ name: 'echo', arguments: { text: 'a' } });
    await beta.callTool({ name: 'echo', arguments: { text: 'b' } });
    expect(m.seen.alpha?.[0]?.call.connection).not.toBe(m.seen.beta?.[0]?.call.connection);
  });

  it('reports what each upstream speaks, and which is down', async () => {
    const m = await multiRig([
      { name: 'old', era: 'legacy' },
      { name: 'new', era: 'modern' },
      { name: 'gone', dead: true },
    ]);
    const probed = await m.gateway.probe();
    expect(probed.map((p) => [p.server, p.era])).toEqual([
      ['old', 'legacy'],
      ['new', 'modern'],
      ['gone', 'unavailable'],
    ]);
  });

  it('will not be built with no servers, or one name twice', () => {
    const base = {
      callContext: (input: GatewayCallInput) => input,
      sessionOf: (call: GatewayCallInput) => call.session.sessionId,
      auth: createBearerAuthenticator([]),
      allowedHosts: [],
      allowedOrigins: [],
      session: { key: 'auto', idleTimeoutMs: 1_000, maxBindings: 4 },
      maxUpstreamConnections: 1,
      maxBodyBytes: 1_000,
      maxUpstreamResponseBytes: 1_000,
      clientName: 'x',
      version: '0',
    };
    const gates: Gates<GatewayCallInput> = {
      onCall: async (_r, forward) => forward(),
      onList: async (_r, forward) => forward(),
      onRead: async (_r, forward) => forward(),
    };
    expect(() => createHttpGateway({ ...base, servers: [] })).toThrow(/at least one server/);
    const server = { name: 'a', target: { url: 'http://127.0.0.1:1/mcp' }, gates };
    expect(() => createHttpGateway({ ...base, servers: [server, server] })).toThrow(/used twice/);
  });
});
