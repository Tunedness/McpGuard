/**
 * The guarded HTTP gateway: one Fetch handler in front of N upstreams (ADR-011).
 *
 * Each upstream is a server with its own path, `/mcp/<name>`, its own gates, its
 * own shared modern client and its own pool of legacy connections. Nothing is
 * merged: tool names, URIs and capabilities pass through as the server sent them,
 * and a server whose upstream is down answers its own path with an error while
 * every other path goes on. What the servers do share is what describes the
 * caller rather than the server: the bearer token, the Host and Origin checks, the
 * limits, and the session attribution table, so one client calling two servers is
 * one session.
 *
 * `serve` is `wrap` with an HTTP front door, and the front door has to answer
 * questions a pipe never asks: who is calling, which task is this call part of,
 * and which protocol era is this client speaking. The era is decided by the
 * SDK's own classifier, `isLegacyRequest`, and splits the traffic in two:
 *
 * - **Modern** (2026-07-28): no session, no `initialize`, no server-to-client
 *   request channel. `createMcpHandler(..., { legacy: 'reject' })` serves it from
 *   a factory that builds the bridge's downstream `Server` for each request, over
 *   one upstream `Client` shared by every request. Sharing is safe because
 *   nothing the upstream could push needs to be routed back to a particular
 *   caller.
 * - **Legacy** (2025 and earlier): a session per `Mcp-Session-Id`, which this
 *   gateway mints. Each session owns its transport, its bridge and its own
 *   upstream `Client` — one connection, as `wrap` has — because the legacy era
 *   pushes sampling, roots and elicitation without naming the caller, and a
 *   shared client would deliver them to the wrong downstream.
 *
 * Nothing is translated between the eras (ADR-002). A modern request to an
 * upstream that is legacy-only is refused with the SDK's own
 * unsupported-protocol-version answer, which lists the revisions this endpoint
 * does serve, so a negotiating client falls back by itself.
 *
 * Attribution is separate from the connection (ADR-011): every request's session
 * is resolved by the ADR-006 ladder at the moment the call is made, and written
 * into the `_meta` that goes upstream. Authentication is a static bearer token
 * checked before anything is parsed. Host and Origin are validated on every
 * request, no CORS header is ever written, and nothing here retries a call:
 * `tools/call` is not idempotent.
 *
 * Plain HTTP only. TLS is terminated in front of this, or the bind stays on
 * loopback.
 *
 * The per-request facts a gate needs but a `Request` cannot carry (the peer's
 * address, the token's identity) travel in an `AsyncLocalStorage`, so a handler
 * deep inside the SDK reads the facts of the request that is being served and
 * never those of one served beside it.
 *
 * This module imports neither engine package. See `boundary.test.ts`.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import {
  CLIENT_INFO_META_KEY,
  createMcpHandler,
  hostHeaderValidationResponse,
  isInitializeRequest,
  isJsonContentType,
  isLegacyRequest,
  localhostAllowedHostnames,
  localhostAllowedOrigins,
  originValidationResponse,
  ProtocolError,
  ProtocolErrorCode,
  type Server,
  type ServerContext,
  SUPPORTED_PROTOCOL_VERSIONS,
  WebStandardStreamableHTTPServerTransport,
} from '@modelcontextprotocol/server';
import { type Bridge, type BridgedRequest, createBridge, type Gates } from './bridge.js';
import { type Era, EraMismatchError, eraOf, FIRST_MODERN_PROTOCOL_VERSION } from './era.js';
import { type BearerAuthenticator, unauthorizedResponse } from './http-auth.js';
import { GATEWAY_ERROR, jsonRpcError } from './http-response.js';
import { listAllTools } from './list-tools.js';
import type { RequestContext } from './node-http.js';
import { type ClientIdentity, clientInfoOf, type MetaBag } from './remap.js';
import type { SessionKeyResolution, SessionKeyResolverOptions } from './session-ladder.js';
import { type PooledSession, SessionPool } from './session-pool.js';
import {
  connectUpstream,
  endUpstreamSession,
  SharedUpstream,
  UpstreamResponseTooLarge,
  type UpstreamTarget,
} from './upstream.js';

/** What the host is told about a call, to build the context its gates read. */
export interface GatewayCallInput {
  readonly era: Era;
  /** The session this call was attributed to, and which rung said so. */
  readonly session: SessionKeyResolution;
  /** The identity a bearer token mapped to, when the gateway authenticated one. */
  readonly tokenIdentity: string | undefined;
  /** What the caller says it is: from `initialize` (legacy) or the envelope (modern). */
  readonly clientInfo: ClientIdentity | undefined;
  /**
   * The raw `traceparent` header of the HTTP request, unparsed and unvalidated:
   * the host decides what it is worth. A `_meta.traceparent` is in the request.
   */
  readonly traceparent: string | undefined;
  /** Asks the upstream this call goes to for its whole tool list. */
  readonly listTools: () => Promise<readonly unknown[]>;
  /**
   * Names the upstream connection serving this call: one per legacy session, one
   * for the shared modern connection (and a new one when it is re-established).
   */
  readonly connection: string;
  /**
   * Names the server record this call belongs to (`servers.<name>`), for state that
   * belongs to what the server said rather than to who asked or which connection
   * carried it. It is the same for every session of both eras: a mismatch seen on
   * one session's upstream connection stops the server for all of them, the ones
   * opened afterwards included (ADR-005).
   */
  readonly upstream: string;
}

/** What one request cost the proxy, in milliseconds (ADR-011 item 7). */
export interface GatewayTiming {
  readonly era: Era;
  readonly method: string | undefined;
  /** Whether the call reached the upstream at all; a refused one did not. */
  readonly forwarded: boolean;
  /** Request received to upstream call sent. */
  readonly ingressMs: number;
  /** Upstream answer received to the response fully written. */
  readonly egressMs: number;
  readonly totalMs: number;
}

/** One upstream the gateway fronts. */
export interface GatewayServer<C> {
  /** The name it is routed by: `/mcp/<name>`. Unique in a gateway. */
  readonly name: string;
  readonly target: UpstreamTarget;
  /** The gates of this server: built for its name, so its rules and its lock entry are its own. */
  readonly gates: Gates<C>;
}

/** How a gateway is built. */
export interface HttpGatewayOptions<C> {
  /** The upstreams, each served at its own path. At least one. */
  readonly servers: readonly GatewayServer<C>[];
  /** Builds the context the gates read from what the gateway resolved. */
  readonly callContext: (input: GatewayCallInput) => C;
  /** The session id inside a context, to write into the `_meta` sent upstream. */
  readonly sessionOf: (context: C) => string | undefined;
  readonly auth: BearerAuthenticator;
  /** Hostnames accepted in `Host`; empty means the loopback names. */
  readonly allowedHosts: readonly string[];
  /** Hostnames accepted in `Origin` beyond localhost. */
  readonly allowedOrigins: readonly string[];
  readonly session: Pick<SessionKeyResolverOptions, 'key' | 'idleTimeoutMs' | 'maxBindings'>;
  /** Legacy upstream connections held open at once, per server. */
  readonly maxUpstreamConnections: number;
  readonly maxBodyBytes: number;
  readonly maxUpstreamResponseBytes: number;
  /** The proxy's own name, presented to the upstream as `clientInfo`. */
  readonly clientName: string;
  /** Reported by `/healthz`. */
  readonly version: string;
  readonly clock?: (() => number) | undefined;
  readonly onError?: ((error: Error) => void) | undefined;
  /** Operational events: `session_opened`, `upstream_lost`, `request_rejected`, … */
  readonly onEvent?: ((event: string, detail: Record<string, unknown>) => void) | undefined;
  /** Off by default; when set, called once per request with what the proxy added. */
  readonly onTiming?: ((timing: GatewayTiming) => void) | undefined;
}

/** What a server's upstream turned out to speak. */
export interface ServerProbe {
  readonly server: string;
  readonly era: Era | 'unavailable';
  readonly reason?: string;
}

/** A running gateway. */
export interface HttpGateway {
  fetch(request: Request, context: RequestContext): Promise<Response>;
  /**
   * Connects every upstream now, to report what each speaks. Never throws: an
   * upstream that is down is a fact to report, and the gateway still starts.
   */
  probe(): Promise<readonly ServerProbe[]>;
  /** Legacy sessions open right now, in one server or in all of them. */
  sessionCount(server?: string): number;
  close(): Promise<void>;
}

/** The facts of the request being served. */
interface RequestFacts {
  readonly era: Era;
  readonly remoteAddress: string | undefined;
  readonly tokenIdentity: string | undefined;
  readonly mcpSessionId: string | undefined;
  readonly clientInfo: ClientIdentity | undefined;
  readonly traceparent: string | undefined;
  readonly timing: { readonly start: number; sentAt?: number; receivedAt?: number };
}

interface LegacySession extends PooledSession {
  id: string | undefined;
  readonly transport: WebStandardStreamableHTTPServerTransport;
  readonly bridge: Bridge;
  readonly clientInfo: ClientIdentity | undefined;
}

const LEGACY_VERSIONS: readonly string[] = SUPPORTED_PROTOCOL_VERSIONS.filter(
  (version) => eraOf(version) === 'legacy',
);

function asBag(value: unknown): MetaBag | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as MetaBag)
    : undefined;
}

/** The JSON-RPC id of a request body, to answer it by. */
function idOf(body: unknown): string | number | null {
  const id = asBag(body)?.id;
  return typeof id === 'string' || typeof id === 'number' ? id : null;
}

function methodOf(body: unknown): string | undefined {
  const method = asBag(body)?.method;
  return typeof method === 'string' ? method.slice(0, 64) : undefined;
}

/**
 * Runs `done` once the response body has been read out, failed or been abandoned.
 *
 * A pull-based passthrough rather than a `TransformStream`, so backpressure
 * reaches the producer and a reader that goes away is noticed by `cancel`.
 */
function afterBody(response: Response, done: () => void): Response {
  if (response.body === null) {
    done();
    return response;
  }
  const reader = response.body.getReader();
  const watched = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const chunk = await reader.read();
        if (chunk.done) {
          controller.close();
          done();
        } else {
          controller.enqueue(chunk.value);
        }
      } catch (error) {
        controller.error(error);
        done();
      }
    },
    async cancel(reason) {
      done();
      await reader.cancel(reason);
    },
  });
  return new Response(watched, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

/** One server of the gateway: its upstream, its legs, its connection pool. */
interface Leg {
  readonly name: string;
  serveModern(request: Request, body: unknown, facts: RequestFacts): Promise<Response>;
  serveLegacy(request: Request, body: unknown, facts: RequestFacts): Promise<Response>;
  probe(): Promise<ServerProbe>;
  sessionCount(): number;
  close(): Promise<void>;
}

/** Builds the gateway. */
export function createHttpGateway<C>(options: HttpGatewayOptions<C>): HttpGateway {
  const clock = options.clock ?? (() => Date.now());
  const report = (error: unknown): void => {
    options.onError?.(error instanceof Error ? error : new Error(String(error)));
  };
  const emit = (event: string, detail: Record<string, unknown> = {}): void => {
    options.onEvent?.(event, detail);
  };

  if (options.servers.length === 0) {
    throw new Error('a gateway needs at least one server');
  }
  const names = new Set<string>();
  for (const server of options.servers) {
    if (server.name === '' || names.has(server.name)) {
      throw new Error(`server name "${server.name}" is empty or used twice`);
    }
    names.add(server.name);
  }

  const storage = new AsyncLocalStorage<RequestFacts>();
  // One pool for the gateway: the attribution table is shared by every server, so
  // one client talking to two of them is one session, and the sweeper is one timer.
  const pool = new SessionPool({ ...options.session, clock });
  const resolver = pool.resolver;
  pool.start();
  const hosts =
    options.allowedHosts.length > 0 ? [...options.allowedHosts] : localhostAllowedHostnames();
  // A gateway reachable by name accepts the origins it was given and no others:
  // `http://localhost:*` means nothing to a browser talking to a remote host.
  const origins =
    options.allowedHosts.length > 0
      ? [...options.allowedOrigins]
      : [...localhostAllowedOrigins(), ...options.allowedOrigins];
  let closed = false;

  const connectionIds = new WeakMap<object, string>();
  let connectionCount = 0;
  const connectionOf = (upstream: object): string => {
    let id = connectionIds.get(upstream);
    if (id === undefined) {
      id = `upstream-${connectionCount++}`;
      connectionIds.set(upstream, id);
    }
    return id;
  };

  const onUpstream = (phase: 'sent' | 'received'): void => {
    const timing = storage.getStore()?.timing;
    if (timing === undefined) return;
    if (phase === 'sent') timing.sentAt = performance.now();
    else timing.receivedAt = performance.now();
  };

  const reject = (reason: string, response: Response, detail: Record<string, unknown> = {}) => {
    emit('request_rejected', { reason, status: response.status, ...detail });
    return response;
  };

  /**
   * Everything one server owns. A server's upstream failing is that server's
   * failure: its shared client, its legacy connections and its pool are its own,
   * and nothing in a leg reaches another leg's state.
   */
  const buildLeg = (server: GatewayServer<C>): Leg => {
    const serverName = server.name;
    const shared = new SharedUpstream({
      clock,
      connect: () =>
        connectUpstream({
          target: server.target,
          era: 'modern',
          clientName: options.clientName,
          maxResponseBytes: options.maxUpstreamResponseBytes,
        }),
      onError: report,
      onConnected: () => emit('upstream_connected', { server: serverName, era: 'modern' }),
      onLost: () => emit('upstream_lost', { server: serverName, era: 'modern' }),
    });

    const sessions = pool.connections<LegacySession>({
      maxConnections: options.maxUpstreamConnections,
      onDrop: (session, why) => {
        emit('session_closed', { server: serverName, why });
        endUpstreamSession(session.bridge.client)
          .then(() => session.bridge.close())
          .catch(report);
      },
    });

    /** The per-call hook of a bridge in `era`: runs the session ladder and asks the host for a context. */
    const callContextFor =
      (era: Era, upstream: Bridge['client']) =>
      (request: BridgedRequest, ctx: ServerContext): C => {
        const facts = storage.getStore();
        if (facts === undefined) {
          throw new ProtocolError(ProtocolErrorCode.InternalError, 'The request context was lost');
        }
        const meta = asBag((request.params as { _meta?: unknown } | undefined)?._meta);
        const clientInfo =
          facts.clientInfo ?? clientInfoOf(asBag((ctx.mcpReq as { envelope?: unknown }).envelope));
        const session = resolver.resolve({
          meta,
          mcpSessionId: facts.mcpSessionId,
          clientInfo,
          remoteAddress: facts.remoteAddress,
        });
        if (session === undefined) {
          // Refused rather than given a session of its own: a call attributed to a
          // session that exists for that call alone would turn every combination
          // rule into no rule.
          throw new ProtocolError(
            ProtocolErrorCode.InvalidRequest,
            'The session of this request could not be resolved; check session.key',
          );
        }
        return options.callContext({
          era,
          session,
          tokenIdentity: facts.tokenIdentity,
          clientInfo,
          traceparent: facts.traceparent,
          listTools: () => listAllTools(upstream),
          connection: connectionOf(upstream),
          upstream: serverName,
        });
      };

    const bridgeFor = (era: Era, client: Bridge['client'], sharedUpstream: boolean): Bridge =>
      createBridge<C>({
        client,
        serverInfo: client.getServerVersion() ?? { name: serverName, version: '0.0.0' },
        capabilities: client.getServerCapabilities(),
        instructions: client.getInstructions(),
        gates: server.gates,
        callContext: callContextFor(era, client),
        sessionOf: options.sessionOf,
        forwardClientInfo: era === 'modern',
        sharedUpstream,
        onError: report,
        ...(options.onTiming !== undefined ? { onUpstream } : {}),
      });

    const modern = createMcpHandler(
      async (): Promise<Server> => {
        const client = await shared.get();
        return bridgeFor('modern', client, true).server;
      },
      { legacy: 'reject', onerror: report },
    );

    // -- answers the gateway writes itself ----------------------------------

    const upstreamFailure = (error: unknown, id: string | number | null, era: Era): Response => {
      const failure = error instanceof Error ? error : new Error(String(error));
      if (failure instanceof EraMismatchError) {
        // The answer lists what this endpoint does serve for the server, so a
        // negotiating client falls back to it instead of giving up.
        return jsonRpcError(
          400,
          GATEWAY_ERROR.unsupportedProtocolVersion,
          `Unsupported protocol version: the server "${serverName}" does not speak this protocol era`,
          {
            supported: era === 'modern' ? [...LEGACY_VERSIONS] : [FIRST_MODERN_PROTOCOL_VERSION],
            reason: 'era_mismatch',
            server: serverName,
          },
          undefined,
          id,
        );
      }
      report(failure);
      const tooLarge = failure instanceof UpstreamResponseTooLarge;
      return jsonRpcError(
        200,
        GATEWAY_ERROR.internal,
        tooLarge ? 'The upstream response was too large' : 'The upstream server is unavailable',
        {
          reason: tooLarge ? 'upstream_response_too_large' : 'upstream_unavailable',
          server: serverName,
          ...(tooLarge ? { limit: failure.limit } : {}),
        },
        undefined,
        id,
      );
    };

    // -- the modern leg ------------------------------------------------------

    const serveModern = async (
      request: Request,
      body: unknown,
      facts: RequestFacts,
    ): Promise<Response> => {
      try {
        await shared.get();
      } catch (error) {
        return upstreamFailure(error, idOf(body), 'modern');
      }
      return storage.run(facts, () => modern.fetch(request, { parsedBody: body }));
    };

    // -- the legacy leg ------------------------------------------------------

    const openLegacy = async (
      request: Request,
      body: Record<string, unknown>,
      facts: RequestFacts,
    ): Promise<Response> => {
      const release = sessions.reserve();
      if (release === undefined) {
        return reject(
          'upstream_connections_full',
          jsonRpcError(
            503,
            GATEWAY_ERROR.refused,
            'Service busy: too many open sessions for this server',
            { reason: 'upstream_connections_full', server: serverName },
            { 'retry-after': '5' },
            idOf(body),
          ),
          { server: serverName },
        );
      }
      try {
        const params = asBag(body.params);
        const capabilities = asBag(params?.capabilities);
        const clientInfo = clientInfoOf({ [CLIENT_INFO_META_KEY]: params?.clientInfo });
        let client: Bridge['client'];
        try {
          client = await connectUpstream({
            target: server.target,
            era: 'legacy',
            clientName: options.clientName,
            maxResponseBytes: options.maxUpstreamResponseBytes,
            // What the downstream declared is what the upstream is told.
            ...(capabilities !== undefined
              ? {
                  capabilities: capabilities as Parameters<
                    typeof connectUpstream
                  >[0]['capabilities'],
                }
              : {}),
          });
        } catch (error) {
          return upstreamFailure(error, idOf(body), 'legacy');
        }

        const bridge = bridgeFor('legacy', client, false);
        const session: LegacySession = {
          id: undefined,
          bridge,
          owner: facts.tokenIdentity,
          clientInfo,
          lastSeenAt: clock(),
          inflight: 0,
          transport: new WebStandardStreamableHTTPServerTransport({
            // A gateway-minted, unguessable id: it is the exact session rung of the
            // ladder, and it is the only credential a legacy stream has. The
            // upstream's own session id never reaches the downstream.
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (id) => {
              session.id = id;
              sessions.add(id, session);
              emit('session_opened', { server: serverName, session: id });
            },
            onsessionclosed: () => {
              sessions.drop(session.id, session, 'deleted');
            },
          }),
        };
        bridge.server.onclose = () => {
          sessions.drop(session.id, session, 'closed');
        };
        // The upstream going away ends the session too: a child that died leaves
        // nothing to talk to, and a session that stayed would keep its pool slot and,
        // being used, never look idle. The client's next request gets a 404 and
        // initializes afresh.
        client.onclose = () => {
          sessions.drop(session.id, session, 'closed');
        };
        try {
          await bridge.server.connect(session.transport);
          const response = await storage.run({ ...facts, clientInfo }, () =>
            session.transport.handleRequest(request, { parsedBody: body }),
          );
          // An `initialize` the transport refused leaves no session: free what it holds.
          if (session.id === undefined) await bridge.close();
          return response;
        } catch (error) {
          await bridge.close().catch(report);
          throw error;
        }
      } finally {
        release();
      }
    };

    const serveLegacy = async (
      request: Request,
      body: unknown,
      facts: RequestFacts,
    ): Promise<Response> => {
      pool.sweep();
      const sessionId = request.headers.get('mcp-session-id');
      if (sessionId === null) {
        const message = asBag(body);
        if (request.method === 'POST' && message !== undefined && isInitializeRequest(message)) {
          return openLegacy(request, message, facts);
        }
        return reject(
          'session_required',
          jsonRpcError(
            400,
            GATEWAY_ERROR.invalidRequest,
            'Bad Request: Mcp-Session-Id header is required',
            undefined,
            undefined,
            idOf(body),
          ),
          { server: serverName },
        );
      }
      // Looked up in this server's pool only: a session id minted for another
      // server's path is no session here.
      const lease = sessions.use(sessionId, facts.tokenIdentity);
      if (lease === undefined) {
        // The same answer for an unknown session and for one that is someone
        // else's: whether the id exists is not the caller's to learn.
        return reject(
          'session_not_found',
          jsonRpcError(
            404,
            GATEWAY_ERROR.refused,
            'Session not found',
            undefined,
            undefined,
            idOf(body),
          ),
          { server: serverName },
        );
      }
      try {
        const response = await storage.run(
          { ...facts, mcpSessionId: sessionId, clientInfo: lease.session.clientInfo },
          () =>
            lease.session.transport.handleRequest(
              request,
              body === undefined ? undefined : { parsedBody: body },
            ),
        );
        // The call is in flight until its response has been read out, not until
        // the SDK has handed over a stream: an idle sweep must not close a session
        // in the middle of a long tool call.
        return afterBody(response, lease.done);
      } catch (error) {
        lease.done();
        throw error;
      }
    };

    return {
      name: serverName,
      serveModern,
      serveLegacy,
      async probe() {
        try {
          await shared.get();
          return { server: serverName, era: 'modern' };
        } catch (error) {
          if (error instanceof EraMismatchError) return { server: serverName, era: 'legacy' };
          return {
            server: serverName,
            era: 'unavailable',
            reason: error instanceof Error ? error.message : String(error),
          };
        }
      },
      sessionCount: () => sessions.size,
      async close() {
        await Promise.allSettled([
          modern.close(),
          shared.close(),
          ...sessions.drain().map(async (session) => {
            await endUpstreamSession(session.bridge.client);
            await session.bridge.close();
          }),
        ]);
      },
    };
  };

  const legs = new Map<string, Leg>(
    options.servers.map((server) => [server.name, buildLeg(server)]),
  );

  // -- the front door --------------------------------------------------------

  const dispatch = async (request: Request, context: RequestContext): Promise<Response> => {
    // Timing reads the monotonic high-resolution clock, not the injected one: that
    // is a wall clock in milliseconds, for expiry, and a sub-millisecond cost
    // would read as zero on it.
    const started = performance.now();
    const hostRefusal =
      hostHeaderValidationResponse(request, hosts) ?? originValidationResponse(request, origins);
    if (hostRefusal !== undefined) return reject('host_or_origin', hostRefusal);

    const url = new URL(request.url);
    if (url.pathname === '/healthz') {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return jsonRpcError(405, GATEWAY_ERROR.invalidRequest, 'Method not allowed', undefined, {
          allow: 'GET, HEAD',
        });
      }
      return new Response(JSON.stringify({ status: 'ok', version: options.version }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }

    // Before the path is looked at: with tokens defined, whether a server name exists
    // is for a caller who holds one to learn, so a name that is served and one that is
    // not answer a caller without a token the same way.
    const authenticated = options.auth.authenticate(request.headers);
    if (authenticated.kind === 'refused') {
      return reject('unauthorized', unauthorizedResponse(), { why: authenticated.reason });
    }
    const tokenIdentity = authenticated.kind === 'ok' ? authenticated.identity : undefined;

    const segments = url.pathname.split('/');
    let routed: string | undefined;
    if (segments.length === 3 && segments[0] === '' && segments[1] === 'mcp') {
      try {
        routed = decodeURIComponent(segments[2] as string);
      } catch {
        routed = undefined;
      }
    }
    // An own-property lookup on a Map: a name like `__proto__` is no server.
    const leg = routed === undefined ? undefined : legs.get(routed);
    if (leg === undefined) {
      return reject(
        'unknown_server',
        jsonRpcError(404, GATEWAY_ERROR.refused, 'Not found', { reason: 'unknown_server' }),
      );
    }

    if (request.method !== 'POST' && request.method !== 'GET' && request.method !== 'DELETE') {
      return reject(
        'method_not_allowed',
        jsonRpcError(405, GATEWAY_ERROR.invalidRequest, 'Method not allowed', undefined, {
          allow: 'POST, GET, DELETE',
        }),
      );
    }

    let body: unknown;
    if (request.method === 'POST') {
      if (!isJsonContentType(request.headers.get('content-type'))) {
        return reject(
          'unsupported_media_type',
          jsonRpcError(
            415,
            GATEWAY_ERROR.invalidRequest,
            'Unsupported Media Type: Content-Type must be application/json',
          ),
        );
      }
      const text = await request.text();
      if (Buffer.byteLength(text, 'utf8') > options.maxBodyBytes) {
        return reject('body_too_large', new Response('request body too large\n', { status: 413 }));
      }
      try {
        body = JSON.parse(text);
      } catch {
        return reject(
          'parse_error',
          jsonRpcError(400, -32700, 'Parse error: the body is not valid JSON'),
        );
      }
    }

    const era: Era = (await isLegacyRequest(request, body)) ? 'legacy' : 'modern';
    const facts: RequestFacts = {
      era,
      remoteAddress: context.remoteAddress,
      tokenIdentity,
      mcpSessionId: undefined,
      clientInfo: undefined,
      traceparent: request.headers.get('traceparent') ?? undefined,
      timing: { start: started },
    };
    const response =
      era === 'modern'
        ? await leg.serveModern(request, body, facts)
        : await leg.serveLegacy(request, body, facts);

    if (options.onTiming === undefined) return response;
    return afterBody(response, () => {
      const end = performance.now();
      const { start, sentAt, receivedAt } = facts.timing;
      options.onTiming?.({
        era,
        method: methodOf(body),
        forwarded: sentAt !== undefined && receivedAt !== undefined,
        ingressMs: (sentAt ?? end) - start,
        egressMs: receivedAt === undefined ? 0 : end - receivedAt,
        totalMs: end - start,
      });
    });
  };

  return {
    async fetch(request, context) {
      if (closed) {
        return jsonRpcError(503, GATEWAY_ERROR.refused, 'The gateway is shutting down');
      }
      try {
        return await dispatch(request, context);
      } catch (error) {
        report(error);
        return jsonRpcError(
          500,
          GATEWAY_ERROR.internal,
          'The gateway failed to handle the request',
        );
      }
    },
    probe: () => Promise.all([...legs.values()].map((leg) => leg.probe())),
    sessionCount(server) {
      if (server !== undefined) return legs.get(server)?.sessionCount() ?? 0;
      let total = 0;
      for (const leg of legs.values()) total += leg.sessionCount();
      return total;
    },
    async close() {
      closed = true;
      pool.close();
      await Promise.allSettled([...legs.values()].map((leg) => leg.close()));
    },
  };
}
