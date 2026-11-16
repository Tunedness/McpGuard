/**
 * The `Server` + `Client` pair, and the guarded seams hung off it.
 *
 * One upstream `Client` per downstream connection: multiplexing breaks
 * sampling, elicitation and roots, which the legacy era pushes without naming
 * the caller. Three methods are ours — `tools/call`, `tools/list`,
 * `resources/read` — and everything else passes through the fallback handlers
 * untouched, because a proxy is not a validator and a method it has never heard
 * of has to work.
 *
 * This module imports the engines only through the injected `onCall`,
 * `onList`, `onRead` and `onRequest` gates: it knows they turn a request into a result, not
 * how. That keeps the transport skeleton liftable — see `boundary.test.ts`.
 *
 * A host that serves many callers through one set of gates (the HTTP gateway)
 * has a per-call fact the gates need — which session, which identity — that a
 * connection-bound host (`wrap`) holds once. `callContext` resolves it for each
 * request as it arrives and hands it to the gate; the bridge does not look
 * inside it. A host that has no such thing passes nothing and the gates are
 * called with `undefined`, exactly as before.
 */
import type { Client } from '@modelcontextprotocol/client';
import {
  type CallToolRequest,
  type CallToolResult,
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  type Implementation,
  isCallToolResult,
  type JSONRPCRequest,
  type ListToolsRequest,
  type ListToolsResult,
  type Notification,
  type ReadResourceRequest,
  type ReadResourceResult,
  type Result,
  Server,
  type ServerCapabilities,
  type ServerContext,
  type StandardSchemaV1,
} from '@modelcontextprotocol/server';
import { injectSession } from './remap.js';

/** A result schema that validates nothing, so forwarded methods pass through. */
export const PASSTHROUGH_RESULT: StandardSchemaV1<unknown, Result> = {
  '~standard': {
    version: 1,
    vendor: 'mcpguard',
    validate: (value: unknown) => ({ value: value as Result }),
  },
};

/**
 * The guarded paths, injected by the host. Each turns a request into a result.
 *
 * `C` is whatever the host resolves per call (see {@link BridgeOptions.callContext});
 * for a host that resolves nothing it is `undefined`.
 */
export interface Gates<C = undefined> {
  onCall(
    request: CallToolRequest,
    forward: () => Promise<CallToolResult>,
    context: C,
  ): Promise<CallToolResult>;
  onList(
    request: ListToolsRequest,
    forward: () => Promise<ListToolsResult>,
    context: C,
  ): Promise<ListToolsResult>;
  onRead(
    request: ReadResourceRequest,
    forward: () => Promise<ReadResourceResult>,
    context: C,
  ): Promise<ReadResourceResult>;
  /**
   * Every other request the downstream sends the server — `resources/list`,
   * `prompts/get`, `completion/complete` and whatever a method the proxy has never
   * heard of is called. The host decides whether it goes on; the result is the
   * server's, untouched. The SDK answers `initialize` and `ping` itself, so they
   * never arrive here.
   */
  onRequest(request: BridgedRequest, forward: () => Promise<Result>, context: C): Promise<Result>;
}

/** A request as the bridge shows it to a per-call hook. */
export interface BridgedRequest {
  readonly method: string;
  readonly params?: unknown;
}

/** Where an upstream call is, for a host that measures the time the proxy adds. */
export type UpstreamPhase = 'sent' | 'received';

/** How a bridge is built. */
export interface BridgeOptions<C = undefined> {
  readonly client: Client;
  readonly serverInfo: Implementation;
  readonly capabilities?: ServerCapabilities | undefined;
  readonly instructions?: string | undefined;
  readonly gates: Gates<C>;
  readonly onError?: ((error: Error) => void) | undefined;
  /**
   * Resolves the per-call context from the request as it arrives. It may throw
   * to refuse the request: the error is the answer the caller gets.
   */
  readonly callContext?:
    | ((request: BridgedRequest, context: ServerContext) => C | Promise<C>)
    | undefined;
  /**
   * The session id to write into the `_meta` of every request forwarded upstream,
   * as the `tunedness.session-id` baggage member (ADR-006). Absent, nothing is
   * injected, which is what `wrap` does.
   */
  readonly sessionOf?: ((context: C) => string | undefined) | undefined;
  /**
   * Also hand the downstream's own `clientInfo` to the upstream on a modern
   * request, next to its capabilities. Without it the upstream sees the proxy's.
   */
  readonly forwardClientInfo?: boolean | undefined;
  /**
   * The upstream `Client` is shared with other bridges (the modern leg of the
   * gateway builds one bridge per request over one client). Such a bridge does
   * not install the client's fallback handlers, does not forward notifications —
   * their request ids are the downstream's, and on a client every caller shares
   * they would name some other caller's call — and does not close the client.
   */
  readonly sharedUpstream?: boolean | undefined;
  /** Called as each upstream call leaves and returns, for latency measurement. */
  readonly onUpstream?: ((phase: UpstreamPhase, context: C) => void) | undefined;
}

/** A running bridge. */
export interface Bridge {
  readonly server: Server;
  readonly client: Client;
  close(): Promise<void>;
}

function servesTools(capabilities: ServerCapabilities | undefined): boolean {
  return capabilities?.tools !== undefined;
}

function servesResources(capabilities: ServerCapabilities | undefined): boolean {
  return capabilities?.resources !== undefined;
}

/** Wires a downstream `Server` to an already-connected upstream `Client`. */
export function createBridge<C = undefined>(options: BridgeOptions<C>): Bridge {
  const { client, gates } = options;
  const server = new Server(options.serverInfo, {
    ...(options.capabilities !== undefined ? { capabilities: options.capabilities } : {}),
    ...(options.instructions !== undefined ? { instructions: options.instructions } : {}),
  });

  const report = (error: unknown): void => {
    options.onError?.(error instanceof Error ? error : new Error(String(error)));
  };

  const contextOf = async (request: BridgedRequest, ctx: ServerContext): Promise<C> =>
    options.callContext !== undefined
      ? options.callContext(request, ctx)
      : (undefined as unknown as C);

  const forward = async (
    method: string,
    params: unknown,
    ctx: ServerContext,
    call: C,
  ): Promise<Result> => {
    // The modern era has no `initialize` to carry what the client can do: every
    // request names it on its own `_meta` envelope, which the downstream server
    // lifts off before a handler sees the request. The upstream client builds an
    // envelope of its own, from what was declared when it connected; a `_meta`
    // key set here wins over it, so the capabilities of *this* request are the
    // ones the upstream server is told.
    const envelope = ctx.mcpReq.envelope as Record<string, unknown> | undefined;
    const carried = params as { _meta?: Record<string, unknown> } | undefined;
    let meta: Record<string, unknown> | undefined;
    const set = (key: string, value: unknown): void => {
      meta = { ...carried?._meta, ...meta, [key]: value };
    };
    const declared = envelope?.[CLIENT_CAPABILITIES_META_KEY];
    if (declared !== undefined) set(CLIENT_CAPABILITIES_META_KEY, declared);
    const caller = envelope?.[CLIENT_INFO_META_KEY];
    if (options.forwardClientInfo === true && caller !== undefined) {
      set(CLIENT_INFO_META_KEY, caller);
    }
    // The outermost proxy puts the session it resolved where the inner ones read
    // it, over whatever the caller wrote there: the upstream must hear the session
    // the audit record names (ADR-006), including when the ladder passed over the
    // caller's own member.
    const session = options.sessionOf?.(call);
    if (session !== undefined) {
      meta = injectSession({ ...carried?._meta, ...meta }, session, { replace: true });
    }
    const withEnvelope = meta === undefined ? params : { ...carried, _meta: meta };
    const request =
      withEnvelope === undefined
        ? { method }
        : { method, params: withEnvelope as Record<string, unknown> };
    options.onUpstream?.('sent', call);
    try {
      return await client.request(request, PASSTHROUGH_RESULT, { signal: ctx.mcpReq.signal });
    } finally {
      options.onUpstream?.('received', call);
    }
  };

  const guardCall = async (
    request: CallToolRequest,
    ctx: ServerContext,
  ): Promise<CallToolResult> => {
    const call = await contextOf(request, ctx);
    return gates.onCall(
      request,
      async () => {
        const result = await forward('tools/call', request.params, ctx, call);
        if (!isCallToolResult(result)) {
          throw new Error('upstream answered tools/call with a non-CallToolResult');
        }
        return result;
      },
      call,
    );
  };

  const guardRead = async (
    request: ReadResourceRequest,
    ctx: ServerContext,
  ): Promise<ReadResourceResult> => {
    const call = await contextOf(request, ctx);
    return gates.onRead(
      request,
      async () =>
        (await forward('resources/read', request.params, ctx, call)) as ReadResourceResult,
      call,
    );
  };

  const guardList = async (
    request: ListToolsRequest,
    ctx: ServerContext,
  ): Promise<ListToolsResult> => {
    const call = await contextOf(request, ctx);
    return gates.onList(
      request,
      async () => (await forward('tools/list', request.params, ctx, call)) as ListToolsResult,
      call,
    );
  };

  if (servesTools(options.capabilities)) {
    server.setRequestHandler('tools/call', guardCall);
    server.setRequestHandler('tools/list', guardList);
  }
  if (servesResources(options.capabilities)) {
    server.setRequestHandler('resources/read', guardRead);
  }

  server.fallbackRequestHandler = async (request: JSONRPCRequest, ctx: ServerContext) => {
    if (request.method === 'tools/call')
      return guardCall(request as unknown as CallToolRequest, ctx);
    if (request.method === 'resources/read')
      return guardRead(request as unknown as ReadResourceRequest, ctx);
    const call = await contextOf(request, ctx);
    return gates.onRequest(request, () => forward(request.method, request.params, ctx, call), call);
  };
  const shared = options.sharedUpstream === true;
  server.fallbackNotificationHandler = async (notification: Notification) => {
    if (!shared) await client.notification(notification);
  };
  if (!shared) {
    client.fallbackRequestHandler = async (request) =>
      server.request(request as unknown as JSONRPCRequest, PASSTHROUGH_RESULT);
    client.fallbackNotificationHandler = async (notification) => {
      await server.notification(notification as Notification);
    };
  }

  let closed = false;
  return {
    server,
    client,
    close: async () => {
      if (closed) return;
      closed = true;
      const results = await Promise.allSettled([
        server.close(),
        shared ? undefined : client.close(),
      ]);
      for (const result of results) if (result.status === 'rejected') report(result.reason);
    },
  };
}
