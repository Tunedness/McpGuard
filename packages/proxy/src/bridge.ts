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
 * `onList` and `onRead` gates: it knows they turn a request into a result, not
 * how. That keeps the transport skeleton liftable — see `boundary.test.ts`.
 */
import type { Client } from '@modelcontextprotocol/client';
import {
  type CallToolRequest,
  type CallToolResult,
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

/** A result schema that validates nothing, so forwarded methods pass through. */
export const PASSTHROUGH_RESULT: StandardSchemaV1<unknown, Result> = {
  '~standard': {
    version: 1,
    vendor: 'mcpguard',
    validate: (value: unknown) => ({ value: value as Result }),
  },
};

/** The guarded paths, injected by the host. Each turns a request into a result. */
export interface Gates {
  onCall(request: CallToolRequest, forward: () => Promise<CallToolResult>): Promise<CallToolResult>;
  onList(
    request: ListToolsRequest,
    forward: () => Promise<ListToolsResult>,
  ): Promise<ListToolsResult>;
  onRead(
    request: ReadResourceRequest,
    forward: () => Promise<ReadResourceResult>,
  ): Promise<ReadResourceResult>;
}

/** How a bridge is built. */
export interface BridgeOptions {
  readonly client: Client;
  readonly serverInfo: Implementation;
  readonly capabilities?: ServerCapabilities | undefined;
  readonly instructions?: string | undefined;
  readonly gates: Gates;
  readonly onError?: ((error: Error) => void) | undefined;
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
export function createBridge(options: BridgeOptions): Bridge {
  const { client, gates } = options;
  const server = new Server(options.serverInfo, {
    ...(options.capabilities !== undefined ? { capabilities: options.capabilities } : {}),
    ...(options.instructions !== undefined ? { instructions: options.instructions } : {}),
  });

  const report = (error: unknown): void => {
    options.onError?.(error instanceof Error ? error : new Error(String(error)));
  };

  const forward = async (method: string, params: unknown, ctx: ServerContext): Promise<Result> => {
    const request =
      params === undefined ? { method } : { method, params: params as Record<string, unknown> };
    return client.request(request, PASSTHROUGH_RESULT, { signal: ctx.mcpReq.signal });
  };

  const guardCall = async (request: CallToolRequest, ctx: ServerContext): Promise<CallToolResult> =>
    gates.onCall(request, async () => {
      const result = await forward('tools/call', request.params, ctx);
      if (!isCallToolResult(result)) {
        throw new Error('upstream answered tools/call with a non-CallToolResult');
      }
      return result;
    });

  const guardRead = async (
    request: ReadResourceRequest,
    ctx: ServerContext,
  ): Promise<ReadResourceResult> =>
    gates.onRead(
      request,
      async () => (await forward('resources/read', request.params, ctx)) as ReadResourceResult,
    );

  const guardList = async (
    request: ListToolsRequest,
    ctx: ServerContext,
  ): Promise<ListToolsResult> =>
    gates.onList(
      request,
      async () => (await forward('tools/list', request.params, ctx)) as ListToolsResult,
    );

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
    return forward(request.method, request.params, ctx);
  };
  server.fallbackNotificationHandler = async (notification: Notification) => {
    await client.notification(notification);
  };
  client.fallbackRequestHandler = async (request) =>
    server.request(request as unknown as JSONRPCRequest, PASSTHROUGH_RESULT);
  client.fallbackNotificationHandler = async (notification) => {
    await server.notification(notification as Notification);
  };

  let closed = false;
  return {
    server,
    client,
    close: async () => {
      if (closed) return;
      closed = true;
      const results = await Promise.allSettled([server.close(), client.close()]);
      for (const result of results) if (result.status === 'rejected') report(result.reason);
    },
  };
}
