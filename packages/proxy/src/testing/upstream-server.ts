/**
 * A real MCP server on a real loopback port, for tests that need an upstream.
 *
 * In whichever era is asked for: `legacy` is a sessionful 2025-style server,
 * `modern` is the per-request 2026-07-28 one (2025 openings refused), `both` is
 * the two behind the SDK's own era classifier. What it records is what a gateway
 * in front of it did to the traffic: the `_meta` each call arrived with, and how
 * many sessions and connections it saw.
 */
import { randomUUID } from 'node:crypto';
import {
  acceptedContent,
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  createMcpHandler,
  inputRequired,
  isInitializeRequest,
  isLegacyRequest,
  McpServer,
  WebStandardStreamableHTTPServerTransport,
} from '@modelcontextprotocol/server';
import { z } from 'zod';
import { startHttpEndpoint } from '../node-http.js';

export type UpstreamEra = 'legacy' | 'modern' | 'both';

export interface TestUpstream {
  readonly url: string;
  /** The `_meta` each `show_meta` call arrived with, newest last. */
  readonly seenMeta: Record<string, unknown>[];
  /** Legacy sessions open on this server now. */
  sessions(): number;
  /** Lets every call parked in `hold` finish. */
  release(): void;
  close(): Promise<void>;
}

export async function startUpstream(era: UpstreamEra = 'both'): Promise<TestUpstream> {
  const seenMeta: Record<string, unknown>[] = [];
  let releaseHeld: () => void = () => {};
  let held = new Promise<void>((resolve) => {
    releaseHeld = resolve;
  });

  const build = (): McpServer => {
    const server = new McpServer({ name: 'test-upstream', version: '1.0.0' });
    server.registerTool(
      'echo',
      { description: 'Echo the text.', inputSchema: z.object({ text: z.string() }) },
      async ({ text }) => ({ content: [{ type: 'text', text }] }),
    );
    server.registerTool(
      'show_meta',
      { description: 'Report the _meta of this request.', inputSchema: z.object({}) },
      async (_args, ctx) => {
        const meta = (ctx.mcpReq._meta ?? {}) as Record<string, unknown>;
        seenMeta.push(meta);
        return { content: [{ type: 'text', text: JSON.stringify(meta) }] };
      },
    );
    server.registerTool(
      'show_client',
      { description: 'Report who this request says is calling.', inputSchema: z.object({}) },
      async (_args, ctx) => {
        const envelope = ctx.mcpReq.envelope as Record<string, unknown> | undefined;
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                capabilities: envelope?.[CLIENT_CAPABILITIES_META_KEY],
                clientInfo: envelope?.[CLIENT_INFO_META_KEY],
              }),
            },
          ],
        };
      },
    );
    server.registerTool(
      'big',
      { description: 'Answer with n bytes.', inputSchema: z.object({ n: z.number() }) },
      async ({ n }) => ({ content: [{ type: 'text', text: 'x'.repeat(n) }] }),
    );
    server.registerTool(
      'hold',
      { description: 'Wait until released.', inputSchema: z.object({}) },
      async () => {
        await held;
        return { content: [{ type: 'text', text: 'released' }] };
      },
    );
    server.registerTool(
      'deploy',
      { description: 'Ask, then deploy.', inputSchema: z.object({ env: z.string() }) },
      async ({ env }, ctx) => {
        if (!acceptedContent(ctx.mcpReq.inputResponses, 'confirm')) {
          return inputRequired({
            inputRequests: {
              confirm: inputRequired.elicit({
                message: `Deploy to ${env}?`,
                requestedSchema: {
                  type: 'object',
                  properties: { confirm: { type: 'boolean' } },
                  required: ['confirm'],
                },
              }),
            },
          });
        }
        return { content: [{ type: 'text', text: `deployed to ${env}` }] };
      },
    );
    return server;
  };

  const modern = createMcpHandler(() => build(), { legacy: 'reject' });
  const transports = new Map<string, WebStandardStreamableHTTPServerTransport>();

  const legacy = async (request: Request, body: unknown): Promise<Response> => {
    const id = request.headers.get('mcp-session-id');
    if (id !== null) {
      const transport = transports.get(id);
      if (transport === undefined) return new Response('no such session', { status: 404 });
      return transport.handleRequest(request, { parsedBody: body });
    }
    if (!(request.method === 'POST' && isInitializeRequest(body))) {
      return new Response('bad request', { status: 400 });
    }
    const transport: WebStandardStreamableHTTPServerTransport =
      new WebStandardStreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid) => {
          transports.set(sid, transport);
        },
        onsessionclosed: (sid) => {
          transports.delete(sid);
        },
      });
    await build().connect(transport);
    return transport.handleRequest(request, { parsedBody: body });
  };

  const endpoint = await startHttpEndpoint({
    host: '127.0.0.1',
    port: 0,
    handler: async (request) => {
      const body = request.method === 'POST' ? JSON.parse(await request.text()) : undefined;
      if (era === 'modern') return modern.fetch(request, { parsedBody: body });
      if (era === 'legacy') return legacy(request, body);
      return (await isLegacyRequest(request, body))
        ? legacy(request, body)
        : modern.fetch(request, { parsedBody: body });
    },
  });

  return {
    url: `http://127.0.0.1:${endpoint.port}/mcp`,
    seenMeta,
    sessions: () => transports.size,
    release: () => {
      releaseHeld();
      held = new Promise<void>((resolve) => {
        releaseHeld = resolve;
      });
    },
    close: async () => {
      releaseHeld();
      await modern.close();
      await Promise.allSettled([...transports.values()].map((transport) => transport.close()));
      await endpoint.close();
    },
  };
}
