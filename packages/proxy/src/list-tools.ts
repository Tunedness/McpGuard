/**
 * Asking an upstream stdio server for its whole tool list, once, and leaving.
 *
 * `mcpguard lock` needs the manifest a server advertises right now without
 * putting a proxy in front of anyone. It goes through the same raw
 * `tools/list` request the bridge forwards (`PASSTHROUGH_RESULT`), not the
 * SDK's parsed `listTools()`: the lock hashes what the server sent, and a
 * second path that normalised it could disagree with the gate about whether a
 * tool changed.
 */
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { PASSTHROUGH_RESULT } from './bridge.js';
import { EraMismatchError } from './era.js';
import { connectUpstream, endUpstreamSession, type UpstreamTarget } from './upstream.js';

/** How to reach the server. */
export interface ListToolsOptions {
  readonly command: string;
  readonly args: readonly string[];
  /** Environment for the child. Defaults to the parent's. */
  readonly env?: Record<string, string> | undefined;
  /** A server that never stops paginating is refused after this many pages. */
  readonly maxPages?: number | undefined;
}

const DEFAULT_MAX_PAGES = 64;

/**
 * Walks every page of `tools/list` on a connected client and returns the raw
 * tool entries in advertised order.
 *
 * @throws when the server errors or paginates without end.
 */
export async function listAllTools(
  client: Client,
  maxPages: number = DEFAULT_MAX_PAGES,
): Promise<unknown[]> {
  const tools: unknown[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const result = (await client.request(
      { method: 'tools/list', ...(cursor !== undefined ? { params: { cursor } } : {}) },
      PASSTHROUGH_RESULT,
    )) as { tools?: unknown; nextCursor?: unknown };
    if (Array.isArray(result.tools)) tools.push(...result.tools);
    const next = typeof result.nextCursor === 'string' ? result.nextCursor : undefined;
    if (next === undefined) return tools;
    if (seen.has(next)) throw new Error('the server repeated a pagination cursor');
    seen.add(next);
    cursor = next;
  }
  throw new Error('the server did not stop paginating tools/list');
}

/**
 * Spawns the server, walks every page of `tools/list`, closes it, and returns
 * the raw tool entries in advertised order.
 *
 * @throws when the server cannot be started, errors, or paginates without end.
 */
export async function listStdioTools(options: ListToolsOptions): Promise<unknown[]> {
  const transport = new StdioClientTransport({
    command: options.command,
    args: [...options.args],
    stderr: 'inherit',
    ...(options.env !== undefined ? { env: options.env } : {}),
  });
  const client = new Client({ name: 'mcpguard-lock', version: '0.0.0' });
  await client.connect(transport);
  try {
    return await listAllTools(client, options.maxPages);
  } finally {
    await client.close().catch(() => {});
  }
}

/** How {@link listUpstreamTools} reaches the server. */
export interface ListUpstreamOptions {
  /** The upstream as the gateway reaches it: a URL or a command. */
  readonly target: UpstreamTarget;
  /** Presented to the upstream as `clientInfo`. */
  readonly clientName: string;
  /** The same response ceiling the gateway applies to this upstream, for a URL. */
  readonly maxResponseBytes?: number | undefined;
  readonly maxPages?: number | undefined;
}

/**
 * Asks an upstream for its whole tool list, over the connection path the gateway
 * itself uses (`connectUpstream`): the same transport, the same response ceiling,
 * the same way of finding out which protocol era the server speaks. A client that
 * the gateway could not reach is a client `mcpguard lock` cannot reach either, and
 * one it can reach is read exactly as the gateway would read it, so the manifest
 * the lock pins is the one the gate will compare.
 *
 * The modern era is tried first, as the gateway's probe does; a legacy-only server
 * is then asked in its own era. Nothing is translated.
 *
 * @throws when the server cannot be reached, errors, or paginates without end.
 */
export async function listUpstreamTools(options: ListUpstreamOptions): Promise<unknown[]> {
  const connect = (era: 'modern' | 'legacy') =>
    connectUpstream({
      target: options.target,
      era,
      clientName: options.clientName,
      maxResponseBytes: options.maxResponseBytes,
    });
  let client: Client;
  try {
    client = await connect('modern');
  } catch (error) {
    if (!(error instanceof EraMismatchError)) throw error;
    client = await connect('legacy');
  }
  try {
    return await listAllTools(client, options.maxPages);
  } finally {
    await endUpstreamSession(client).catch(() => {});
    await client.close().catch(() => {});
  }
}
