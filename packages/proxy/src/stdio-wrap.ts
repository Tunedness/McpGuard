/**
 * `wrap` mode: guard one stdio MCP server.
 *
 * Spawns the server command as a child, connects an upstream `Client` to it,
 * mirrors its identity and capabilities into the downstream `Server` the bridge
 * presents, and serves that on the current process's stdio. One child is one
 * connection is one session — the exact, heuristic-free identity the wrap story
 * is told through (ADR-006).
 *
 * The child's stderr passes through to the parent's untouched; its stdout is the
 * upstream JSON-RPC stream and never mixes with ours. The single hard rule of
 * this mode — nothing but protocol frames on our stdout — is why every
 * diagnostic goes to stderr.
 *
 * This module is the one engine-free file that touches the SDK's serving entry;
 * it takes the gates already built by the host and does not know what they do.
 */
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import type { Implementation, ServerCapabilities } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { type Bridge, createBridge, type Gates } from './bridge.js';

/** How `wrap` is configured. */
export interface WrapOptions {
  /** The server command and its arguments: `wrap -- node server.mjs`. */
  readonly command: string;
  readonly args: readonly string[];
  /** Environment for the child. Defaults to the parent's. */
  readonly env?: Record<string, string> | undefined;
  /** The proxy's own identity, presented to nobody the upstream does not. */
  readonly clientName: string;
  /** The guarded seams. */
  readonly gates: Gates;
  readonly onError?: ((error: Error) => void) | undefined;
}

/** A running wrap. */
export interface WrapHandle {
  readonly bridge: Bridge;
  close(): Promise<void>;
}

/**
 * Starts a wrapped server and serves the guard on stdio.
 *
 * The upstream is connected first, because the bridge mirrors its capabilities:
 * a downstream client should negotiate against the real server's capabilities,
 * which is more truthful than the proxy advertising its own.
 */
export async function wrapStdioServer(options: WrapOptions): Promise<WrapHandle> {
  const transport = new StdioClientTransport({
    command: options.command,
    args: [...options.args],
    // The child's stderr is inherited by the parent, byte for byte; only its
    // stdout — the protocol stream — is piped to the upstream client.
    stderr: 'inherit',
    ...(options.env !== undefined ? { env: options.env } : {}),
  });
  const client = new Client({ name: options.clientName, version: '0.0.0' });
  await client.connect(transport);

  const serverInfo = (client.getServerVersion() ?? {
    name: 'wrapped-server',
    version: '0.0.0',
  }) as Implementation;
  const capabilities = client.getServerCapabilities() as ServerCapabilities | undefined;
  const instructions = client.getInstructions();

  const bridge = createBridge({
    client,
    serverInfo,
    capabilities,
    instructions,
    gates: options.gates,
    ...(options.onError !== undefined ? { onError: options.onError } : {}),
  });

  await bridge.server.connect(new StdioServerTransport());

  return {
    bridge,
    close: () => bridge.close(),
  };
}
