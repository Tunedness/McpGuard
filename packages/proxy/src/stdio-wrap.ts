/**
 * `wrap` mode: guard one stdio MCP server.
 *
 * Spawns the server command as a child, connects an upstream `Client` to it,
 * mirrors its identity and capabilities into the downstream `Server` the bridge
 * presents, and serves that on the current process's stdio. One child is one
 * connection is one session — the exact, heuristic-free identity the wrap story
 * is told through (ADR-006).
 *
 * The downstream is served through `serveStdio`, which owns the era decision
 * (ADR-002): the client's opening message picks legacy or modern, and this
 * module builds the whole bridge — upstream child included — for that era, in
 * the factory `serveStdio` calls. The upstream is connected in the same era and
 * a disagreement is an error, never a translation.
 *
 * The child's stderr passes through to the parent's untouched; its stdout is the
 * upstream JSON-RPC stream and never mixes with ours. The single hard rule of
 * this mode — nothing but protocol frames on our stdout — is why every
 * diagnostic goes to stderr.
 *
 * This module is the one engine-free file that touches the SDK's serving entry;
 * it takes the gates already built by the host and does not know what they do.
 */
import { accessSync, constants, statSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { Client, UnsupportedProtocolVersionError } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import {
  CLIENT_CAPABILITIES_META_KEY,
  type ClientCapabilities,
  type Implementation,
  isJSONRPCRequest,
  type JSONRPCMessage,
  type MessageExtraInfo,
  ProtocolError,
  ProtocolErrorCode,
  Server,
  type ServerCapabilities,
  type Transport,
  type TransportSendOptions,
} from '@modelcontextprotocol/server';
import { StdioServerTransport, serveStdio } from '@modelcontextprotocol/server/stdio';
import { type Bridge, createBridge, type Gates } from './bridge.js';
import { assertSameEra, type Era, EraMismatchError, eraOf } from './era.js';
import { PROXY_VERSION } from './version.js';

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
  /** Where the downstream is served. Defaults to this process's stdio. */
  readonly transport?: Transport | undefined;
}

/** A running wrap. */
export interface WrapHandle {
  /**
   * The bridge serving the connection right now, or `undefined` before the
   * client has opened one. It is not fixed at start: the era, and with it the
   * bridge, is chosen by the client's first message.
   */
  current(): Bridge | undefined;
  /** Settles when the downstream connection has ended. */
  readonly closed: Promise<void>;
  close(): Promise<void>;
}

/**
 * Watches the downstream wire without touching it.
 *
 * A legacy client's `initialize` carries the capabilities it declares, and the
 * server it talks to has to answer that `initialize` with the capabilities of
 * the real upstream. The upstream, in turn, can only be connected once it knows
 * what the client declared, or it tells its server the client has no roots, no
 * sampling and no elicitation. The two meet at the opening message: `serveStdio`
 * builds the bridge only after that message has arrived, and this transport has
 * seen it first. Every frame is passed on as it came; nothing is written,
 * altered or invented. `serveStdio` documents `transport` as the seam for
 * exactly this kind of wire.
 */
class OpeningObserver implements Transport {
  onclose?: (() => void) | undefined;
  onerror?: ((error: Error) => void) | undefined;
  setProtocolVersion?: ((version: string) => void) | undefined;
  setSupportedProtocolVersions?: ((versions: string[]) => void) | undefined;
  onmessage?:
    | (<T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => void)
    | undefined;

  /** What the most recent legacy `initialize` declared. */
  legacyCapabilities: ClientCapabilities | undefined;
  /** What the most recent request carrying a modern envelope declared. */
  modernCapabilities: ClientCapabilities | undefined;
  readonly closed: Promise<void>;
  private resolveClosed: () => void = () => {};

  constructor(private readonly inner: Transport) {
    this.closed = new Promise((resolve) => {
      this.resolveClosed = resolve;
    });
    // Optional hooks the serving entry calls on its wire, handed on only when the
    // wire has them, so wrapping it changes nothing it would have done.
    if (inner.setProtocolVersion !== undefined) {
      this.setProtocolVersion = (version) => inner.setProtocolVersion?.(version);
    }
    if (inner.setSupportedProtocolVersions !== undefined) {
      this.setSupportedProtocolVersions = (versions) =>
        inner.setSupportedProtocolVersions?.(versions);
    }
    inner.onmessage = (message, extra) => {
      this.observe(message);
      this.onmessage?.(message, extra);
    };
    inner.onerror = (error) => this.onerror?.(error);
    inner.onclose = () => {
      this.resolveClosed();
      this.onclose?.();
    };
  }

  start(): Promise<void> {
    return this.inner.start();
  }

  send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    return this.inner.send(message, options);
  }

  async close(): Promise<void> {
    try {
      await this.inner.close();
    } finally {
      this.resolveClosed();
    }
  }

  private observe(message: JSONRPCMessage): void {
    if (!isJSONRPCRequest(message)) return;
    const params = message.params as Record<string, unknown> | undefined;
    if (message.method === 'initialize') {
      this.legacyCapabilities = capabilitiesOf(params?.capabilities);
      return;
    }
    const meta = params?._meta as Record<string, unknown> | undefined;
    const declared = capabilitiesOf(meta?.[CLIENT_CAPABILITIES_META_KEY]);
    if (declared !== undefined) this.modernCapabilities = declared;
  }
}

/** A capabilities object off the wire, or nothing: the wire is not trusted to have the shape. */
function capabilitiesOf(value: unknown): ClientCapabilities | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as ClientCapabilities)
    : undefined;
}

/**
 * A `Server` that answers every request with one error, for a connection that
 * cannot be served. The error reaches the client as the reply to its opening
 * request, where a thrown factory would reach it as a bare "Internal server
 * error" and keep the reason on stderr.
 */
function refusingServer(reason: Error): Server {
  const server = new Server({ name: 'mcpguard', version: PROXY_VERSION }, { capabilities: {} });
  const refuse = async (): Promise<never> => {
    throw new ProtocolError(ProtocolErrorCode.InternalError, reason.message);
  };
  server.setRequestHandler('initialize', refuse);
  server.fallbackRequestHandler = refuse;
  return server;
}

/**
 * Throws when `command` names nothing that can be run.
 *
 * Nothing is spawned until the client's first message names an era, so a
 * mistyped command would otherwise surface only as a failed `initialize` to a
 * client that cannot read stderr. This looks the command up the way a shell
 * does, without running it.
 */
function assertRunnable(command: string, env: Record<string, string | undefined>): void {
  const windows = process.platform === 'win32';
  const extensions = windows ? (env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';') : [''];
  const names =
    command.includes('/') || (windows && command.includes('\\'))
      ? [command]
      : (env.PATH ?? '').split(delimiter).map((dir) => join(dir === '' ? '.' : dir, command));
  for (const name of names) {
    for (const extension of extensions) {
      try {
        accessSync(name + extension, constants.X_OK);
        if (statSync(name + extension).isFile()) return;
      } catch {
        // Not here; try the next candidate.
      }
    }
  }
  throw new Error(`cannot start the server: "${command}" was not found or is not executable`);
}

/**
 * Starts a wrapped server and serves the guard on stdio.
 *
 * Nothing is spawned until the client's first message names an era. The
 * upstream is connected before the downstream answers, because the bridge
 * mirrors its capabilities: a downstream client should negotiate against the
 * real server's capabilities, which is more truthful than the proxy advertising
 * its own.
 */
export async function wrapStdioServer(options: WrapOptions): Promise<WrapHandle> {
  assertRunnable(options.command, options.env ?? process.env);
  // An error can reach `report` twice (once here, once through `serveStdio`'s
  // own `onerror`); stderr should carry it once.
  const reported = new WeakSet<Error>();
  const report = (error: unknown): void => {
    const failure = error instanceof Error ? error : new Error(String(error));
    if (reported.has(failure)) return;
    reported.add(failure);
    options.onError?.(failure);
  };
  const observer = new OpeningObserver(options.transport ?? new StdioServerTransport());
  let live: Bridge | undefined;

  /** Connects the upstream child in `era` and builds the bridge over it. */
  const open = async (era: Era): Promise<Bridge> => {
    const transport = new StdioClientTransport({
      command: options.command,
      args: [...options.args],
      // The child's stderr is inherited by the parent, byte for byte; only its
      // stdout — the protocol stream — is piped to the upstream client.
      stderr: 'inherit',
      ...(options.env !== undefined ? { env: options.env } : {}),
    });
    const declared = era === 'modern' ? observer.modernCapabilities : observer.legacyCapabilities;
    const client = new Client(
      { name: options.clientName, version: '0.0.0' },
      {
        // What the downstream client declared is what the upstream server is
        // told. A server that checks before it asks sees a client that can
        // answer, or one that cannot, exactly as the real client is.
        ...(declared !== undefined ? { capabilities: declared } : {}),
        // `auto` so a legacy-only upstream is found out, not assumed away: the
        // era it lands in is compared with the downstream's below.
        ...(era === 'modern' ? { versionNegotiation: { mode: 'auto' as const } } : {}),
      },
    );
    try {
      await client.connect(transport);
      assertSameEra(era, client.getProtocolEra() ?? 'legacy');
    } catch (error) {
      await client.close().catch(() => {});
      // A server that answers a legacy opening with the modern revisions it
      // does serve is a different era, not a broken server: say so.
      if (era === 'legacy' && error instanceof UnsupportedProtocolVersionError) {
        const supported = (error.data as { supported?: readonly string[] } | undefined)?.supported;
        if (supported?.length && supported.every((version) => eraOf(version) === 'modern')) {
          throw new EraMismatchError('legacy', 'modern');
        }
      }
      throw error;
    }

    const serverInfo = (client.getServerVersion() ?? {
      name: 'wrapped-server',
      version: '0.0.0',
    }) as Implementation;
    const bridge = createBridge({
      client,
      serverInfo,
      capabilities: client.getServerCapabilities() as ServerCapabilities | undefined,
      instructions: client.getInstructions(),
      gates: options.gates,
      ...(options.onError !== undefined ? { onError: options.onError } : {}),
    });
    // The upstream lives exactly as long as the downstream instance does,
    // including an instance `serveStdio` builds to answer a `server/discover`
    // probe and discards when the client falls back to `initialize`.
    bridge.server.onclose = () => {
      if (live === bridge) live = undefined;
      client.close().catch(report);
    };
    return bridge;
  };

  const connection = serveStdio(
    async ({ era }) => {
      try {
        const bridge = await open(era);
        live = bridge;
        return bridge.server;
      } catch (error) {
        // A modern opening is `server/discover`, which `serveStdio` answers
        // itself and never lets a refusing instance answer, so for that era the
        // failure is thrown: the client's connect fails, and the reason goes to
        // stderr through `onerror`. A legacy opening is `initialize`, which the
        // refusing instance does answer, with the reason in the reply.
        report(error);
        if (era === 'modern') throw error;
        return refusingServer(error instanceof Error ? error : new Error(String(error)));
      }
    },
    { transport: observer, onerror: report },
  );

  return {
    current: () => live,
    closed: observer.closed,
    close: async () => {
      await connection.close();
      await live?.close();
    },
  };
}
