/**
 * Reaching an upstream server: one connected `Client`, in one era.
 *
 * Two shapes of upstream are served (ADR-011): a streamable HTTP endpoint and a
 * command that speaks stdio. Either is connected in the era the downstream
 * speaks and a disagreement is an error, never a translation (ADR-002). A
 * legacy downstream session owns the `Client` this builds; the modern leg shares
 * one per server through {@link SharedUpstream}, because the modern protocol has
 * no session and no server-to-client request channel, so there is nothing a
 * second caller could be confused with.
 *
 * Two limits live here because they are properties of the connection: an HTTP
 * upstream's response is read through a counting `fetch` that refuses to buffer
 * more than `maxResponseBytes`, and a connection that fails is not retried in a
 * loop — {@link SharedUpstream} backs off.
 *
 * This module imports neither engine package. See `boundary.test.ts`.
 */
import {
  Client,
  type ClientCapabilities,
  type FetchLike,
  SdkHttpError,
  StreamableHTTPClientTransport,
  UnsupportedProtocolVersionError,
} from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { assertSameEra, type Era, EraMismatchError, eraOf } from './era.js';

/** Where an upstream is reached. */
export type UpstreamTarget =
  | { readonly url: string }
  | {
      readonly command: string;
      readonly args: readonly string[];
      readonly env?: Record<string, string> | undefined;
    };

/** How an upstream connection is made. */
export interface ConnectOptions {
  readonly target: UpstreamTarget;
  readonly era: Era;
  /** What the downstream declared; the upstream server is told the same. */
  readonly capabilities?: ClientCapabilities | undefined;
  /** The proxy's own name, presented to the upstream as `clientInfo`. */
  readonly clientName: string;
  readonly maxResponseBytes?: number | undefined;
}

/** Raised when an upstream HTTP response outgrows `maxResponseBytes`. */
export class UpstreamResponseTooLarge extends Error {
  constructor(readonly limit: number) {
    super(`the upstream response exceeds ${limit} bytes`);
    this.name = 'UpstreamResponseTooLarge';
  }
}

/**
 * A `fetch` that refuses to read more than `limit` bytes of a response.
 *
 * The scanner samples content above `scan.max_bytes`, but memory is a separate
 * limit: a hostile upstream could otherwise stream an unbounded body into the
 * process. The standalone `GET` stream is exempt — it is open-ended by design
 * and a byte total over its lifetime would cut a healthy connection off.
 */
export function limitedFetch(limit: number, inner: FetchLike = fetch): FetchLike {
  return async (url, init) => {
    const response = await inner(url, init);
    if ((init?.method ?? 'GET').toUpperCase() === 'GET' || response.body === null) return response;
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > limit) {
      await response.body.cancel().catch(() => {});
      throw new UpstreamResponseTooLarge(limit);
    }
    let seen = 0;
    const counted = response.body.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          seen += chunk.byteLength;
          if (seen > limit) controller.error(new UpstreamResponseTooLarge(limit));
          else controller.enqueue(chunk);
        },
      }),
    );
    return new Response(counted, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  };
}

/**
 * The revisions an upstream named when it refused a protocol version, if it did.
 *
 * Over stdio that arrives as the JSON-RPC error itself; over HTTP the server
 * answers `400` and the SDK reports the body as text inside an HTTP error.
 */
function supportedRevisionsOf(error: unknown): readonly string[] | undefined {
  if (error instanceof UnsupportedProtocolVersionError) {
    return (error.data as { supported?: readonly string[] } | undefined)?.supported;
  }
  if (error instanceof SdkHttpError && error.status === 400) {
    try {
      const body = JSON.parse(String(error.data.text ?? '')) as {
        error?: { code?: number; data?: { supported?: unknown } };
      };
      const supported = body.error?.data?.supported;
      if (body.error?.code === -32022 && Array.isArray(supported)) {
        return supported.filter((version): version is string => typeof version === 'string');
      }
    } catch {
      // Not JSON: an ordinary 400.
    }
  }
  return undefined;
}

/** Connects an upstream `Client` in `options.era`, or throws. */
export async function connectUpstream(options: ConnectOptions): Promise<Client> {
  const { target, era } = options;
  const transport =
    'url' in target
      ? new StreamableHTTPClientTransport(new URL(target.url), {
          ...(options.maxResponseBytes !== undefined
            ? { fetch: limitedFetch(options.maxResponseBytes) }
            : {}),
        })
      : new StdioClientTransport({
          command: target.command,
          args: [...target.args],
          // The child's stderr is the parent's, byte for byte; only its stdout —
          // the protocol stream — is piped to the client.
          stderr: 'inherit',
          ...(target.env !== undefined ? { env: target.env } : {}),
        });
  const client = new Client(
    { name: options.clientName, version: '0.0.0' },
    {
      // What the downstream declared is what the upstream server is told: a
      // server that checks before it asks sees a client that can answer, or one
      // that cannot, exactly as the real one is.
      ...(options.capabilities !== undefined ? { capabilities: options.capabilities } : {}),
      // `auto`, so a legacy-only upstream is found out rather than assumed away.
      ...(era === 'modern' ? { versionNegotiation: { mode: 'auto' as const } } : {}),
    },
  );
  try {
    await client.connect(transport);
    assertSameEra(era, client.getProtocolEra() ?? 'legacy');
  } catch (error) {
    await client.close().catch(() => {});
    // A server that answers a legacy opening with the modern revisions it does
    // serve is a different era, not a broken server: say so.
    if (era === 'legacy') {
      const supported = supportedRevisionsOf(error);
      if (supported?.length && supported.every((version) => eraOf(version) === 'modern')) {
        throw new EraMismatchError('legacy', 'modern');
      }
    }
    throw error;
  }
  return client;
}

/**
 * Ends the upstream session of a legacy connection, if it has one.
 *
 * `Client.close()` drops the connection; it does not tell an HTTP server the
 * session is over, so a gateway that only closed the client would leave a
 * session behind on the upstream for every one of its own that ended. The DELETE
 * is best effort and bounded: an upstream that does not answer must not hold the
 * gateway's own teardown.
 */
export async function endUpstreamSession(client: Client, timeoutMs = 2_000): Promise<void> {
  const transport = client.transport;
  if (!(transport instanceof StreamableHTTPClientTransport)) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      transport.terminateSession(),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, timeoutMs);
        timer.unref();
      }),
    ]);
  } catch {
    // Already gone, or refusing: nothing more to do about it.
  } finally {
    clearTimeout(timer);
  }
}

/** How a shared upstream is built. */
export interface SharedUpstreamOptions {
  readonly connect: () => Promise<Client>;
  readonly clock: () => number;
  /** The first back-off after a failed connect, doubled on each failure up to the cap. */
  readonly backoffMs?: number | undefined;
  readonly maxBackoffMs?: number | undefined;
  readonly onError?: ((error: Error) => void) | undefined;
  /** Called once a connection is up. */
  readonly onConnected?: ((client: Client) => void) | undefined;
  /** Called when an established connection drops. */
  readonly onLost?: (() => void) | undefined;
}

/**
 * One connected `Client` shared by every modern request of a server.
 *
 * Connected on first use, by one attempt however many requests ask at once. A
 * failed connect is remembered: until the back-off has passed, the next
 * requests get the same failure at once, so a dead upstream is not hammered by
 * every request that arrives, and for a stdio upstream a crash loop is not a
 * spawn per request. When the connection later drops, the next request
 * reconnects.
 */
export class SharedUpstream {
  readonly #options: SharedUpstreamOptions;
  #client: Client | undefined;
  #connecting: Promise<Client> | undefined;
  #failure: { readonly error: Error; readonly retryAt: number } | undefined;
  #failures = 0;
  #closed = false;

  constructor(options: SharedUpstreamOptions) {
    this.#options = options;
  }

  /** The connected client now, without connecting one. */
  current(): Client | undefined {
    return this.#client;
  }

  /** The connected client, connecting it first when nothing is. */
  async get(): Promise<Client> {
    if (this.#closed) throw new Error('the gateway is shutting down');
    if (this.#client !== undefined) return this.#client;
    if (this.#connecting !== undefined) return this.#connecting;
    if (this.#failure !== undefined && this.#options.clock() < this.#failure.retryAt) {
      throw this.#failure.error;
    }
    const attempt = this.#options
      .connect()
      .then((client) => {
        if (this.#closed) {
          client.close().catch(() => {});
          throw new Error('the gateway is shutting down');
        }
        this.#client = client;
        this.#failure = undefined;
        this.#failures = 0;
        client.onclose = () => {
          if (this.#client !== client) return;
          this.#client = undefined;
          this.#options.onLost?.();
        };
        this.#options.onConnected?.(client);
        return client;
      })
      .catch((error: unknown) => {
        const failure = error instanceof Error ? error : new Error(String(error));
        const base = this.#options.backoffMs ?? 500;
        const cap = this.#options.maxBackoffMs ?? 30_000;
        this.#failures += 1;
        this.#failure = {
          error: failure,
          retryAt: this.#options.clock() + Math.min(cap, base * 2 ** (this.#failures - 1)),
        };
        throw failure;
      })
      .finally(() => {
        this.#connecting = undefined;
      });
    this.#connecting = attempt;
    return attempt;
  }

  /** Closes the connection and refuses further use. */
  async close(): Promise<void> {
    this.#closed = true;
    const client = this.#client;
    this.#client = undefined;
    await client?.close().catch((error: unknown) => {
      this.#options.onError?.(error instanceof Error ? error : new Error(String(error)));
    });
  }
}
