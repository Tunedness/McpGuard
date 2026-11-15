/**
 * A `node:http` server that speaks the Fetch API to whatever it wraps.
 *
 * The SDK's HTTP entries are web-standard: they answer
 * `(Request) => Promise<Response>`. Node frameworks are expected to bridge that
 * with `@modelcontextprotocol/node`, which is not a dependency — it would pull
 * `hono` and `@hono/node-server` into a security proxy whose dependency tree
 * should stay short enough to audit (ADR-007, ADR-011). Node already ships
 * `Request`, `Response`, `Headers` and `ReadableStream`, so the bridge is this
 * file. It is adapted from AgentFuse's, which has been through the same review.
 *
 * What it does with the things that are easy to get wrong:
 * - **Bodies are bounded.** Over the limit is `413`, and the handler never runs;
 *   a `Content-Length` that already says so is refused before a byte is read.
 * - **Concurrency is bounded.** Past `maxInflight` a request is answered `503`
 *   with `Retry-After`, never queued.
 * - **Responses stream.** An SSE response never ends, so the body is pumped
 *   with backpressure rather than buffered.
 * - **A disconnect aborts the handler.** In the modern era closing the
 *   per-request stream is the cancellation signal.
 * - **A handler that throws still answers.** `500`, one diagnostic, no hung
 *   socket. A request line the `Request` constructor rejects is a `400`.
 * - **The peer's address comes from the socket.** `X-Forwarded-For` is not
 *   consulted: any caller could write it.
 *
 * This module imports neither engine package. See `boundary.test.ts`.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { GATEWAY_ERROR, jsonRpcError } from './http-response.js';

/** What the transport knows and a `Request` cannot carry. */
export interface RequestContext {
  /** The peer's address, straight off the socket. */
  readonly remoteAddress: string | undefined;
}

/** The handler shape, matching `createMcpHandler().fetch` plus the context. */
export type FetchHandler = (request: Request, context: RequestContext) => Promise<Response>;

/** How an endpoint behaves. */
export interface HttpEndpointOptions {
  readonly handler: FetchHandler;
  readonly host: string;
  /** `0` asks the OS for a free port, which is what tests use. */
  readonly port: number;
  readonly maxBodyBytes?: number | undefined;
  /** Requests served at once; beyond it, `503`. */
  readonly maxInflight?: number | undefined;
  /** Out-of-band error reporting. Never changes what goes on the wire. */
  readonly onError?: ((error: Error) => void) | undefined;
}

/** A listening endpoint. */
export interface HttpEndpoint {
  readonly port: number;
  readonly host: string;
  /** Stops listening and waits for the sockets to go. */
  close(): Promise<void>;
}

export const DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024;
export const DEFAULT_MAX_INFLIGHT = 256;

const BODILESS = new Set(['GET', 'HEAD']);

class BodyTooLarge extends Error {
  constructor(readonly limit: number) {
    super(`request body exceeds ${limit} bytes`);
    this.name = 'BodyTooLarge';
  }
}

async function readBody(request: IncomingMessage, limit: number): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = chunk as Buffer;
    total += buffer.length;
    if (total > limit) throw new BodyTooLarge(limit);
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

/** The headers off the wire, repeats kept (the parsed bag joins most and drops order). */
function headersOf(request: IncomingMessage): Headers {
  const headers = new Headers();
  const raw = request.rawHeaders;
  for (let index = 0; index + 1 < raw.length; index += 2) {
    headers.append(raw[index] as string, raw[index + 1] as string);
  }
  return headers;
}

function write(response: ServerResponse, chunk: Uint8Array): Promise<void> {
  return new Promise((resolve, reject) => {
    response.write(chunk, (error) => (error ? reject(error) : resolve()));
  });
}

/** Copies a Fetch `Response` onto a Node one. */
async function send(response: Response, node: ServerResponse): Promise<void> {
  const headers: Record<string, string | string[]> = {};
  response.headers.forEach((value, name) => {
    headers[name] = name === 'set-cookie' ? response.headers.getSetCookie() : value;
  });
  node.writeHead(response.status, headers);

  if (response.body === null) {
    node.end();
    return;
  }

  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (node.destroyed) {
        // The caller went away mid-stream; the producer is told, so a source that
        // would go on generating frames for nobody stops.
        await reader.cancel();
        break;
      }
      await write(node, value);
    }
  } finally {
    reader.releaseLock();
    node.end();
  }
}

async function sendResponse(node: ServerResponse, response: Response): Promise<void> {
  await send(response, node);
}

/** Starts an HTTP endpoint in front of a Fetch handler. */
export async function startHttpEndpoint(options: HttpEndpointOptions): Promise<HttpEndpoint> {
  const limit = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const maxInflight = options.maxInflight ?? DEFAULT_MAX_INFLIGHT;
  const report = (error: unknown): void => {
    options.onError?.(error instanceof Error ? error : new Error(String(error)));
  };
  let inflight = 0;

  const serveOne = async (node: IncomingMessage, response: ServerResponse): Promise<void> => {
    if (inflight >= maxInflight) {
      await sendResponse(
        response,
        jsonRpcError(
          503,
          GATEWAY_ERROR.refused,
          'Service busy: too many requests in flight',
          { reason: 'overloaded' },
          { 'retry-after': '1' },
        ),
      );
      return;
    }
    inflight += 1;
    response.once('close', () => {
      inflight -= 1;
    });

    // Fired when the peer goes away before the response finished.
    const aborted = new AbortController();
    response.on('close', () => {
      if (!response.writableFinished) aborted.abort();
    });

    const method = node.method as string;
    const target = node.url as string;
    // An origin-form target only: an absolute-form or `*` target is never what an
    // MCP client sends, and gluing it behind the authority builds a URL the
    // client did not name.
    if (!target.startsWith('/')) {
      await sendResponse(
        response,
        jsonRpcError(400, GATEWAY_ERROR.invalidRequest, 'Bad request target'),
      );
      return;
    }

    const declared = Number(node.headers['content-length']);
    if (Number.isFinite(declared) && declared > limit) {
      await sendResponse(
        response,
        new Response(`request body exceeds ${limit} bytes\n`, {
          status: 413,
          headers: { 'content-type': 'text/plain; charset=utf-8', connection: 'close' },
        }),
      );
      return;
    }

    let body: Uint8Array | undefined;
    if (!BODILESS.has(method)) {
      try {
        body = await readBody(node, limit);
      } catch (error) {
        if (error instanceof BodyTooLarge) {
          await sendResponse(
            response,
            new Response(`${error.message}\n`, {
              status: 413,
              headers: { 'content-type': 'text/plain; charset=utf-8', connection: 'close' },
            }),
          );
          return;
        }
        report(error);
        await sendResponse(
          response,
          jsonRpcError(400, GATEWAY_ERROR.invalidRequest, 'Could not read the request body'),
        );
        return;
      }
    }

    let request: Request;
    try {
      const authority = node.headers.host ?? `${options.host}:${options.port}`;
      request = new Request(`http://${authority}${target}`, {
        method,
        headers: headersOf(node),
        signal: aborted.signal,
        ...(body !== undefined && body.byteLength > 0 ? { body } : undefined),
      });
    } catch {
      // A `Host` or a method the Fetch constructor will not take.
      await sendResponse(
        response,
        jsonRpcError(400, GATEWAY_ERROR.invalidRequest, 'Malformed request'),
      );
      return;
    }

    try {
      const answer = await options.handler(request, { remoteAddress: node.socket.remoteAddress });
      await send(answer, response);
    } catch (error) {
      report(error);
      if (!response.headersSent) {
        await sendResponse(
          response,
          jsonRpcError(500, GATEWAY_ERROR.internal, 'The gateway failed to handle the request'),
        ).catch(report);
      } else {
        response.end();
      }
    }
  };

  const server: Server = createServer((node, response) => {
    serveOne(node, response).catch((error) => {
      report(error);
      if (!response.headersSent) response.writeHead(500);
      response.end();
    });
  });
  server.on('error', report);
  server.on('clientError', (_error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port, options.host, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  const bound = server.address() as AddressInfo;

  return {
    port: bound.port,
    host: bound.address,
    close: () =>
      new Promise<void>((resolve) => {
        // `closeAllConnections`: a keep-alive socket nobody is using would
        // otherwise hold the process open.
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
