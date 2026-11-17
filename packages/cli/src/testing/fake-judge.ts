/**
 * A stand-in for a local model server, for the judge's tests.
 *
 * A real HTTP server on a loopback port, so the adapter is exercised through the
 * real `fetch`, the real abort signal and a real socket. What the "model" says is
 * the test's to decide, and every request it received is kept for inspection.
 */
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

/** One request the fake received, parsed. */
export interface FakeRequest {
  readonly headers: IncomingHttpHeaders;
  readonly body: {
    readonly model: string;
    readonly messages: ReadonlyArray<{ role: string; content: string }>;
    readonly temperature: number;
    readonly max_tokens: number;
    readonly response_format: unknown;
    readonly stream: boolean;
  };
}

/** What the fake does with a request. */
export type FakeReply =
  /** A well-formed verdict. */
  | { readonly label: 'injection' | 'benign'; readonly confidence: number; readonly model?: string }
  /** This exact string as the model's message content. */
  | { readonly content: string }
  /** This exact string as the whole HTTP body. */
  | { readonly rawBody: string }
  | { readonly status: number }
  /** Waits, then answers with the reply inside. */
  | { readonly delayMs: number; readonly then: FakeReply }
  /** Never answers. */
  | { readonly hang: true }
  /** Redirects to another URL. */
  | { readonly redirectTo: string };

/** A running fake. */
export interface FakeJudge {
  readonly url: string;
  readonly requests: FakeRequest[];
  close(): Promise<void>;
}

/** Starts a fake that answers each request with `reply(request, index)`. */
export async function startFakeJudge(
  reply: (request: FakeRequest, index: number) => FakeReply,
): Promise<FakeJudge> {
  const requests: FakeRequest[] = [];
  const sockets = new Set<import('node:net').Socket>();
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as FakeRequest['body'];
      const request: FakeRequest = { headers: req.headers, body: parsed };
      requests.push(request);
      respond(reply(request, requests.length - 1));
    });

    function respond(answer: FakeReply): void {
      if ('hang' in answer) return;
      if ('delayMs' in answer) {
        setTimeout(() => respond(answer.then), answer.delayMs);
        return;
      }
      if ('redirectTo' in answer) {
        res.writeHead(302, { location: answer.redirectTo }).end();
        return;
      }
      if ('status' in answer) {
        res.writeHead(answer.status, { 'content-type': 'application/json' }).end('{}');
        return;
      }
      if ('rawBody' in answer) {
        res.writeHead(200, { 'content-type': 'application/json' }).end(answer.rawBody);
        return;
      }
      const content =
        'content' in answer
          ? answer.content
          : JSON.stringify({ label: answer.label, confidence: answer.confidence });
      const model = 'label' in answer ? answer.model : undefined;
      res.writeHead(200, { 'content-type': 'application/json' }).end(
        JSON.stringify({
          ...(model !== undefined ? { model } : {}),
          choices: [{ message: { role: 'assistant', content } }],
        }),
      );
    }
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/v1/chat/completions`,
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}
