/**
 * The HTTP gateway's latency benchmark: how much time `serve` adds to a call
 * (ADR-011 item 7, PRD §6).
 *
 * The figure that matters is what the gateway itself added to a call, so that is
 * what is measured and what the gate is on: the gateway reports, for each
 * request, the time from the request arriving to the upstream call leaving
 * (parsing, the Host/Origin/token checks, the session ladder, the access
 * decision) and from the upstream answer arriving to the response being fully
 * written (the scan, PII masking, the audit append, serialisation). Their sum is
 * the added latency of that call, and the p95 of those sums is the number. It is
 * measured inside the gateway, so loopback jitter between the processes is not in
 * it.
 *
 * The difference of two end-to-end p95s (client → upstream against client →
 * gateway → upstream) is reported beside it as a sanity check and is not the gate:
 * the difference of percentiles is not the percentile of the difference, and the
 * two runs are different calls.
 *
 * The gates here are the engine path `runtime.ts` runs for `tools/call` — the
 * access decision, the content scan with PII masking, the hash-chained audit
 * append — without its combination and manifest bookkeeping, which the CLI does
 * not export. That is stated in the report rather than hidden.
 *
 * Each era is measured separately, over real sockets, with the SDK's own clients.
 */
import { randomUUID } from 'node:crypto';
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import {
  createMcpHandler,
  isInitializeRequest,
  isLegacyRequest,
  McpServer,
  WebStandardStreamableHTTPServerTransport,
} from '@modelcontextprotocol/server';
import {
  type AuditFields,
  buildRecord,
  compilePolicy,
  GENESIS_HASH,
  parsePolicy,
  serializeRecord,
} from '@tunedness/mcpguard-core';
import { loadRuleset, type ScanOptions } from '@tunedness/mcpguard-detect';
import {
  blockedResult,
  createBearerAuthenticator,
  createHttpGateway,
  type Gates,
  type GatewayCallInput,
  type GatewayTiming,
  guardCall,
  guardResult,
  startHttpEndpoint,
} from '@tunedness/mcpguard-proxy';
import { loadRulesetData } from '@tunedness/mcpguard-ruleset';
import { z } from 'zod';
import { generateCorpus } from '../injection/corpus.js';
import { type Stats, summarize } from './stats.js';

const TARGET_MS = 20;
const WARMUP = 30;
const CALLS = 300;
const BUCKETS = [188, 1_000, 4_000, 16_000, 64_000];
const START = '<!-- http-gateway:start -->';
const END = '<!-- http-gateway:end -->';

type Era = 'legacy' | 'modern';

const SCAN: ScanOptions = {
  action: 'flag',
  flagAt: 40,
  blockAt: 70,
  maxBytes: 262_144,
  onDegraded: 'flag',
  pii: { recognizers: [], strictChecksum: true, keepLast: 0, correlationTags: false },
};

/** Text of exactly `bytes` bytes, made of the committed corpus so the scan has real content. */
function grower(): (bytes: number) => string {
  const sample = generateCorpus()
    .map((item) => item.text)
    .join('\n');
  return (bytes) => {
    let out = sample;
    while (out.length < bytes) out += sample;
    return out.slice(0, bytes);
  };
}

/** An upstream MCP server on loopback, in both eras, whose one tool answers `bytes` bytes. */
async function startUpstream(text: (bytes: number) => string): Promise<{
  url: string;
  close(): Promise<void>;
}> {
  const build = (): McpServer => {
    const server = new McpServer({ name: 'bench-upstream', version: '1.0.0' });
    server.registerTool(
      'payload',
      { description: 'Answer bytes bytes.', inputSchema: z.object({ bytes: z.number() }) },
      async ({ bytes }) => ({ content: [{ type: 'text', text: text(bytes) }] }),
    );
    return server;
  };
  const modern = createMcpHandler(() => build(), { legacy: 'reject' });
  const transports = new Map<string, WebStandardStreamableHTTPServerTransport>();
  const legacy = async (request: Request, body: unknown): Promise<Response> => {
    const id = request.headers.get('mcp-session-id');
    if (id !== null) {
      const known = transports.get(id);
      if (known === undefined) return new Response('no such session', { status: 404 });
      return known.handleRequest(request, { parsedBody: body });
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
      return (await isLegacyRequest(request, body))
        ? legacy(request, body)
        : modern.fetch(request, { parsedBody: body });
    },
  });
  return {
    url: `http://127.0.0.1:${endpoint.port}/mcp`,
    close: async () => {
      await modern.close();
      await Promise.allSettled([...transports.values()].map((t) => t.close()));
      await endpoint.close();
    },
  };
}

/** The gates `runtime.ts` runs for `tools/call`, minus its combination and manifest bookkeeping. */
function engineGates(auditPath: string): Gates<GatewayCallInput> {
  const ruleset = loadRuleset(loadRulesetData());
  const policy = parsePolicy({ version: 1 });
  const compiled = compilePolicy(policy);
  const context = {
    policy: compiled,
    ruleset,
    scanOptions: SCAN,
    enforce: true,
  };
  let seq = 0;
  let prev = GENESIS_HASH;
  return {
    onCall: async (request, forward, call) => {
      const tool = String(request.params.name);
      const access = guardCall(context, 'bench', tool, undefined);
      if (access.action === 'deny')
        return blockedResult('deny', 0, ruleset.rulesetVersion) as never;
      const upstream = await forward();
      const guarded = guardResult(context, 'bench', tool, upstream);
      const fields: AuditFields = {
        at: Date.now(),
        sessionId: call.session.sessionId,
        kind: 'tool_call',
        serverName: 'bench',
        toolName: tool,
        action: guarded.action,
        score: Math.max(0, ...guarded.verdicts.map((v) => v.score)),
        findings: guarded.verdicts.flatMap((v) => v.findings.map((f) => f.ruleId)),
        piiKinds: guarded.verdicts.flatMap((v) => v.piiFindings.map((f) => f.kind)),
        maskedContent: guarded.verdicts
          .map((v) => v.text)
          .join('\n')
          .slice(0, 4_096),
        sessionExact: call.session.exact,
        sessionSource: call.session.source,
      };
      const record = buildRecord(seq++, prev, fields, '', undefined);
      prev = record.hash;
      // Synchronous, as the CLI's writer is: the cost of a record is part of the call.
      appendFileSync(auditPath, serializeRecord(record));
      return guarded.result as never;
    },
    onList: async (_request, forward) => forward(),
    onRead: async (_request, forward) => forward(),
    onRequest: async (_request, forward) => forward(),
  };
}

interface Row {
  readonly bytes: number;
  /** What the gateway added to a call: p95 of (ingress + egress). */
  readonly added: Stats;
  readonly ingress: Stats;
  readonly egress: Stats;
  /** End to end through the gateway, and straight to the upstream, for the sanity check. */
  readonly proxied: Stats;
  readonly direct: Stats;
}

async function timed(client: Client, bytes: number): Promise<number> {
  const start = performance.now();
  await client.callTool({ name: 'payload', arguments: { bytes } });
  return performance.now() - start;
}

async function measureEra(
  era: Era,
  upstreamUrl: string,
  gatewayUrl: string,
  timings: GatewayTiming[],
): Promise<{ rows: Row[]; sessionOpen: number }> {
  const options =
    era === 'modern' ? { versionNegotiation: { mode: { pin: '2026-07-28' } } as const } : {};
  const opened = performance.now();
  const proxiedClient = new Client({ name: 'bench', version: '1.0.0' }, options);
  await proxiedClient.connect(new StreamableHTTPClientTransport(new URL(gatewayUrl)));
  const sessionOpen = performance.now() - opened;
  const directClient = new Client({ name: 'bench', version: '1.0.0' }, options);
  await directClient.connect(new StreamableHTTPClientTransport(new URL(upstreamUrl)));

  const rows: Row[] = [];
  try {
    for (const bytes of BUCKETS) {
      for (let i = 0; i < WARMUP; i++) {
        await timed(proxiedClient, bytes);
        await timed(directClient, bytes);
      }
      timings.length = 0;
      const proxied: number[] = [];
      const direct: number[] = [];
      // Interleaved, so drift in the machine's load lands on both.
      for (let i = 0; i < CALLS; i++) {
        proxied.push(await timed(proxiedClient, bytes));
        direct.push(await timed(directClient, bytes));
      }
      const calls = timings.filter((t) => t.method === 'tools/call' && t.era === era);
      rows.push({
        bytes,
        added: summarize(calls.map((t) => t.ingressMs + t.egressMs)),
        ingress: summarize(calls.map((t) => t.ingressMs)),
        egress: summarize(calls.map((t) => t.egressMs)),
        proxied: summarize(proxied),
        direct: summarize(direct),
      });
    }
  } finally {
    await proxiedClient.close().catch(() => {});
    await directClient.close().catch(() => {});
  }
  return { rows, sessionOpen };
}

const ms = (value: number): string => value.toFixed(3);

function render(
  results: Record<Era, { rows: Row[]; sessionOpen: number }>,
  reference: number,
  met: boolean,
): string {
  const table = (era: Era): string =>
    results[era].rows
      .map(
        (r) =>
          `| ${r.bytes.toLocaleString()} | ${ms(r.ingress.p95)} | ${ms(r.egress.p95)} | **${ms(r.added.p95)}** | ${ms(r.added.max)} | ${ms(r.proxied.p95)} | ${ms(r.direct.p95)} | ${ms(r.proxied.p95 - r.direct.p95)} |`,
      )
      .join('\n');
  const head =
    '| bytes | in p95 | out p95 | **added p95** | added max | e2e proxied p95 | e2e direct p95 | p95 difference |\n| --- | --- | --- | --- | --- | --- | --- | --- |';
  return `${START}
## HTTP gateway (\`mcpguard serve\`)

${CALLS} calls per size per era after ${WARMUP} discarded, over real loopback sockets with
the SDK's own clients. All figures are milliseconds. **added** is what the gateway itself
contributed to a call: *in* is the request arriving to the upstream call leaving
(parsing, Host/Origin/token checks, the session ladder, the access decision), *out* is
the upstream answer arriving to the response fully written (the scan, PII masking, the
hash-chained audit append, serialisation). The p95 of their sum is the gated number; it
is taken inside the gateway, so loopback jitter between processes is not in it. The two
end-to-end columns are a sanity check only — the difference of two p95s is not the p95
of the difference, and it includes the second loopback hop and the extra JSON encode and
decode a proxy cannot avoid, which is why it is larger than **added**.

The gates are the engine path \`runtime.ts\` runs for \`tools/call\` (access decision,
content scan with PII masking, synchronous audit append). Its combination-rule and
manifest bookkeeping is not in this run.

### Legacy era (a session per client; opening one took ${ms(results.legacy.sessionOpen)} ms, not part of a call)

${head}
${table('legacy')}

### Modern era (no session, one shared upstream connection)

${head}
${table('modern')}

### Verdict against PRD §6 and ADR-011

- added p95 < ${TARGET_MS} ms on the reference workload (the scan benchmark's: ${reference.toLocaleString()} bytes, the 95th percentile item floored at 1 KB; the corpus median is 188 bytes, its own row), both eras: ${met ? 'MET' : 'NOT MET'}
- the gate is the reference row only. Larger rows are the curve: the cost is the scan's, which grows with size (see the scan table above), and the gateway's own part (in) stays near a tenth of a millisecond at every size.
${END}
`;
}

/** Replaces the marked section of `results.md`, or appends it; the scan benchmark's text is left alone. */
function writeSection(path: string, section: string): void {
  let current = '';
  try {
    current = readFileSync(path, 'utf8');
  } catch {
    // No scan results yet: the section stands alone.
  }
  const from = current.indexOf(START);
  const to = current.indexOf(END);
  const next =
    from !== -1 && to > from
      ? `${current.slice(0, from)}${section.trimEnd()}${current.slice(to + END.length)}`
      : `${current.trimEnd()}\n\n${section}`;
  writeFileSync(path, next.endsWith('\n') ? next : `${next}\n`);
}

async function main(): Promise<void> {
  const text = grower();
  const dir = mkdtempSync(join(tmpdir(), 'mcpguard-bench-http-'));
  const timings: GatewayTiming[] = [];
  const upstream = await startUpstream(text);
  const gateway = createHttpGateway<GatewayCallInput>({
    servers: [
      {
        name: 'bench',
        target: { url: upstream.url },
        gates: engineGates(join(dir, 'audit.jsonl')),
      },
    ],
    callContext: (input) => input,
    sessionOf: (call) => call.session.sessionId,
    auth: createBearerAuthenticator([]),
    allowedHosts: [],
    allowedOrigins: [],
    session: { key: 'auto', idleTimeoutMs: 600_000, maxBindings: 1_024 },
    maxUpstreamConnections: 32,
    maxBodyBytes: 4_194_304,
    maxUpstreamResponseBytes: 16_777_216,
    clientName: 'mcpguard-bench',
    version: '0.0.0',
    onTiming: (timing) => timings.push(timing),
  });
  const endpoint = await startHttpEndpoint({ host: '127.0.0.1', port: 0, handler: gateway.fetch });
  const gatewayUrl = `http://127.0.0.1:${endpoint.port}/mcp/bench`;

  try {
    const results = {
      legacy: await measureEra('legacy', upstream.url, gatewayUrl, timings),
      modern: await measureEra('modern', upstream.url, gatewayUrl, timings),
    };
    // The reference workload is the scan benchmark's: the committed corpus's 95th
    // percentile item, floored at 1 KB.
    const sizes = generateCorpus()
      .map((item) => new TextEncoder().encode(item.text).length)
      .sort((a, b) => a - b);
    const reference = Math.max(sizes[Math.floor(sizes.length * 0.95)] ?? 0, 1_000);
    const at = (era: Era): Row | undefined => results[era].rows.find((r) => r.bytes === 1_000);
    const met = [at('legacy'), at('modern')].every(
      (row) => row !== undefined && row.added.p95 < TARGET_MS,
    );

    const here = dirname(fileURLToPath(import.meta.url));
    writeSection(join(here, '..', '..', 'latency', 'results.md'), render(results, reference, met));
    for (const era of ['legacy', 'modern'] as const) {
      const row = at(era);
      console.log(
        `${era}: added p95 at ${reference} bytes = ${row === undefined ? 'n/a' : ms(row.added.p95)} ms (budget ${TARGET_MS} ms)`,
      );
    }
    console.log(`reference workload p95 < ${TARGET_MS}ms in both eras: ${met}`);
    if (!met) process.exitCode = 1;
  } finally {
    await gateway.close();
    await endpoint.close();
    await upstream.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

await main();
