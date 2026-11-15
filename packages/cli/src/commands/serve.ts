/**
 * `mcpguard serve`: the guarded HTTP gateway in front of one upstream (ADR-011).
 *
 * `wrap`, with an HTTP front door. The three gates are the ones `wrap` runs —
 * `buildGates` is called here exactly as it is there — and what differs is what
 * a pipe never needs: the session of each call is resolved by the ADR-006
 * ladder and written into the `_meta` that goes upstream, the caller is
 * identified by a bearer token when the policy defines any, and Host, Origin,
 * body size and concurrency are bounded before a request reaches any of it.
 *
 * This command loads the policy and the ruleset, refuses to start on a
 * configuration that would expose the gateway unprotected, builds the gates,
 * opens the audit writer, and hands the lot to the proxy. Everything it writes
 * goes to stderr; nothing here writes to stdout.
 *
 * It speaks plain HTTP. TLS is terminated in front of it, or the bind stays on
 * loopback, and the start-up line says which.
 */
import {
  type CompiledPolicy,
  compilePolicy,
  escapeUnsafeJson,
  type IdentityResolution,
} from '@tunedness/mcpguard-core';
import {
  assertRunnable,
  createBearerAuthenticator,
  createHttpGateway,
  type GatewayCallInput,
  isSupportedSessionKey,
  PROXY_VERSION,
  startHttpEndpoint,
  type UpstreamTarget,
} from '@tunedness/mcpguard-proxy';
import { AuditWriter } from '../audit-writer.js';
import { loadPolicy, resolveAgainst } from '../config.js';
import { CliError, EXIT, messageOf } from '../errors.js';
import { type CliContext, writeLines } from '../io.js';
import { fileLockStore } from '../lock-file.js';
import { assertPolicyRunnable, readKey } from '../preflight.js';
import { loadShippedRuleset } from '../ruleset.js';
import { buildGates, type CallContext, resolveIdentity } from '../runtime.js';
import { NULL_TELEMETRY, OtlpTelemetrySink } from '../telemetry/sink.js';
import { parseServeArgs } from './serve-args.js';
import { headersFrom, otlpPoster } from './wrap.js';

/** The default bind address: loopback, and nothing else unless asked. */
export const DEFAULT_HOST = '127.0.0.1';
/** One above AgentFuse's 8765, so the two can run on one machine without flags. */
export const DEFAULT_PORT = 8766;

/** Flags `serve` accepts before the `--`. */
export function serveHelp(): string[] {
  return [
    'Usage: mcpguard serve [options] --upstream <url>',
    '       mcpguard serve [options] -- <server-command> [server-args...]',
    '',
    'Guards one MCP server behind an HTTP endpoint at /mcp/<name>.',
    '',
    'Options:',
    '  --policy <path>    Policy file (default: search up from cwd)',
    '  --name <name>      Name the server goes by in the path, rules and the log (default: server)',
    '  --upstream <url>   A streamable HTTP MCP server to guard',
    `  --host <address>   Address to bind (default: ${DEFAULT_HOST}); anything but loopback needs`,
    '                     auth.tokens and http.allowed_hosts in the policy',
    `  --port <port>      Port to bind (default: ${DEFAULT_PORT}; 0 picks a free one)`,
    '  --help             Show this help',
    '',
    'Plain HTTP only: terminate TLS in front of it, or keep it on loopback.',
  ];
}

/** Whether `host` binds loopback only. A name other than `localhost` may resolve anywhere. */
export function isLoopbackHost(host: string): boolean {
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  return bare === 'localhost' || bare === '::1' || /^127(\.\d{1,3}){3}$/.test(bare);
}

/** Resolves the upstream the command line names. */
function upstreamOf(
  parsed: ReturnType<typeof parseServeArgs>,
  env: CliContext['env'],
): UpstreamTarget {
  if (parsed.command !== undefined && parsed.upstream !== undefined) {
    throw new CliError('serve takes --upstream or a command after `--`, not both');
  }
  if (parsed.upstream !== undefined) {
    if (parsed.upstream === '') throw new CliError('--upstream needs a URL');
    let url: URL;
    try {
      url = new URL(parsed.upstream);
    } catch {
      throw new CliError(`--upstream is not a URL: ${parsed.upstream}`);
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new CliError('--upstream must be an http: or https: URL');
    }
    return { url: url.toString() };
  }
  if (parsed.command !== undefined) {
    try {
      assertRunnable(parsed.command, env);
    } catch (error) {
      throw new CliError(messageOf(error), { exitCode: EXIT.usage });
    }
    return { command: parsed.command, args: parsed.args };
  }
  throw new CliError('serve needs an upstream: --upstream <url>, or a command after `--`', {
    hints: [
      'example: mcpguard serve --name echo -- node server.mjs',
      'example: mcpguard serve --name docs --upstream https://mcp.example.com/mcp',
    ],
  });
}

/** Runs the serve command. */
export async function runServe(context: CliContext, argv: readonly string[]): Promise<number> {
  const parsed = parseServeArgs(argv);
  if (parsed.help) {
    writeLines(context.stdout, serveHelp());
    return EXIT.ok;
  }
  if (parsed.unknown.length > 0) {
    throw new CliError(`serve does not know ${parsed.unknown.map((a) => `"${a}"`).join(', ')}`, {
      hints: ['run `mcpguard serve --help`'],
    });
  }
  for (const [flag, value] of [
    ['--policy', parsed.policy],
    ['--name', parsed.name],
    ['--host', parsed.host],
    ['--port', parsed.port],
  ] as const) {
    if (value === '') throw new CliError(`${flag} needs a value`);
  }

  const host = parsed.host ?? DEFAULT_HOST;
  const port = parsed.port === undefined ? DEFAULT_PORT : Number(parsed.port);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new CliError(`--port is not a port number: ${parsed.port}`);
  }
  const serverName = parsed.name ?? 'server';
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(serverName)) {
    throw new CliError(`--name "${serverName}" cannot be used in a URL path`, {
      hints: ['use letters, digits, `.`, `_` and `-`, up to 64 characters'],
    });
  }
  const target = upstreamOf(parsed, context.env);

  const loaded = loadPolicy(context.cwd, context.env, parsed.policy);
  assertPolicyRunnable(loaded.policy, context.env);
  const policy = loaded.policy;

  if (policy.servers[serverName]?.upstream !== undefined) {
    // One name, one definition: a silent precedence rule between the command line
    // and the policy would let either quietly override the other.
    throw new CliError(
      `"${serverName}" is given an upstream both here and in the policy (servers.${serverName}.upstream)`,
      { exitCode: EXIT.policy, hints: ['define it in one place, or use another --name'] },
    );
  }
  if (!isSupportedSessionKey(policy.session.key)) {
    throw new CliError(`session.key "${policy.session.key}" is not supported`, {
      exitCode: EXIT.policy,
      hints: ['use auto, traceparent, baggage:<name> or connection'],
    });
  }
  const loopback = isLoopbackHost(host);
  if (!loopback) {
    // Reachable from the network: without a token anyone who can reach the port
    // is the caller, and without a host allowlist the Host check protects nothing.
    const missing = [
      ...(policy.auth.tokens.length === 0 ? ['auth.tokens'] : []),
      ...(policy.http.allowed_hosts.length === 0 ? ['http.allowed_hosts'] : []),
    ];
    if (missing.length > 0) {
      throw new CliError(
        `refusing to bind ${host}: the policy does not set ${missing.join(' and ')}`,
        {
          exitCode: EXIT.policy,
          hints: [
            'a gateway reachable beyond this machine needs a bearer token and the hostnames it answers to',
            `or keep it on loopback: --host ${DEFAULT_HOST}`,
          ],
        },
      );
    }
  }

  const ruleset = loadShippedRuleset();
  const compiled: CompiledPolicy = compilePolicy(policy);
  const out = (event: string, detail: Record<string, unknown>): void => {
    context.stderr.write(`[mcpguard] ${escapeUnsafeJson(JSON.stringify({ event, ...detail }))}\n`);
  };

  const audit = policy.audit.enabled
    ? new AuditWriter({
        path: resolveAgainst(loaded.dir, policy.audit.path),
        auditKey:
          policy.audit.key_env !== undefined ? context.env[policy.audit.key_env] : undefined,
        checkpointEvery: policy.audit.checkpoint_every,
        checkpoint: policy.audit.checkpoint_to === 'stderr' ? context.stderr : undefined,
      })
    : undefined;

  const telemetry =
    policy.telemetry.enabled && policy.telemetry.endpoint !== undefined
      ? new OtlpTelemetrySink({
          service: policy.telemetry.service_name,
          post: otlpPoster(
            policy.telemetry.endpoint,
            headersFrom(context.env, policy.telemetry.headers_env),
          ),
          onError: (error) => out('telemetry_error', { message: error.message }),
        })
      : NULL_TELEMETRY;

  const gates = buildGates({
    policy,
    compiledPolicy: compiled,
    ruleset,
    serverName,
    correlationKey: readKey(context.env, policy.pii.correlation_key_env),
    audit,
    lock: policy.lock.enabled
      ? fileLockStore(resolveAgainst(loaded.dir, policy.lock.path))
      : undefined,
    clock: () => Date.now(),
    telemetry,
    onEvent: out,
  });

  /** Who is calling: a token's identity when one was presented, else what the client calls itself. */
  const identityOf = (input: GatewayCallInput): IdentityResolution =>
    input.tokenIdentity !== undefined
      ? { identity: input.tokenIdentity, source: 'token', exact: true }
      : resolveIdentity({ clientName: input.clientInfo?.name });

  const gateway = createHttpGateway<CallContext>({
    name: serverName,
    target,
    gates,
    callContext: (input) => ({
      session: {
        id: input.session.sessionId,
        source: input.session.source,
        exact: input.session.exact,
      },
      identity: identityOf(input),
      listTools: input.listTools,
      connection: input.connection,
      upstream: input.upstream,
    }),
    sessionOf: (call) => call.session.id,
    auth: createBearerAuthenticator(
      policy.auth.tokens.map((token) => ({
        identity: token.identity,
        tokenSha256: token.token_sha256,
      })),
    ),
    allowedHosts: policy.http.allowed_hosts,
    allowedOrigins: policy.http.allowed_origins,
    session: {
      key: policy.session.key,
      idleTimeoutMs: policy.session.idle_timeout,
      maxBindings: policy.session.max_sessions,
    },
    maxUpstreamConnections: policy.session.max_upstream_connections,
    maxBodyBytes: policy.http.max_body_bytes,
    maxUpstreamResponseBytes: policy.http.max_upstream_response_bytes,
    clientName: 'mcpguard',
    version: PROXY_VERSION,
    onError: (error) => out('error', { message: error.message }),
    onEvent: out,
  });

  let endpoint: Awaited<ReturnType<typeof startHttpEndpoint>>;
  try {
    endpoint = await startHttpEndpoint({
      handler: gateway.fetch,
      host,
      port,
      maxBodyBytes: policy.http.max_body_bytes,
      maxInflight: policy.http.max_inflight,
      onError: (error) => out('error', { message: error.message }),
    });
  } catch (error) {
    await gateway.close();
    throw new CliError(`serve failed to bind ${host}:${port}: ${messageOf(error)}`, {
      exitCode: EXIT.runtime,
      cause: error,
    });
  }

  const probed = await gateway.probe();
  const shownHost = endpoint.host.includes(':') ? `[${endpoint.host}]` : endpoint.host;
  out('serve_started', {
    url: `http://${shownHost}:${endpoint.port}/mcp/${serverName}`,
    host: endpoint.host,
    port: endpoint.port,
    server: serverName,
    upstream: 'url' in target ? 'http' : 'stdio',
    upstreamEra: probed.era,
    ...(probed.reason !== undefined ? { upstreamNote: probed.reason } : {}),
    auth: policy.auth.tokens.length > 0 ? 'token' : 'none',
    transport: 'plain-http',
    ...(loopback
      ? {}
      : {
          warning:
            'plain HTTP on a non-loopback address: terminate TLS in front of this, or the token travels in the clear',
        }),
  });

  // Runs until the process is asked to stop.
  await new Promise<void>((resolve) => {
    if (context.onShutdown === undefined) return;
    context.onShutdown(resolve);
  });
  await endpoint.close();
  await gateway.close();
  out('serve_stopped', { server: serverName });
  return EXIT.ok;
}
