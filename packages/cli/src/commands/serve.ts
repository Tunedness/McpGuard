/**
 * `mcpguard serve`: the guarded HTTP gateway in front of one or more upstreams
 * (ADR-011).
 *
 * `wrap`, with an HTTP front door. The three gates are the ones `wrap` runs —
 * `buildGates` is called here exactly as it is there, once for each server, so a
 * server's rules, its lock entry (`servers.<name>` in `guardlock.json`) and its
 * halt are its own — and what differs is what a pipe never needs: the session
 * of each call is resolved by the ADR-006 ladder and written into the `_meta`
 * that goes upstream, the caller is identified by a bearer token when the policy
 * defines any, and Host, Origin, body size and concurrency are bounded before a
 * request reaches any of it.
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
  type GatewayServer,
  isSupportedSessionKey,
  PROXY_VERSION,
  parseTraceparent,
  startHttpEndpoint,
  type UpstreamTarget,
} from '@tunedness/mcpguard-proxy';
import { AuditWriter } from '../audit-writer.js';
import { loadPolicy, resolveAgainst } from '../config.js';
import { CliError, EXIT, messageOf } from '../errors.js';
import { type CliContext, writeLines } from '../io.js';
import { buildJudge } from '../judge/index.js';
import { fileLockStore } from '../lock-file.js';
import { assertPolicyRunnable, readKey } from '../preflight.js';
import { loadShippedRuleset } from '../ruleset.js';
import { buildGates, type CallContext, CombinationHistory, resolveIdentity } from '../runtime.js';
import { checkServerName, reportUnmatchedServer } from '../server-name.js';
import {
  checkpointFailureReporter,
  checkpointSinkFor,
  NULL_TELEMETRY,
  OtlpTelemetrySink,
} from '../telemetry/sink.js';
import { ulid } from '../ulid.js';
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
    '       mcpguard serve [options]            (servers come from the policy)',
    '',
    'Guards MCP servers behind one HTTP endpoint each, at /mcp/<name>. The servers are',
    'the ones the policy defines under servers.<name>.upstream, plus the one given here,',
    'if any. Each has its own rules, its own lock entry and its own connections.',
    '',
    'Options:',
    '  --policy <path>    Policy file (default: search up from cwd)',
    '  --name <name>      Name the server given here goes by in the path, rules and the log',
    '                     (default: server)',
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

/** The longest and the characters a server name may have: it is a URL path segment. */
const SERVER_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** Checks an HTTP upstream URL and returns it in canonical form. */
function httpTarget(raw: string, what: string): UpstreamTarget {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new CliError(`${what} is not a URL: ${raw}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new CliError(`${what} must be an http: or https: URL`);
  }
  return { url: url.toString() };
}

/** Checks that a stdio upstream can be started, and returns it. */
function commandTarget(
  command: string,
  args: readonly string[],
  env: CliContext['env'],
  exitCode: number,
): UpstreamTarget {
  try {
    assertRunnable(command, env);
  } catch (error) {
    throw new CliError(messageOf(error), { exitCode });
  }
  return { command, args };
}

/** A server the gateway fronts, and where its definition came from. */
interface ServerDefinition {
  readonly name: string;
  readonly target: UpstreamTarget;
  readonly source: 'command line' | 'policy';
}

/**
 * The servers to front: the one the command line names, if any, and every server
 * the policy gives an upstream. A name defined in both places is an error rather
 * than a precedence rule, since a silent override between the two would let either
 * quietly replace the other.
 */
function serversOf(
  parsed: ReturnType<typeof parseServeArgs>,
  policy: CompiledPolicy['policy'],
  env: CliContext['env'],
): ServerDefinition[] {
  const definitions: ServerDefinition[] = [];
  const given = parsed.upstream !== undefined || parsed.command !== undefined;
  if (parsed.command !== undefined && parsed.upstream !== undefined) {
    throw new CliError('serve takes --upstream or a command after `--`, not both');
  }
  if (!given && parsed.name !== undefined) {
    throw new CliError('--name names the server of --upstream or of a command after `--`', {
      hints: ['servers defined in the policy are named by their key under servers:'],
    });
  }

  if (given) {
    const name = parsed.name ?? 'server';
    if (!SERVER_NAME.test(name)) {
      throw new CliError(`--name "${name}" cannot be used in a URL path`, {
        hints: ['use letters, digits, `.`, `_` and `-`, up to 64 characters'],
      });
    }
    if (parsed.upstream !== undefined) {
      if (parsed.upstream === '') throw new CliError('--upstream needs a URL');
      definitions.push({
        name,
        target: httpTarget(parsed.upstream, '--upstream'),
        source: 'command line',
      });
    } else if (parsed.command !== undefined) {
      definitions.push({
        name,
        target: commandTarget(parsed.command, parsed.args, env, EXIT.usage),
        source: 'command line',
      });
    }
  }

  for (const [name, server] of Object.entries(policy.servers)) {
    const upstream = server.upstream;
    if (upstream === undefined) continue;
    if (definitions.some((entry) => entry.name === name)) {
      throw new CliError(
        `"${name}" is given an upstream both here and in the policy (servers.${name}.upstream)`,
        { exitCode: EXIT.policy, hints: ['define it in one place, or use another --name'] },
      );
    }
    if (!SERVER_NAME.test(name)) {
      throw new CliError(`servers.${name} cannot be served: its name is not usable in a URL path`, {
        exitCode: EXIT.policy,
        hints: ['use letters, digits, `.`, `_` and `-`, up to 64 characters'],
      });
    }
    try {
      definitions.push({
        name,
        target:
          'url' in upstream
            ? httpTarget(upstream.url, `servers.${name}.upstream.url`)
            : commandTarget(upstream.command, upstream.args, env, EXIT.policy),
        source: 'policy',
      });
    } catch (error) {
      // A definition in the policy that cannot be served is a policy problem.
      if (error instanceof CliError && error.exitCode === EXIT.usage) {
        throw new CliError(error.message, { exitCode: EXIT.policy, cause: error });
      }
      throw error;
    }
  }

  if (definitions.length === 0) {
    throw new CliError(
      'serve needs an upstream: --upstream <url>, a command after `--`, or servers.<name>.upstream in the policy',
      {
        hints: [
          'example: mcpguard serve --name echo -- node server.mjs',
          'example: mcpguard serve --name docs --upstream https://mcp.example.com/mcp',
        ],
      },
    );
  }
  return definitions;
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

  const loaded = loadPolicy(context.cwd, context.env, parsed.policy);
  assertPolicyRunnable(loaded.policy, context.env);
  const policy = loaded.policy;
  const definitions = serversOf(parsed, policy, context.env);
  // The command-line upstream is the one server whose name the operator types; the
  // policy's own are named by their keys. Under `enforce` a name the policy's
  // `servers` section does not carry is refused: it would run without the rules
  // written under `servers.<name>`, roles included.
  const unmatched = definitions
    .filter((definition) => definition.source === 'command line')
    .map((definition) =>
      checkServerName(policy, definition.name, 'serve', parsed.name !== undefined),
    )
    .find((entry) => entry !== undefined);
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
  if (unmatched !== undefined) {
    reportUnmatchedServer(unmatched, out, telemetry, Date.now, ulid());
  }

  const audit = policy.audit.enabled
    ? new AuditWriter({
        path: resolveAgainst(loaded.dir, policy.audit.path),
        auditKey:
          policy.audit.key_env !== undefined ? context.env[policy.audit.key_env] : undefined,
        checkpointEvery: policy.audit.checkpoint_every,
        // A checkpoint that goes missing is reported on stderr and as a security event.
        checkpoint: checkpointSinkFor(
          policy.audit,
          context.stderr,
          checkpointFailureReporter({
            out,
            telemetry,
            clock: Date.now,
            sessionId: ulid(),
            serverName: '*',
          }),
        ),
      })
    : undefined;

  // One history for every server: a combination rule is about what a session has
  // done, and a session may have done it on two servers. Marks carry the server.
  const history =
    compiled.combinations.length > 0
      ? new CombinationHistory(
          Math.max(...compiled.combinations.map((combination) => combination.rule.window)),
        )
      : undefined;
  const lock = policy.lock.enabled
    ? fileLockStore(resolveAgainst(loaded.dir, policy.lock.path))
    : undefined;
  const correlationKey = readKey(context.env, policy.pii.correlation_key_env);
  // One judge for every server: one endpoint, one breaker, one in-flight limit.
  const judgeSession = ulid();
  const judge = buildJudge(policy, {
    headers: headersFrom(context.env, policy.judge.headers_env),
    clock: () => Date.now(),
    onUnavailable: (info) => {
      out('judge_error', { session: judgeSession, reason: 'circuit_open', ...info });
      telemetry.emit({
        type: 'security_event',
        kind: 'judge_unavailable',
        at: Date.now(),
        sessionId: judgeSession,
        serverName: '*',
        toolName: undefined,
        score: undefined,
        action: 'none',
        evidence: ['judge.circuit_open'],
      });
    },
  });

  const servers: GatewayServer<CallContext>[] = definitions.map((definition) => ({
    name: definition.name,
    target: definition.target,
    // Built for this server's name: its scan and access rules, its entry in the
    // lock and its halt are looked up by it, and no other server's state is read.
    gates: buildGates({
      policy,
      compiledPolicy: compiled,
      ruleset,
      serverName: definition.name,
      correlationKey,
      audit,
      lock,
      history,
      clock: () => Date.now(),
      telemetry,
      judge,
      onEvent: out,
    }),
  }));

  /** Who is calling: a token's identity when one was presented, else what the client calls itself. */
  const identityOf = (input: GatewayCallInput): IdentityResolution =>
    input.tokenIdentity !== undefined
      ? { identity: input.tokenIdentity, source: 'token', exact: true }
      : resolveIdentity({ clientName: input.clientInfo?.name });

  const gateway = createHttpGateway<CallContext>({
    servers,
    callContext: (input) => ({
      session: {
        id: input.session.sessionId,
        source: input.session.source,
        exact: input.session.exact,
      },
      identity: identityOf(input),
      trace: parseTraceparent(input.traceparent),
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
    host: endpoint.host,
    port: endpoint.port,
    servers: definitions.map((definition) => {
      const probe = probed.find((entry) => entry.server === definition.name);
      return {
        name: definition.name,
        url: `http://${shownHost}:${endpoint.port}/mcp/${definition.name}`,
        upstream: 'url' in definition.target ? 'http' : 'stdio',
        defined: definition.source,
        upstreamEra: probe?.era ?? 'unavailable',
        ...(probe?.reason !== undefined ? { upstreamNote: probe.reason } : {}),
      };
    }),
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
  out('serve_stopped', { servers: definitions.map((definition) => definition.name) });
  return EXIT.ok;
}
