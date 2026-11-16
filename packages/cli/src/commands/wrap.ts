/**
 * `mcpguard wrap -- <server-cmd>`: guard one stdio MCP server.
 *
 * One wrapped child is one connection is one session, identified by a ULID
 * minted here — the exact, heuristic-free session id the records are tied
 * together by (ADR-006). The caller's identity is a separate thing, resolved
 * through the ADR-010 ladder. This command loads the policy and the ruleset, builds the
 * gates, mints the session, opens the audit writer, and hands the lot to the
 * proxy. Everything it writes goes to stderr; stdout belongs to the agent's
 * JSON-RPC stream.
 */
import { compilePolicy, escapeUnsafeJson } from '@tunedness/mcpguard-core';
import { eraOf, listAllTools, type WrapHandle, wrapStdioServer } from '@tunedness/mcpguard-proxy';
import { AuditWriter } from '../audit-writer.js';
import { loadPolicy, resolveAgainst } from '../config.js';
import { CliError, EXIT, messageOf } from '../errors.js';
import { type CliContext, writeLines } from '../io.js';
import { fileLockStore } from '../lock-file.js';
import { assertPolicyRunnable, readKey } from '../preflight.js';
import { loadShippedRuleset } from '../ruleset.js';
import { buildGates, resolveIdentity } from '../runtime.js';
import { checkServerName, reportUnmatchedServer } from '../server-name.js';
import { NULL_TELEMETRY, OtlpTelemetrySink } from '../telemetry/sink.js';
import { ulid } from '../ulid.js';
import { parseWrapArgs } from './wrap-args.js';

/** Flags `wrap` accepts before the `--`. */
export function wrapHelp(): string[] {
  return [
    'Usage: mcpguard wrap [options] -- <server-command> [server-args...]',
    '',
    'Options:',
    '  --policy <path>   Policy file (default: search up from cwd)',
    '  --name <name>     Name the wrapped server goes by in rules and the log',
    '  --identity <name> Who the caller is, for role mapping (or set MCPGUARD_IDENTITY)',
    '  --help            Show this help',
  ];
}

/** Runs the wrap command. */
export async function runWrap(context: CliContext, argv: readonly string[]): Promise<number> {
  const parsed = parseWrapArgs(argv);
  if (parsed.help) {
    writeLines(context.stdout, wrapHelp());
    return EXIT.ok;
  }
  if (parsed.command === undefined) {
    throw new CliError('wrap needs a server command after `--`', {
      hints: ['example: mcpguard wrap -- node server.mjs'],
    });
  }

  if (parsed.identity !== undefined && parsed.identity.trim() === '') {
    throw new CliError('--identity needs a value', {
      hints: ['example: mcpguard wrap --identity alice -- node server.mjs'],
    });
  }

  // An identity the operator tried to set and left empty is a mistake to stop
  // on, not a reason to fall through to the rung the client controls. When
  // `--identity` is given the env rung is never read, so a stray empty export
  // is harmless and does not stop the start.
  const envIdentity = context.env.MCPGUARD_IDENTITY;
  if (parsed.identity === undefined && envIdentity !== undefined && envIdentity.trim() === '') {
    throw new CliError('MCPGUARD_IDENTITY is set but empty', {
      hints: ['give it a value, or unset it to resolve the identity from clientInfo'],
    });
  }

  const loaded = loadPolicy(context.cwd, context.env, parsed.policy);
  assertPolicyRunnable(loaded.policy, context.env);
  const ruleset = loadShippedRuleset();
  const serverName = parsed.name ?? 'server';
  // Everything under `servers.<name>` is read under this name: a name the policy
  // does not carry runs unrestricted, so under `enforce` it is refused here.
  const unmatched = checkServerName(loaded.policy, serverName, 'wrap', parsed.name !== undefined);
  const sessionId = ulid();
  const compiled = compilePolicy(loaded.policy);

  const audit = loaded.policy.audit.enabled
    ? new AuditWriter({
        path: resolveAgainst(loaded.dir, loaded.policy.audit.path),
        auditKey:
          loaded.policy.audit.key_env !== undefined
            ? context.env[loaded.policy.audit.key_env]
            : undefined,
        checkpointEvery: loaded.policy.audit.checkpoint_every,
        checkpoint: loaded.policy.audit.checkpoint_to === 'stderr' ? context.stderr : undefined,
      })
    : undefined;

  const telemetry =
    loaded.policy.telemetry.enabled && loaded.policy.telemetry.endpoint !== undefined
      ? new OtlpTelemetrySink({
          service: loaded.policy.telemetry.service_name,
          post: otlpPoster(
            loaded.policy.telemetry.endpoint,
            headersFrom(context.env, loaded.policy.telemetry.headers_env),
          ),
          onError: (error) =>
            context.stderr.write(
              `[mcpguard] ${JSON.stringify({ event: 'telemetry_error', message: error.message })}\n`,
            ),
        })
      : NULL_TELEMETRY;
  if (unmatched !== undefined) {
    reportUnmatchedServer(
      unmatched,
      (event, detail) =>
        context.stderr.write(
          `[mcpguard] ${escapeUnsafeJson(JSON.stringify({ event, session: sessionId, ...detail }))}\n`,
        ),
      telemetry,
      Date.now,
      sessionId,
    );
  }

  // The bridge exists only once the client's first message has named an era, and
  // the identity ladder and the manifest gate read from it, so it is reached
  // through the running wrap. A call that arrives before it is set sees no
  // identity, which fails towards the policy's default, never towards a role.
  let wrap: WrapHandle | undefined;
  const clientName = (): string | undefined => {
    const downstream: DownstreamView | undefined = wrap?.current()?.server;
    const negotiated = downstream?.getNegotiatedProtocolVersion();
    // ADR-010: the modern era has no `initialize`, so there is no rung to read.
    if (negotiated === undefined || eraOf(negotiated) === 'modern') return undefined;
    return downstream?.getClientVersion()?.name;
  };

  const gates = buildGates({
    policy: loaded.policy,
    compiledPolicy: compiled,
    ruleset,
    serverName,
    sessionId,
    sessionExact: true,
    resolveIdentity: () =>
      resolveIdentity({
        flag: parsed.identity,
        env: context.env.MCPGUARD_IDENTITY,
        clientName: clientName(),
      }),
    correlationKey: readKey(context.env, loaded.policy.pii.correlation_key_env),
    audit,
    lock: loaded.policy.lock.enabled
      ? fileLockStore(resolveAgainst(loaded.dir, loaded.policy.lock.path))
      : undefined,
    fetchTools: async () => {
      const upstream = wrap?.current()?.client;
      if (upstream === undefined) throw new Error('the upstream is not connected yet');
      return listAllTools(upstream);
    },
    clock: () => Date.now(),
    telemetry,
    onEvent: (event, detail) =>
      context.stderr.write(
        `[mcpguard] ${escapeUnsafeJson(JSON.stringify({ event, session: sessionId, ...detail }))}\n`,
      ),
  });

  try {
    wrap = await wrapStdioServer({
      command: parsed.command,
      args: parsed.args,
      clientName: 'mcpguard',
      gates,
      onError: (error) =>
        context.stderr.write(
          `[mcpguard] ${JSON.stringify({ event: 'error', message: error.message })}\n`,
        ),
    });
    // Runs until the transport closes (the client goes away or stdin ends).
    await wrap.closed;
    await wrap.close();
    return EXIT.ok;
  } catch (error) {
    throw new CliError(`wrap failed: ${messageOf(error)}`, {
      exitCode: EXIT.runtime,
      cause: error,
    });
  }
}

/** The slice of the downstream `Server` the identity ladder reads. */
interface DownstreamView {
  getClientVersion(): { name: string } | undefined;
  getNegotiatedProtocolVersion(): string | undefined;
}

/** A best-effort OTLP/HTTP JSON poster. A failed post is reported, never thrown. */
export function otlpPoster(
  endpoint: string,
  headers: Record<string, string>,
): (payload: unknown) => Promise<void> {
  return async (payload) => {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(`collector responded ${response.status}`);
  };
}

/** Parses `KEY=value,KEY2=value2` from the named environment variable. */
export function headersFrom(
  env: Readonly<Record<string, string | undefined>>,
  headersEnv: string | undefined,
): Record<string, string> {
  const raw = headersEnv !== undefined ? env[headersEnv] : undefined;
  if (raw === undefined) return {};
  const out: Record<string, string> = {};
  for (const pair of raw.split(',')) {
    const [key, ...rest] = pair.split('=');
    if (key !== undefined && rest.length > 0) out[key.trim()] = rest.join('=').trim();
  }
  return out;
}
