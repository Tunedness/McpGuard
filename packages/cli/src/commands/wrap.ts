/**
 * `mcpguard wrap -- <server-cmd>`: guard one stdio MCP server.
 *
 * One wrapped child is one connection is one session, identified by a ULID
 * minted here — the exact, heuristic-free identity the wrap story is told
 * through (ADR-006). This command loads the policy and the ruleset, builds the
 * gates, mints the session, opens the audit writer, and hands the lot to the
 * proxy. Everything it writes goes to stderr; stdout belongs to the agent's
 * JSON-RPC stream.
 */
import { compilePolicy } from '@mcpguard/core';
import { wrapStdioServer } from '@mcpguard/proxy';
import { AuditWriter } from '../audit-writer.js';
import { loadPolicy } from '../config.js';
import { CliError, EXIT, messageOf } from '../errors.js';
import { type CliContext, writeLines } from '../io.js';
import { loadShippedRuleset } from '../ruleset.js';
import { buildGates } from '../runtime.js';
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

  const loaded = loadPolicy(context.cwd, context.env, parsed.policy);
  const ruleset = loadShippedRuleset();
  const serverName = parsed.name ?? 'server';
  const sessionId = ulid();
  const compiled = compilePolicy(loaded.policy);

  const audit = loaded.policy.audit.enabled
    ? new AuditWriter({
        path: resolveAuditPath(loaded.dir, loaded.policy.audit.path),
        auditKey:
          loaded.policy.audit.key_env !== undefined
            ? context.env[loaded.policy.audit.key_env]
            : undefined,
        checkpointEvery: loaded.policy.audit.checkpoint_every,
        checkpoint: loaded.policy.audit.checkpoint_to === 'stderr' ? context.stderr : undefined,
      })
    : undefined;

  const gates = buildGates({
    policy: loaded.policy,
    compiledPolicy: compiled,
    ruleset,
    serverName,
    sessionId,
    sessionExact: true,
    audit,
    clock: () => Date.now(),
    onEvent: (event, detail) =>
      context.stderr.write(
        `[mcpguard] ${JSON.stringify({ event, session: sessionId, ...detail })}\n`,
      ),
  });

  try {
    const handle = await wrapStdioServer({
      command: parsed.command,
      args: parsed.args,
      clientName: 'mcpguard',
      gates,
      onError: (error) =>
        context.stderr.write(
          `[mcpguard] ${JSON.stringify({ event: 'error', message: error.message })}\n`,
        ),
    });
    // Runs until the transport closes (the child exits or stdin ends).
    await waitForClose(handle.bridge.server);
    await handle.close();
    return EXIT.ok;
  } catch (error) {
    throw new CliError(`wrap failed: ${messageOf(error)}`, {
      exitCode: EXIT.runtime,
      cause: error,
    });
  }
}

function resolveAuditPath(dir: string, path: string): string {
  return path.startsWith('/') ? path : `${dir}/${path}`;
}

/** Resolves when the downstream server transport closes. */
function waitForClose(server: { onclose?: (() => void) | undefined }): Promise<void> {
  return new Promise((resolve) => {
    const prior = server.onclose;
    server.onclose = () => {
      prior?.();
      resolve();
    };
  });
}
