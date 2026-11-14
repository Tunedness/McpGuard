/**
 * `mcpguard lock`: look at the manifest lock, compare it to a live server, and
 * approve a change.
 *
 * `wrap` writes the lock on first contact and holds the server to it after
 * (ADR-005). This is the other half: `show` reads the lock back, `--diff` asks a
 * server for its manifest right now and says how it differs from the pin, and
 * `--accept` is the explicit approval that turns that manifest into the new pin.
 * Nothing here ever changes the lock without `--accept`.
 *
 * The live commands start the server themselves, because the transport is a
 * command-line argument and not policy: `mcpguard lock --accept -- node s.mjs`.
 */
import {
  compilePolicy,
  diffServer,
  emptyLock,
  escapeUnsafeJson,
  lockServer,
  type ManifestDiff,
  quote,
  serverLockOf,
  type ToolDefinition,
  toToolDefinition,
  withServerLock,
} from '@mcpguard/core';
import { listStdioTools } from '@mcpguard/proxy';
import { loadPolicy, resolveAgainst } from '../config.js';
import { CliError, EXIT, messageOf } from '../errors.js';
import { type CliContext, writeLines } from '../io.js';
import { fileLockStore, type LockStore } from '../lock-file.js';
import { scanFindings } from '../manifest-gate.js';
import { loadShippedRuleset } from '../ruleset.js';
import { toolScanner } from '../runtime.js';

/** The `lock` help text. */
export function lockHelp(): string[] {
  return [
    'Usage: mcpguard lock show   [--policy <path>]',
    '       mcpguard lock --diff   [--policy <path>] [--server <name>] -- <server-cmd> [args...]',
    '       mcpguard lock --accept [--policy <path>] [--server <name>] [--expect <set-hash>] [--full] -- <server-cmd> [args...]',
    '',
    '  show      Print what guardlock.json pins.',
    '  --diff    Start the server, read its tools now, and show how they differ from the pin,',
    '            with the full definition of every altered or added tool and the set hash.',
    '            Exits 5 when they differ or the server is not pinned.',
    "  --accept  Pin the server's tools as they are now. This is the approval step.",
    "  --expect  With --accept: refuse unless the manifest's set hash is this one, so what is",
    '            approved is exactly what --diff showed.',
    '  --full    Show whole tool definitions; by default a long one is cut at 4000 characters.',
    '  --server  The name the server is pinned under (default: server; same as wrap --name).',
  ];
}

interface LockArgs {
  readonly mode: 'show' | 'diff' | 'accept';
  readonly policy: string | undefined;
  readonly server: string | undefined;
  readonly expect: string | undefined;
  readonly full: boolean;
  readonly command: string | undefined;
  readonly args: readonly string[];
}

function parseLockArgs(argv: readonly string[]): LockArgs {
  let mode: LockArgs['mode'] | undefined;
  let policy: string | undefined;
  let server: string | undefined;
  let expect: string | undefined;
  let full = false;
  let i = 0;
  /** The value after a flag; a flag left without one is an error, not `undefined`. */
  const takeValue = (flag: string): string => {
    const value = argv[++i];
    if (value === undefined || value.trim() === '') {
      throw new CliError(`${flag} needs a value`, { exitCode: EXIT.usage });
    }
    return value;
  };
  const setMode = (next: LockArgs['mode']): void => {
    if (mode !== undefined && mode !== next) {
      throw new CliError('choose one of show, --diff and --accept', { exitCode: EXIT.usage });
    }
    mode = next;
  };
  for (; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') {
      i++;
      break;
    }
    if (arg === 'show') setMode('show');
    else if (arg === '--diff') setMode('diff');
    else if (arg === '--accept') setMode('accept');
    else if (arg === '--policy' || arg === '-p') policy = takeValue(arg);
    else if (arg === '--server' || arg === '-s') server = takeValue(arg);
    else if (arg === '--expect') expect = takeValue(arg);
    else if (arg === '--full') full = true;
    else {
      throw new CliError(`unknown lock argument: ${arg}`, {
        hints: ['use `show`, `--diff` or `--accept`; the server command goes after `--`'],
      });
    }
  }
  if (mode === undefined) {
    throw new CliError('lock needs `show`, `--diff` or `--accept`', { exitCode: EXIT.usage });
  }
  if (full && mode === 'show') {
    throw new CliError('--full goes with --diff or --accept', { exitCode: EXIT.usage });
  }
  if (expect !== undefined && mode !== 'accept') {
    throw new CliError('--expect only goes with --accept', { exitCode: EXIT.usage });
  }
  const rest = argv.slice(i);
  return { mode, policy, server, expect, full, command: rest[0], args: rest.slice(1) };
}

/** Runs the lock command. */
export async function runLock(context: CliContext, argv: readonly string[]): Promise<number> {
  const [first] = argv;
  if (first === undefined || first === '--help' || first === '-h') {
    writeLines(context.stdout, lockHelp());
    return first === undefined ? EXIT.usage : EXIT.ok;
  }
  const args = parseLockArgs(argv);
  const loaded = loadPolicy(context.cwd, context.env, args.policy);
  const store = fileLockStore(resolveAgainst(loaded.dir, loaded.policy.lock.path));

  if (args.mode === 'show') return show(context, store);

  if (args.command === undefined) {
    throw new CliError(`lock --${args.mode} needs the server command after \`--\``, {
      exitCode: EXIT.usage,
      hints: [`example: mcpguard lock --${args.mode} -- node server.mjs`],
    });
  }
  const serverName = args.server ?? 'server';
  const compiledPolicy = compilePolicy(loaded.policy);
  const scanTool = toolScanner({
    policy: loaded.policy,
    compiledPolicy,
    ruleset: loadShippedRuleset(),
    serverName,
  });

  const tools = await currentTools(args.command, args.args);
  const pinnedState = store.read();
  if (pinnedState.kind === 'invalid') {
    throw new CliError(`${store.path} cannot be used: ${pinnedState.reason}`, {
      exitCode: EXIT.integrity,
      hints: ['restore it from version control, or delete it to start over'],
    });
  }
  const pinned = pinnedState.kind === 'ok' ? serverLockOf(pinnedState.lock, serverName) : undefined;
  const flagged = scanFindings(tools, scanTool);

  const lines = [`lock: ${store.path}`, `server: ${quote(serverName)}`];
  const diff = pinned === undefined ? undefined : diffServer(pinned, tools);
  const setHash = lockServer(tools).toolsHash;
  if (pinned === undefined) lines.push('  not pinned yet');
  else if (diff !== undefined) lines.push(...describeDiff(diff));
  // What the operator is being asked to trust: the definitions as they are now,
  // not just their names. Quoted, because a definition is the server's words.
  const shown =
    pinned === undefined
      ? tools
      : tools.filter((t) => !diff || [...diff.altered, ...diff.added].includes(t.name));
  if (diff?.changed !== false) {
    for (const tool of shown) lines.push(`  now: ${showDefinition(tool, args.full)}`);
  }
  lines.push(`  set: ${setHash}`);
  for (const [tool, ruleIds] of flagged) {
    lines.push(
      `  description flagged: ${quote(tool)} (${ruleIds.map((id) => quote(id)).join(', ')})`,
    );
  }

  if (args.mode === 'diff') {
    writeLines(context.stdout, lines);
    return diff?.changed === false ? EXIT.ok : EXIT.integrity;
  }

  if (!loaded.policy.lock.enabled) {
    throw new CliError('lock.enabled is false in the policy, so nothing would read the lock', {
      exitCode: EXIT.usage,
      hints: ['set lock.enabled: true, or leave the lock alone'],
    });
  }
  if (args.expect !== undefined && args.expect !== setHash) {
    throw new CliError(
      "the server's manifest is not the one --expect named; it changed since it was reviewed",
      { exitCode: EXIT.integrity, hints: [...lines, 'run --diff again and review what it shows'] },
    );
  }
  if (diff?.changed === false) {
    lines.push(`  already pinned (${tools.length} tool(s)); nothing to write`);
    writeLines(context.stdout, lines);
    return EXIT.ok;
  }
  const base = pinnedState.kind === 'ok' ? pinnedState.lock : emptyLock();
  try {
    store.write(withServerLock(base, serverName, lockServer(tools, flagged)));
  } catch (error) {
    throw new CliError(`could not write ${store.path}: ${messageOf(error)}`, {
      exitCode: EXIT.runtime,
    });
  }
  lines.push(`  accepted: pinned ${tools.length} tool(s)`);
  writeLines(context.stdout, lines);
  return EXIT.ok;
}

function show(context: CliContext, store: LockStore): number {
  const state = store.read();
  if (state.kind === 'absent') {
    throw new CliError(`no lock file at ${store.path}`, {
      exitCode: EXIT.usage,
      hints: ['it is written on the first `wrap` run, or by `mcpguard lock --accept`'],
    });
  }
  if (state.kind === 'invalid') {
    throw new CliError(`${store.path} cannot be used: ${state.reason}`, {
      exitCode: EXIT.integrity,
    });
  }
  // Server and tool names came from a server: quoted, so a control character in
  // one cannot rewrite the operator's screen.
  const lines = [`lock: ${store.path}`];
  for (const [server, entry] of Object.entries(state.lock.servers)) {
    lines.push(
      `  ${quote(server)}: ${entry.tools.length} tool(s), set ${entry.toolsHash.slice(0, 12)}`,
    );
    for (const tool of entry.tools) {
      const flagged =
        tool.findings === undefined
          ? ''
          : `  flagged: ${tool.findings.map((id) => quote(id)).join(', ')}`;
      lines.push(`    ${quote(tool.name)} ${tool.hash.slice(0, 12)}${flagged}`);
    }
  }
  writeLines(context.stdout, lines);
  return EXIT.ok;
}

/** The server's tools right now. A manifest that is not well-formed is not pinned. */
async function currentTools(command: string, args: readonly string[]): Promise<ToolDefinition[]> {
  let raw: unknown[];
  try {
    raw = await listStdioTools({ command, args });
  } catch (error) {
    throw new CliError(`could not read the server's tools: ${messageOf(error)}`, {
      exitCode: EXIT.runtime,
    });
  }
  const tools: ToolDefinition[] = [];
  const names = new Set<string>();
  for (const entry of raw) {
    const tool = toToolDefinition(entry);
    if (tool === undefined || names.has(tool.name)) {
      throw new CliError('the server advertised a tool with no name, or the same name twice', {
        exitCode: EXIT.integrity,
        hints: ['a manifest like that is not pinned'],
      });
    }
    names.add(tool.name);
    tools.push(tool);
  }
  return tools;
}

function describeDiff(diff: ManifestDiff): string[] {
  if (!diff.changed) return ['  matches the pin'];
  const names = (list: readonly string[]): string => list.map((n) => quote(n)).join(', ');
  return [
    ...(diff.altered.length > 0 ? [`  altered: ${names(diff.altered)}`] : []),
    ...(diff.added.length > 0 ? [`  added:   ${names(diff.added)}`] : []),
    ...(diff.removed.length > 0 ? [`  removed: ${names(diff.removed)}`] : []),
  ];
}

const MAX_SHOWN_DEFINITION = 4_000;

/**
 * A tool definition on one quoted line. Long ones are capped unless `full`: a
 * cap is a place to hide a sentence behind padding, so the cap says it cut and
 * `--full` removes it.
 */
function showDefinition(tool: ToolDefinition, full: boolean): string {
  const text = escapeUnsafeJson(JSON.stringify(tool));
  if (full || text.length <= MAX_SHOWN_DEFINITION) return text;
  // Not in the middle of an escape sequence.
  const kept = text.slice(0, MAX_SHOWN_DEFINITION).replace(/\\(?:u[0-9a-f]{0,3})?$/, '');
  return `${kept}… (${text.length - kept.length} more characters; --full shows all)`;
}
