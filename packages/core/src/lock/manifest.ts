/**
 * Manifest pinning: trust-on-first-use, then a hash lock.
 *
 * A rug-pull server changes what its tools do after approval. MCP has no
 * standard server identity yet, so the pragmatic guard (ADR-005) is to record a
 * hash of every tool definition on first contact and hold the server to it. A
 * later mismatch stops traffic and shows the diff; the lock file goes into VCS
 * so a manifest change lands in code review.
 *
 * Normalisation and hashing are pure and live here; reading and writing
 * `guardlock.json` is the CLI's job.
 */
import { quote } from '../util/display.js';
import { sha256 } from '../util/hash.js';
import { type JsonValue, stableStringify, toJsonValue } from '../util/json.js';

/** One tool as the server advertised it. Only the fields that define behaviour. */
export interface ToolDefinition {
  readonly name: string;
  /** The display title some clients show, and some models read. */
  readonly title?: string;
  readonly description?: string;
  readonly inputSchema?: unknown;
  readonly outputSchema?: unknown;
  readonly annotations?: unknown;
}

/** The pinned hash of one tool. */
export interface ToolLock {
  readonly name: string;
  readonly hash: string;
  /**
   * Scanner rule ids that fired on the tool's description and annotations when
   * it was pinned. Informational: they are not part of any hash, so a finding
   * never makes a manifest look changed. Absent when nothing fired.
   */
  readonly findings?: readonly string[];
}

/** The pinned state of one server. */
export interface ServerLock {
  /** Hash over the whole normalised tool set, in advertised order. */
  readonly toolsHash: string;
  readonly tools: readonly ToolLock[];
}

/** The lock file: one entry per server, keyed by name. */
export interface GuardLock {
  readonly version: 1;
  readonly servers: Record<string, ServerLock>;
}

/** Hashes one tool over its normalised, order-independent form. */
export function hashTool(tool: ToolDefinition): string {
  // Only the behaviour-defining fields, in a fixed key order. A server that
  // reorders its input-schema keys has not changed the tool; one that adds a
  // parameter has, and the sorted serialisation shows the second and not the
  // first.
  //
  // `title` and `outputSchema` are hashed only when present, so a tool that has
  // neither keeps the hash it always had; one that has them cannot change
  // either without the diff showing it.
  const normalized: JsonValue = toJsonValue({
    name: tool.name,
    description: tool.description ?? '',
    inputSchema: tool.inputSchema ?? null,
    annotations: tool.annotations ?? null,
    ...(tool.title !== undefined ? { title: tool.title } : {}),
    ...(tool.outputSchema !== undefined ? { outputSchema: tool.outputSchema } : {}),
  });
  return sha256(stableStringify(normalized));
}

/**
 * Builds the lock entry for one server's advertised tools.
 *
 * `findings` maps a tool name to the scanner rule ids that fired on its
 * description; they are recorded beside the hash, sorted and de-duplicated so
 * the file is stable, and never feed the hashes.
 */
export function lockServer(
  tools: readonly ToolDefinition[],
  findings: ReadonlyMap<string, readonly string[]> = new Map(),
): ServerLock {
  const locks: ToolLock[] = tools.map((tool) => {
    const fired = [...new Set(findings.get(tool.name) ?? [])].sort();
    return fired.length === 0
      ? { name: tool.name, hash: hashTool(tool) }
      : { name: tool.name, hash: hashTool(tool), findings: fired };
  });
  // The set hash preserves advertised order: a reordering is not a change to
  // what any tool does, but it is a change to the catalogue, and the diff should
  // be able to say which.
  const toolsHash = sha256(stableStringify(toJsonValue(locks.map((l) => [l.name, l.hash]))));
  return { toolsHash, tools: locks };
}

/** How the current manifest differs from the pinned one. */
export interface ManifestDiff {
  readonly changed: boolean;
  readonly added: readonly string[];
  readonly removed: readonly string[];
  /** Tools whose definition hash no longer matches — the rug-pull shape. */
  readonly altered: readonly string[];
}

/** Compares a server's current tools against its pinned lock. */
export function diffServer(lock: ServerLock, current: readonly ToolDefinition[]): ManifestDiff {
  const currentLocks = new Map(current.map((tool) => [tool.name, hashTool(tool)]));
  const pinned = new Map(lock.tools.map((tool) => [tool.name, tool.hash]));

  const added: string[] = [];
  const removed: string[] = [];
  const altered: string[] = [];

  for (const [name, hash] of currentLocks) {
    const before = pinned.get(name);
    if (before === undefined) added.push(name);
    else if (before !== hash) altered.push(name);
  }
  for (const name of pinned.keys()) {
    if (!currentLocks.has(name)) removed.push(name);
  }

  const changed = added.length > 0 || removed.length > 0 || altered.length > 0;
  return { changed, added: added.sort(), removed: removed.sort(), altered: altered.sort() };
}

/** An empty lock, for a first run. */
export function emptyLock(): GuardLock {
  return { version: 1, servers: {} };
}

/**
 * Reads a tool definition out of whatever a server put in `tools/list`.
 *
 * Only the behaviour-defining fields are kept: name, title, description, both
 * schemas and annotations. A value with no string
 * name is not a tool, and the caller decides what that means: a server that
 * advertises one is misbehaving, not merely sparse.
 */
export function toToolDefinition(value: unknown): ToolDefinition | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const raw = value as Record<string, unknown>;
  if (typeof raw.name !== 'string' || raw.name === '') return undefined;
  return {
    name: raw.name,
    ...(typeof raw.title === 'string' ? { title: raw.title } : {}),
    ...(typeof raw.description === 'string' ? { description: raw.description } : {}),
    ...(raw.inputSchema !== undefined ? { inputSchema: raw.inputSchema } : {}),
    ...(raw.outputSchema !== undefined ? { outputSchema: raw.outputSchema } : {}),
    ...(raw.annotations !== undefined ? { annotations: raw.annotations } : {}),
  };
}

/** The pinned entry for one server, or undefined. Own keys only. */
export function serverLockOf(lock: GuardLock, serverName: string): ServerLock | undefined {
  // `servers` is keyed by a name the operator chose; `constructor` or
  // `__proto__` must not resolve to something on the prototype chain.
  return Object.hasOwn(lock.servers, serverName) ? lock.servers[serverName] : undefined;
}

/** A copy of `lock` with one server's entry set. Other servers are kept. */
export function withServerLock(lock: GuardLock, serverName: string, entry: ServerLock): GuardLock {
  const servers = Object.fromEntries([
    ...Object.entries(lock.servers).filter(([name]) => name !== serverName),
    [serverName, entry],
  ]);
  return { version: 1, servers };
}

/** A lock file that cannot be trusted: unparsable or the wrong shape. */
export class LockFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LockFormatError';
  }
}

const HASH_PATTERN = /^[0-9a-f]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Parses and validates a `guardlock.json`.
 *
 * A lock that half-parses is worse than none: reading a malformed entry as
 * "nothing pinned" would let the next first-use write overwrite it, and reading
 * it as "pinned" would compare against garbage. Anything off is an error.
 *
 * @throws {LockFormatError} naming what is wrong.
 */
export function parseLock(text: string): GuardLock {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    throw new LockFormatError(`not valid JSON: ${error instanceof Error ? error.message : error}`);
  }
  if (!isRecord(raw) || raw.version !== 1) {
    throw new LockFormatError('expected an object with "version": 1');
  }
  if (!isRecord(raw.servers)) throw new LockFormatError('"servers" must be an object');

  const servers: [string, ServerLock][] = [];
  for (const [name, entry] of Object.entries(raw.servers)) {
    if (!isRecord(entry) || typeof entry.toolsHash !== 'string' || !Array.isArray(entry.tools)) {
      throw new LockFormatError(`server ${quote(name)}: expected toolsHash and a tools array`);
    }
    if (!HASH_PATTERN.test(entry.toolsHash)) {
      throw new LockFormatError(`server ${quote(name)}: toolsHash is not a sha-256 digest`);
    }
    const tools: ToolLock[] = [];
    for (const tool of entry.tools) {
      if (!isRecord(tool) || typeof tool.name !== 'string' || typeof tool.hash !== 'string') {
        throw new LockFormatError(`server ${quote(name)}: a tool needs a name and a hash`);
      }
      if (!HASH_PATTERN.test(tool.hash)) {
        throw new LockFormatError(
          `server ${quote(name)}: hash of ${quote(tool.name)} is not a digest`,
        );
      }
      const findings = tool.findings;
      if (findings === undefined) {
        tools.push({ name: tool.name, hash: tool.hash });
      } else if (Array.isArray(findings) && findings.every((id) => typeof id === 'string')) {
        tools.push({ name: tool.name, hash: tool.hash, findings: findings as string[] });
      } else {
        throw new LockFormatError(
          `server ${quote(name)}: findings of ${quote(tool.name)} must be strings`,
        );
      }
    }
    servers.push([name, { toolsHash: entry.toolsHash, tools }]);
  }
  return { version: 1, servers: Object.fromEntries(servers) };
}

function sortKeys(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortKeys(value[key] as JsonValue)]),
    );
  }
  return value;
}

/**
 * Serialises a lock the same way every time: sorted keys, two-space indent, a
 * final newline. The file goes into VCS (ADR-005), so the same pinned state
 * must always be the same bytes, or a re-pin shows up as a diff of nothing.
 */
export function serializeLock(lock: GuardLock): string {
  return `${JSON.stringify(sortKeys(toJsonValue(lock)), null, 2)}\n`;
}
