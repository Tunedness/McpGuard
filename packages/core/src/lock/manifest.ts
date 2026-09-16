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
import { sha256 } from '../util/hash.js';
import { type JsonValue, stableStringify, toJsonValue } from '../util/json.js';

/** One tool as the server advertised it. Only the fields that define behaviour. */
export interface ToolDefinition {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema?: unknown;
  readonly annotations?: unknown;
}

/** The pinned hash of one tool. */
export interface ToolLock {
  readonly name: string;
  readonly hash: string;
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
  const normalized: JsonValue = toJsonValue({
    name: tool.name,
    description: tool.description ?? '',
    inputSchema: tool.inputSchema ?? null,
    annotations: tool.annotations ?? null,
  });
  return sha256(stableStringify(normalized));
}

/** Builds the lock entry for one server's advertised tools. */
export function lockServer(tools: readonly ToolDefinition[]): ServerLock {
  const locks: ToolLock[] = tools.map((tool) => ({ name: tool.name, hash: hashTool(tool) }));
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
