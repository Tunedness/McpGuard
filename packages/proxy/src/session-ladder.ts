/**
 * Session attribution over HTTP: the ADR-006 ladder.
 *
 * In `wrap` a session is a fact — one child process, one connection. Over HTTP
 * nothing can be leaned on, and the modern era has no session at all, so "which
 * calls belong to one task" is answered from what the requests carry. Top to
 * bottom: the trace id of `traceparent`, the `tunedness.session-id` baggage
 * member an outer proxy injected, the `Mcp-Session-Id` the gateway itself minted
 * (legacy only), and last a hash of `clientInfo` and the peer's address.
 *
 * Attribution is not the upstream connection (ADR-011): the connection is
 * keyed by transport, and this runs on every request, so a client that changes
 * its trace id with each call changes the session without opening anything.
 *
 * The bottom rung is a guess, and says so: `exact` is false there and true
 * above it. "Exact" means the caller declared it, not that it cannot be forged
 * — the threat model is an injected model, and a model does not pick a
 * `traceparent`; a hostile client can still split its steps across trace ids.
 *
 * The bottom rung needs memory, so it needs bounds: entries expire against an
 * injected clock (no timers here) and the table never holds more than
 * `maxBindings`, dropping the one idle longest.
 *
 * This module imports neither engine package. See `boundary.test.ts`.
 */
import { createHash, randomUUID } from 'node:crypto';
import {
  baggageEntry,
  type ClientIdentity,
  clientInfoOf,
  type MetaBag,
  parseTraceparent,
  SESSION_BAGGAGE_KEY,
  traceparentOf,
} from './remap.js';

/** Which rung produced a session id. `connection` (wrap's) never appears here. */
export type LadderSource = 'traceparent' | 'baggage' | 'mcp-session-id' | 'client-address';

/** Everything the ladder is allowed to look at. */
export interface SessionKeyInput {
  /** The request's `_meta`. Where the trace rungs live. */
  readonly meta?: MetaBag | undefined;
  /** The gateway-minted `Mcp-Session-Id` of a legacy connection. */
  readonly mcpSessionId?: string | undefined;
  /** `clientInfo`: from `initialize` (legacy), or read off `_meta` when absent. */
  readonly clientInfo?: ClientIdentity | undefined;
  /** The peer's address, off the socket — never from `X-Forwarded-For`. */
  readonly remoteAddress?: string | undefined;
}

/** What the ladder resolved, and how much it is worth. */
export interface SessionKeyResolution {
  readonly sessionId: string;
  readonly source: LadderSource;
  /** True when the caller declared it; false for the address guess. */
  readonly exact: boolean;
}

const NUL = '\u0000';

/** The longest session id taken from a baggage member. */
export const MAX_SESSION_ID_LENGTH = 128;

/** Control, format (bidi, zero-width) and line/paragraph separator characters. */
const UNSAFE_ID = /[\p{Cc}\p{Cf}\u2028\u2029]/u;

/**
 * A baggage value the caller chose, as a session id, or nothing.
 *
 * It is copied into every record, event and header the session touches, so one
 * that is huge or carries line separators or direction controls is not a
 * session id: the rung is treated as absent, not logged.
 */
function usableId(value: string | undefined): string | undefined {
  if (value === undefined || value.length > MAX_SESSION_ID_LENGTH || UNSAFE_ID.test(value)) {
    return undefined;
  }
  return value;
}

/** The trace id of a W3C `traceparent`, when it is well-formed (see `parseTraceparent`). */
export function traceIdOf(traceparent: string | undefined): string | undefined {
  return parseTraceparent(traceparent)?.traceId;
}

/** The bottom rung's key: who, from where. NUL-separated, since NUL cannot occur in either. */
export function clientAddressKey(
  clientInfo: ClientIdentity | undefined,
  remoteAddress: string | undefined,
): string | undefined {
  if (clientInfo === undefined && remoteAddress === undefined) return undefined;
  return createHash('sha256')
    .update([clientInfo?.name ?? '', clientInfo?.version ?? '', remoteAddress ?? ''].join(NUL))
    .digest('hex');
}

/** Whether `key` is a `session.key` this ladder implements. */
export function isSupportedSessionKey(key: string): boolean {
  return (
    key === 'auto' ||
    key === 'traceparent' ||
    key === 'connection' ||
    (key.startsWith('baggage:') && key.length > 'baggage:'.length)
  );
}

interface Binding {
  readonly sessionId: string;
  lastSeenAt: number;
}

/** How a resolver is built. */
export interface SessionKeyResolverOptions {
  /** The policy's `session.key`: `auto`, `traceparent`, `baggage:<name>` or `connection`. */
  readonly key: string;
  readonly idleTimeoutMs: number;
  /** The most bottom-rung bindings held at once. */
  readonly maxBindings: number;
  readonly clock: () => number;
  /** Mints the id of a new bottom-rung binding. */
  readonly newId?: (() => string) | undefined;
}

/** Runs the ladder for one gateway. */
export class SessionKeyResolver {
  readonly #key: string;
  readonly #idleTimeoutMs: number;
  readonly #maxBindings: number;
  readonly #clock: () => number;
  readonly #newId: () => string;
  readonly #bindings = new Map<string, Binding>();

  constructor(options: SessionKeyResolverOptions) {
    if (!isSupportedSessionKey(options.key)) {
      throw new Error(
        `session.key "${options.key}" is not supported: use auto, traceparent, baggage:<name> or connection`,
      );
    }
    this.#key = options.key;
    this.#idleTimeoutMs = options.idleTimeoutMs;
    this.#maxBindings = options.maxBindings;
    this.#clock = options.clock;
    this.#newId = options.newId ?? randomUUID;
  }

  /**
   * Resolves the session of one request, or `undefined` when the configured key
   * has nothing to say. That is not papered over with a fresh id: a call
   * attributed to a session that exists for that call alone turns every
   * combination rule into no rule, so the caller refuses the request.
   */
  resolve(input: SessionKeyInput): SessionKeyResolution | undefined {
    const key = this.#key;
    if (key === 'traceparent') {
      const traceId = traceIdOf(traceparentOf(input.meta));
      return traceId === undefined
        ? undefined
        : { sessionId: traceId, source: 'traceparent', exact: true };
    }
    if (key.startsWith('baggage:')) {
      const value = usableId(baggageEntry(input.meta, key.slice('baggage:'.length)));
      return value === undefined ? undefined : { sessionId: value, source: 'baggage', exact: true };
    }
    if (key === 'connection') {
      return input.mcpSessionId === undefined
        ? undefined
        : { sessionId: input.mcpSessionId, source: 'mcp-session-id', exact: true };
    }
    return this.#auto(input);
  }

  /** How many bottom-rung bindings are held. */
  get size(): number {
    return this.#bindings.size;
  }

  /** Drops the bindings idle past the timeout. Returns how many went. */
  sweep(): number {
    const now = this.#clock();
    let dropped = 0;
    for (const [key, binding] of this.#bindings) {
      if (now - binding.lastSeenAt < this.#idleTimeoutMs) continue;
      this.#bindings.delete(key);
      dropped += 1;
    }
    return dropped;
  }

  /** Forgets every binding, for shutdown. */
  clear(): void {
    this.#bindings.clear();
  }

  #auto(input: SessionKeyInput): SessionKeyResolution | undefined {
    const traceId = traceIdOf(traceparentOf(input.meta));
    if (traceId !== undefined) return { sessionId: traceId, source: 'traceparent', exact: true };

    // Above `Mcp-Session-Id` on purpose: a baggage member names one session for
    // the whole chain, the header only for this hop (ADR-006).
    const chained = usableId(baggageEntry(input.meta, SESSION_BAGGAGE_KEY));
    if (chained !== undefined) return { sessionId: chained, source: 'baggage', exact: true };

    if (input.mcpSessionId !== undefined) {
      return { sessionId: input.mcpSessionId, source: 'mcp-session-id', exact: true };
    }

    const addressKey = clientAddressKey(
      input.clientInfo ?? clientInfoOf(input.meta),
      input.remoteAddress,
    );
    if (addressKey === undefined) return undefined;

    this.sweep();
    const now = this.#clock();
    const existing = this.#bindings.get(addressKey);
    if (existing !== undefined) {
      existing.lastSeenAt = now;
      // Re-inserted, so iteration order is least recently seen first.
      this.#bindings.delete(addressKey);
      this.#bindings.set(addressKey, existing);
      return { sessionId: existing.sessionId, source: 'client-address', exact: false };
    }
    while (this.#bindings.size >= this.#maxBindings) {
      const oldest = this.#bindings.keys().next().value;
      if (oldest === undefined) break;
      this.#bindings.delete(oldest);
    }
    const sessionId = this.#newId();
    this.#bindings.set(addressKey, { sessionId, lastSeenAt: now });
    return { sessionId, source: 'client-address', exact: false };
  }
}
