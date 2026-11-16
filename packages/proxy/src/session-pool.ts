/**
 * The gateway's session state and how it is bounded (ADR-006, ADR-011).
 *
 * Two different things get called "session" over HTTP, and they are bounded
 * differently:
 *
 * - **Attribution** answers "which task is this call part of". The ladder's top
 *   rungs need no memory at all — the caller declared the session on the request
 *   — so only the bottom rung, a guess from `clientInfo` and the peer's address,
 *   is stored. That table is shared by every server of the gateway: one client
 *   talking to two servers is one task, which is the whole point of a
 *   combination rule that spans them. A guess is capped by `max_sessions` and
 *   expires with `idle_timeout`; an exact session is never stored here and so
 *   never evicted by anything.
 * - **Connections** answer "which upstream `Client` carries this call". A legacy
 *   downstream session owns one upstream connection (for a stdio server, one
 *   child process), so this is the expensive thing. Each server has its own
 *   {@link ConnectionPool}: a full pool refuses a new session and never evicts an
 *   existing one, and a session idle past `idle_timeout` is closed even if its
 *   client never sent `DELETE`, because an idle child process is a leak. A
 *   session with a call in flight is never idle.
 *
 * There are no per-entry timers. Expiry is read against an injected clock, by
 * one low-frequency sweeper for the whole gateway and lazily on the way in, so a
 * test drives it with a fake clock and nothing here keeps the process alive.
 *
 * This module imports neither engine package. See `boundary.test.ts`.
 */
import { SessionKeyResolver, type SessionKeyResolverOptions } from './session-ladder.js';

/** Why a connection left its pool. */
export type DropReason = 'idle' | 'deleted' | 'closed';

/** What the pool needs to know about a connection it holds. */
export interface PooledSession {
  /** The token identity that opened it; the session id is no use to anyone else. */
  readonly owner: string | undefined;
  /** Calls being served right now. A session with any is not idle. */
  inflight: number;
  /** When it was last used or finished a call, on the pool's clock. */
  lastSeenAt: number;
}

/** How a connection pool is built. */
export interface ConnectionPoolOptions<S extends PooledSession> {
  /** The most connections held, counting those still being opened. */
  readonly maxConnections: number;
  /** A connection idle this long is dropped. */
  readonly idleTimeoutMs: number;
  readonly clock: () => number;
  /** Called once for every connection that leaves the pool, to close what it holds. */
  readonly onDrop: (session: S, why: DropReason) => void;
}

/** A connection in use: end it when the response has been read out. */
export interface Lease<S extends PooledSession> {
  readonly session: S;
  /** Idempotent. */
  done(): void;
}

/** The legacy connections of one server. */
export class ConnectionPool<S extends PooledSession> {
  readonly #options: ConnectionPoolOptions<S>;
  readonly #byId = new Map<string, S>();
  #opening = 0;

  constructor(options: ConnectionPoolOptions<S>) {
    this.#options = options;
  }

  /** Connections held plus those being opened. */
  get size(): number {
    return this.#byId.size + this.#opening;
  }

  /**
   * Claims room for one connection that is about to be opened, or answers
   * `undefined` when the pool is full. Nothing already held is evicted to make
   * room: whoever is using a connection is in the middle of something.
   *
   * The claim is released by the returned function, whether the connection came
   * up or not; once it has been {@link add}ed it counts as held.
   */
  reserve(): (() => void) | undefined {
    if (this.size >= this.#options.maxConnections) return undefined;
    this.#opening += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.#opening -= 1;
    };
  }

  /** Holds a connection under the id the downstream knows it by. */
  add(id: string, session: S): void {
    session.lastSeenAt = this.#options.clock();
    this.#byId.set(id, session);
  }

  /**
   * Starts using a connection, if `id` is one of this pool's and belongs to
   * `owner`. An unknown id and someone else's are the same answer.
   */
  use(id: string, owner: string | undefined): Lease<S> | undefined {
    const session = this.#byId.get(id);
    if (session === undefined || session.owner !== owner) return undefined;
    session.inflight += 1;
    session.lastSeenAt = this.#options.clock();
    let finished = false;
    return {
      session,
      done: () => {
        if (finished) return;
        finished = true;
        session.inflight -= 1;
        session.lastSeenAt = this.#options.clock();
      },
    };
  }

  /** Whether `session` is still the connection held under `id`. */
  holds(id: string | undefined, session: S): boolean {
    return id !== undefined && this.#byId.get(id) === session;
  }

  /** Removes a connection and reports it dropped. False when it was not held (or already gone). */
  drop(id: string | undefined, session: S, why: DropReason): boolean {
    if (!this.holds(id, session) || id === undefined) return false;
    this.#byId.delete(id);
    this.#options.onDrop(session, why);
    return true;
  }

  /** Drops the connections idle past the timeout and not in the middle of a call. Returns how many went. */
  sweep(): number {
    const now = this.#options.clock();
    let dropped = 0;
    for (const [id, session] of [...this.#byId]) {
      if (session.inflight > 0 || now - session.lastSeenAt < this.#options.idleTimeoutMs) continue;
      if (this.drop(id, session, 'idle')) dropped += 1;
    }
    return dropped;
  }

  /** Empties the pool without reporting each drop, and returns what it held, for shutdown. */
  drain(): S[] {
    const held = [...this.#byId.values()];
    this.#byId.clear();
    return held;
  }
}

/** How a session pool is built. */
export interface SessionPoolOptions
  extends Pick<SessionKeyResolverOptions, 'key' | 'idleTimeoutMs' | 'maxBindings'> {
  readonly clock: () => number;
  /** How often the sweeper runs; by default half the idle timeout, between 1 s and 60 s. */
  readonly sweepEveryMs?: number | undefined;
}

/** The session state of a whole gateway: one attribution table, a connection pool per server. */
export class SessionPool {
  /** The ladder every server's calls are attributed by. */
  readonly resolver: SessionKeyResolver;
  readonly #options: SessionPoolOptions;
  readonly #pools: { sweep(): number }[] = [];
  #timer: ReturnType<typeof setInterval> | undefined;

  constructor(options: SessionPoolOptions) {
    this.#options = options;
    this.resolver = new SessionKeyResolver({
      key: options.key,
      idleTimeoutMs: options.idleTimeoutMs,
      maxBindings: options.maxBindings,
      clock: options.clock,
    });
  }

  /** Makes the connection pool of one server, swept with the rest. */
  connections<S extends PooledSession>(
    options: Pick<ConnectionPoolOptions<S>, 'maxConnections' | 'onDrop'>,
  ): ConnectionPool<S> {
    const pool = new ConnectionPool<S>({
      ...options,
      idleTimeoutMs: this.#options.idleTimeoutMs,
      clock: this.#options.clock,
    });
    this.#pools.push(pool);
    return pool;
  }

  /** Expires what has been idle too long, everywhere. Returns how many entries went. */
  sweep(): number {
    let dropped = this.resolver.sweep();
    for (const pool of this.#pools) dropped += pool.sweep();
    return dropped;
  }

  /** Starts the sweeper. It never keeps the process alive. */
  start(): void {
    if (this.#timer !== undefined) return;
    const every =
      this.#options.sweepEveryMs ??
      Math.max(1_000, Math.min(60_000, Math.floor(this.#options.idleTimeoutMs / 2)));
    this.#timer = setInterval(() => this.sweep(), every);
    this.#timer.unref();
  }

  /** Stops the sweeper and forgets every guess. */
  close(): void {
    if (this.#timer !== undefined) clearInterval(this.#timer);
    this.#timer = undefined;
    this.resolver.clear();
  }
}
