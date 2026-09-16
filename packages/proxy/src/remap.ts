/**
 * `_meta` helpers, including the one thing McpGuard does that AgentFuse does not:
 * it **injects** the session baggage member, because it is the outermost proxy.
 *
 * The chaining contract (ADR-006) is one baggage member: the outermost proxy
 * resolves the session and injects it, inner proxies adopt it. AgentFuse only
 * reads it. McpGuard, in front of the servers, is the one that puts it there.
 *
 * This module imports neither engine package. See `boundary.test.ts`.
 */

export const SESSION_BAGGAGE_KEY = 'tunedness.session-id';
export const BAGGAGE_META_KEY = 'io.modelcontextprotocol/baggage';

/** A loose `_meta` bag. */
export type MetaBag = Record<string, unknown>;

/** One member's value from a W3C `baggage` list, tolerant of malformed entries. */
export function baggageEntry(meta: MetaBag | undefined, name: string): string | undefined {
  const raw = meta?.[BAGGAGE_META_KEY];
  if (typeof raw !== 'string') return undefined;
  for (const member of raw.split(',')) {
    const [key, ...rest] = member.split('=');
    if (key?.trim() !== name || rest.length === 0) continue;
    const value = decodeURIComponent(rest.join('=').split(';', 1)[0]?.trim() ?? '');
    if (value !== '') return value;
  }
  return undefined;
}

/**
 * Returns `_meta` with the session baggage member set to `sessionId`.
 *
 * If a baggage list is already present, the member is merged into it rather than
 * replacing it — a trace context travelling alongside must survive. If the
 * member is already there (an inner proxy would see this), it is left untouched:
 * the outermost proxy's answer wins, and re-injecting the same value is a no-op.
 */
export function injectSession(meta: MetaBag | undefined, sessionId: string): MetaBag {
  const existing =
    typeof meta?.[BAGGAGE_META_KEY] === 'string' ? (meta[BAGGAGE_META_KEY] as string) : '';
  const already = baggageEntry(meta, SESSION_BAGGAGE_KEY);
  if (already !== undefined) return { ...meta };
  const member = `${SESSION_BAGGAGE_KEY}=${encodeURIComponent(sessionId)}`;
  const merged = existing === '' ? member : `${existing},${member}`;
  return { ...meta, [BAGGAGE_META_KEY]: merged };
}
