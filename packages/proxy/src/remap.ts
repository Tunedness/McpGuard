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

import { CLIENT_INFO_META_KEY, TRACEPARENT_META_KEY } from '@modelcontextprotocol/server';

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
    // Baggage comes off the wire: a member that is not valid percent-encoding is
    // skipped, never allowed to throw into the request that carried it.
    let value: string;
    try {
      value = decodeURIComponent(rest.join('=').split(';', 1)[0]?.trim() ?? '');
    } catch {
      continue;
    }
    if (value !== '') return value;
  }
  return undefined;
}

/**
 * Returns `_meta` with the session baggage member set to `sessionId`.
 *
 * If a baggage list is already present, the member is merged into it rather than
 * replacing it — a trace context travelling alongside must survive.
 *
 * What happens to a session member that is already there depends on who is
 * asking. By default it is left untouched: an inner proxy adopts the outer
 * proxy's answer, and re-injecting the same value is a no-op. With `replace`, the
 * existing member — whatever it holds, usable or not — is dropped and `sessionId`
 * written in its place. The outermost proxy needs that: it has already decided
 * which session the call belongs to (the ladder ranks `traceparent` above the
 * baggage and skips a baggage value it cannot use), so what the upstream is told
 * must be what its own audit record says, not whatever the caller wrote.
 */
export function injectSession(
  meta: MetaBag | undefined,
  sessionId: string,
  options: { readonly replace?: boolean } = {},
): MetaBag {
  const existing =
    typeof meta?.[BAGGAGE_META_KEY] === 'string' ? (meta[BAGGAGE_META_KEY] as string) : '';
  if (options.replace !== true && baggageEntry(meta, SESSION_BAGGAGE_KEY) !== undefined) {
    return { ...meta };
  }
  const kept =
    options.replace === true
      ? existing
          .split(',')
          .filter((member) => member.split('=', 1)[0]?.trim() !== SESSION_BAGGAGE_KEY)
          .join(',')
      : existing;
  const member = `${SESSION_BAGGAGE_KEY}=${encodeURIComponent(sessionId)}`;
  return { ...meta, [BAGGAGE_META_KEY]: kept === '' ? member : `${kept},${member}` };
}

/** The W3C `traceparent` a request carries on its `_meta`, if it carries one. */
export function traceparentOf(meta: MetaBag | undefined): string | undefined {
  const value = meta?.[TRACEPARENT_META_KEY];
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/** The trace and span a `traceparent` names, as lower-case hex. */
export interface ParsedTraceparent {
  readonly traceId: string;
  readonly spanId: string;
}

const TRACE_ID = /^[0-9a-f]{32}$/;
const SPAN_ID = /^[0-9a-f]{16}$/;
const HEX2 = /^[0-9a-f]{2}$/;
/** Version 00 is 55 characters; a later version may append fields, but not without bound. */
const MAX_TRACEPARENT_LENGTH = 512;

/**
 * Reads a W3C `traceparent` (`version-traceid-parentid-flags`, lower-case hex).
 *
 * The one reader of that header in the workspace: the session ladder's first
 * rung and the telemetry's trace ids both come from it, so a session that was
 * named by a trace id is always a record that carries that trace. A value that
 * is not well-formed gives `undefined`, never an error: an untrusted caller's
 * header is a reason to leave a correlation off, not to fail a request. All-zero
 * ids are invalid in the spec (and would merge every badly instrumented caller
 * into one session), version `ff` is forbidden, version `00` has exactly four
 * fields, and a later version is read by its first four, as the spec asks.
 */
export function parseTraceparent(value: unknown): ParsedTraceparent | undefined {
  if (typeof value !== 'string' || value.length > MAX_TRACEPARENT_LENGTH) return undefined;
  const parts = value.split('-');
  const [version = '', traceId = '', spanId = '', flags = ''] = parts;
  if (parts.length < 4 || !HEX2.test(version) || version === 'ff') return undefined;
  if (version === '00' && parts.length !== 4) return undefined;
  if (!HEX2.test(flags)) return undefined;
  if (!TRACE_ID.test(traceId) || /^0+$/.test(traceId)) return undefined;
  if (!SPAN_ID.test(spanId) || /^0+$/.test(spanId)) return undefined;
  return { traceId, spanId };
}

/** The self-reported identity of the software that made a request. */
export interface ClientIdentity {
  readonly name: string;
  readonly version?: string | undefined;
}

/**
 * The `clientInfo` a modern request declares on its envelope.
 *
 * A legacy connection declares it once, in `initialize`; the caller reads it
 * from there and hands it on.
 */
export function clientInfoOf(meta: MetaBag | undefined): ClientIdentity | undefined {
  const value = meta?.[CLIENT_INFO_META_KEY];
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const { name, version } = value as { name?: unknown; version?: unknown };
  if (typeof name !== 'string' || name === '') return undefined;
  return { name, ...(typeof version === 'string' ? { version } : {}) };
}
