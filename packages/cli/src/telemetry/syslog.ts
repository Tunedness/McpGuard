/**
 * The syslog checkpoint sink: RFC 5424 lines to UDP, TCP or a unix socket.
 *
 * The chain head is published outside the audit file so a wholesale swap of the
 * file is caught (ADR-004). stderr is one place for that; a syslog daemon is the
 * other, and the one an operator can keep out of reach of whoever can write the
 * file. Hand-written, with `node:dgram` and `node:net`: an external syslog
 * library would be a dependency in a security proxy's tree for one `sendto`
 * (ADR-007's reasoning, applied here).
 *
 * Best-effort in one sense only: a failure never stops or delays a call. It is
 * never silent. Every path on which a checkpoint does not leave this process, or
 * is refused on the way, ends in `onError`, which the host turns into a stderr
 * line and a `security_event`. What each transport can and cannot tell:
 *
 * Nothing here may crash the process. Every callback and event handler a socket
 * can invoke after `write` has returned runs through `#report` and never throws,
 * because an exception there has no `try` above it and would end the agent's session.
 * After any failure the sink drops the dead socket, so the next checkpoint resolves
 * and connects afresh: the retry is one per checkpoint, never a loop and never a timer,
 * and at most `MAX_WAITING_LINES` lines wait on a connection that is being made.
 *
 * - `udp://host[:port]` — RFC 5426, one datagram per message. UDP has no
 *   delivery guarantee: if no one is listening on a remote host the checkpoint is
 *   lost and nothing here can know. The socket is *connected*, so what the local
 *   stack does learn (an ICMP port-unreachable, which loopback and most LANs
 *   return, a failed lookup, a failed send) comes back as an error and is
 *   reported. Use `tcp://` or `unix://` when the checkpoint must arrive.
 * - `tcp://host[:port]` — RFC 6587 non-transparent framing, one message per
 *   line. A refused or lost connection, a failed write or a peer that stops
 *   reading is reported, once per checkpoint it cost; the next checkpoint
 *   reconnects. A checkpoint that failed is not retried.
 * - `unix:///path` — the same over a unix **stream** socket. `/dev/log` is a
 *   datagram socket on Linux and macOS, which Node cannot open; to reach the
 *   local syslogd give it a TCP or UDP listener on loopback, or a stream socket.
 */
import { createSocket, type Socket as DatagramSocket } from 'node:dgram';
import { createConnection, isIP, type LookupFunction, type Socket as StreamSocket } from 'node:net';
import { hostname } from 'node:os';

/** Where the checkpoint goes. */
export type SyslogAddress =
  | { readonly transport: 'udp' | 'tcp'; readonly host: string; readonly port: number }
  | { readonly transport: 'unix'; readonly path: string };

/** The RFC 5424 facility numbers this sink can file a message under. */
const FACILITY_CODES = {
  daemon: 3,
  auth: 4,
  authpriv: 10,
  user: 1,
  local0: 16,
  local1: 17,
  local2: 18,
  local3: 19,
  local4: 20,
  local5: 21,
  local6: 22,
  local7: 23,
} as const;

/** A facility name the policy schema accepts. */
export type SyslogFacility = keyof typeof FACILITY_CODES;

/** Severity 6, informational: a checkpoint is routine, not a fault. */
const SEVERITY_INFORMATIONAL = 6;
const APP_NAME = 'mcpguard';
const MSGID = 'audit_checkpoint';
/** Past this a message is cut: a datagram has to fit and a checkpoint is far shorter. */
const MAX_MESSAGE_BYTES = 2_048;
/** What may queue on a stream whose peer has stopped reading, before writes are dropped (and reported). */
const MAX_QUEUED_BYTES = 64 * 1_024;
/** How many checkpoints may wait on a UDP socket that is still resolving and connecting; more are dropped, and reported. */
const MAX_WAITING_LINES = 16;
/** How long a stream may take to connect before the checkpoints waiting on it are given up on. */
const CONNECT_TIMEOUT_MS = 5_000;
/** The prefix the audit writer puts on the line it gives a sink; syslog's MSG is the JSON after it. */
const LINE_PREFIX = '[mcpguard] ';

/** What `parseSyslogTarget` and the policy schema both say when they refuse a target. */
export const SYSLOG_TARGET_FORMS =
  'udp://127.0.0.1:514, tcp://logs.example.com:514 or unix:///run/mcpguard/syslog.sock';

/**
 * Parses a policy's `audit.syslog.target`.
 *
 * @throws {Error} when it is none of `udp://host[:port]`, `tcp://host[:port]`
 *   and `unix:///absolute/path`.
 */
export function parseSyslogTarget(target: string): SyslogAddress {
  if (target.startsWith('unix://')) {
    const path = target.slice('unix://'.length);
    if (!path.startsWith('/') || path.length < 2 || /[\s\0]/.test(path)) {
      throw new Error(`syslog target "${target}" must be ${SYSLOG_TARGET_FORMS}`);
    }
    return { transport: 'unix', path };
  }
  const match = /^(udp|tcp):\/\/(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::([0-9]{1,5}))?$/.exec(
    target,
  );
  const [, scheme, rawHost, rawPort] = match ?? [];
  if (scheme === undefined || rawHost === undefined) {
    throw new Error(`syslog target "${target}" must be ${SYSLOG_TARGET_FORMS}`);
  }
  const host = rawHost.startsWith('[') ? rawHost.slice(1, -1) : rawHost;
  const port = rawPort === undefined ? 514 : Number(rawPort);
  if (port < 1 || port > 65_535) {
    throw new Error(
      `syslog target "${target}" must be ${SYSLOG_TARGET_FORMS}; the port is 1-65535`,
    );
  }
  return { transport: scheme as 'udp' | 'tcp', host, port };
}

/** The message cut to at most `max` bytes without splitting a character. */
function cutToBytes(message: string, max: number): string {
  const bytes = Buffer.from(message, 'utf8');
  if (bytes.length <= max) return message;
  // The first byte left out is a continuation byte when the cut is mid-character: step back to its start.
  let end = max;
  while (end > 0 && ((bytes[end] ?? 0) & 0xc0) === 0x80) end--;
  return bytes.subarray(0, end).toString('utf8');
}

/**
 * One RFC 5424 message: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG`.
 *
 * No structured data (`-`): MSG is the checkpoint's JSON document, so a receiver
 * has one thing to parse. The process id is `-` (the nil value) because this
 * layer has no business reading the process. Newlines and other control
 * characters in the message are replaced, so one checkpoint is one line, and
 * the whole is at most 2048 bytes.
 */
export function formatSyslogMessage(
  message: string,
  options: { readonly facility: SyslogFacility; readonly at: Date; readonly hostname: string },
): string {
  const pri = FACILITY_CODES[options.facility] * 8 + SEVERITY_INFORMATIONAL;
  // HOSTNAME is printable ASCII with no space, at most 255 characters; anything else is the nil value.
  const host = /^[\x21-\x7e]{1,255}$/.test(options.hostname) ? options.hostname : '-';
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what is being removed
  const body = message.replace(/[\x00-\x1f\x7f]+/g, ' ').trim();
  return cutToBytes(
    `<${pri}>1 ${options.at.toISOString()} ${host} ${APP_NAME} - ${MSGID} - ${body}`,
    MAX_MESSAGE_BYTES,
  );
}

/** How the sink is configured. */
export interface SyslogOptions {
  readonly address: SyslogAddress;
  readonly facility: SyslogFacility;
  /** Called with whatever went wrong, for every checkpoint that did not leave cleanly; the sink never throws. */
  readonly onError: (error: Error) => void;
  /** Injected so tests can pin the timestamp. */
  readonly clock?: (() => number) | undefined;
  readonly hostname?: string | undefined;
  /** Resolves host names; injected so a test can make resolution fail or succeed on demand. */
  readonly lookup?: LookupFunction | undefined;
}

/** The same error with where it happened in front of its message, and its `code` kept. */
function describe(prefix: string, error: unknown): Error {
  const cause = error instanceof Error ? error : new Error(String(error));
  const described = new Error(`${prefix}: ${cause.message}`);
  const code = (cause as NodeJS.ErrnoException).code;
  if (code !== undefined) (described as NodeJS.ErrnoException).code = code;
  return described;
}

/** A UDP socket, whether it has connected yet, and the lines waiting for it to. */
interface DatagramState {
  readonly socket: DatagramSocket;
  ready: boolean;
  /** Failed or closed: late events from the socket are ignored. */
  dead: boolean;
  /** Why it died, when it died of an error. */
  failure: unknown;
  readonly queue: string[];
}

/**
 * Publishes checkpoints to syslog. Shaped as a `CheckpointSink` so the audit
 * writer cannot tell it from stderr.
 */
export class SyslogCheckpointSink {
  readonly #options: SyslogOptions;
  readonly #label: string;
  #datagram: DatagramState | undefined;
  #stream: StreamSocket | undefined;
  #closed = false;

  constructor(options: SyslogOptions) {
    this.#options = options;
    const a = options.address;
    this.#label =
      a.transport === 'unix' ? `unix://${a.path}` : `${a.transport}://${a.host}:${a.port}`;
  }

  /**
   * Hands one checkpoint to the transport. The `[mcpguard] ` prefix and the
   * trailing newline of the stderr form are not part of the message. True means
   * accepted for sending; what happens after is reported through `onError`.
   */
  write(chunk: string): boolean {
    if (this.#closed) {
      this.#report(new Error(`syslog sink for ${this.#label} is closed; checkpoint dropped`));
      return false;
    }
    try {
      const message = chunk.startsWith(LINE_PREFIX) ? chunk.slice(LINE_PREFIX.length) : chunk;
      const line = formatSyslogMessage(message, {
        facility: this.#options.facility,
        at: new Date(this.#options.clock?.() ?? Date.now()),
        hostname: this.#options.hostname ?? hostname(),
      });
      const address = this.#options.address;
      if (address.transport === 'udp') this.#sendDatagram(address, line);
      else this.#sendStream(address, line);
      return true;
    } catch (error) {
      this.#report(describe(`syslog ${this.#label}: checkpoint dropped`, error));
      return false;
    }
  }

  /** Releases the sockets. Later writes are dropped, and reported. */
  close(): void {
    this.#closed = true;
    for (const _lost of this.#datagram?.queue.splice(0) ?? []) {
      this.#report(new Error(`syslog ${this.#label}: closed before the checkpoint was sent`));
    }
    if (this.#datagram !== undefined) {
      this.#datagram.dead = true;
      try {
        this.#datagram.socket.close();
      } catch {
        // Already closed by an error: nothing left to release.
      }
    }
    this.#stream?.destroy();
    this.#datagram = undefined;
    this.#stream = undefined;
  }

  #report(error: Error): void {
    try {
      this.#options.onError(error);
    } catch {
      // A reporter that throws must not take the audit writer down with it.
    }
  }

  #sendDatagram(address: { readonly host: string; readonly port: number }, line: string): void {
    let state = this.#datagram;
    if (state === undefined) state = this.#openDatagram(address);
    if (state.failure !== undefined) {
      // The socket failed while it was being opened (a lookup that fails at once): this
      // checkpoint was not on its queue yet, so say here that it is lost.
      this.#report(describe(`syslog ${this.#label}: checkpoint not sent`, state.failure));
    } else if (state.ready) this.#sendNow(state, line);
    else if (state.queue.length >= MAX_WAITING_LINES) {
      this.#report(
        new Error(`syslog ${this.#label}: still connecting; checkpoint dropped (queue full)`),
      );
    } else state.queue.push(line);
  }

  /** A fresh connected socket; lines wait on it until it is connected. */
  #openDatagram(address: { readonly host: string; readonly port: number }): DatagramState {
    const socket = createSocket({
      type: isIP(address.host) === 6 ? 'udp6' : 'udp4',
      ...(this.#options.lookup !== undefined
        ? { lookup: this.#options.lookup as unknown as undefined }
        : {}),
    });
    const state: DatagramState = {
      socket,
      ready: false,
      dead: false,
      failure: undefined,
      queue: [],
    };
    this.#datagram = state;
    // Connected, the socket hears of an ICMP port-unreachable as an 'error' event; unconnected, never.
    socket.on('error', (error) => this.#failDatagram(state, error));
    // The sink alone must not keep the process alive.
    socket.unref();
    // `connect` reports a failed lookup to its callback, not as an 'error' event, and a connected
    // socket may only send once connected; until then lines wait in `state.queue`.
    const timer = setTimeout(
      () =>
        this.#failDatagram(state, new Error(`connecting timed out after ${CONNECT_TIMEOUT_MS}ms`)),
      CONNECT_TIMEOUT_MS,
    );
    timer.unref();
    try {
      socket.connect(address.port, address.host, (error?: unknown) => {
        clearTimeout(timer);
        if (state.dead) return;
        if (error !== undefined && error !== null) {
          this.#failDatagram(state, error);
          return;
        }
        state.ready = true;
        for (const waiting of state.queue.splice(0)) this.#sendNow(state, waiting);
      });
    } catch (error) {
      clearTimeout(timer);
      this.#failDatagram(state, error);
    }
    return state;
  }

  /**
   * Ends a datagram socket for good and says why: once for the failure, and once more for every
   * checkpoint that was waiting on it. The next write opens a new socket, which resolves again.
   */
  #failDatagram(state: DatagramState, cause: unknown): void {
    if (state.dead) return;
    state.dead = true;
    state.failure = cause;
    if (this.#datagram === state) this.#datagram = undefined;
    this.#report(describe(`syslog ${this.#label}`, cause));
    for (const _lost of state.queue.splice(0)) {
      this.#report(describe(`syslog ${this.#label}: checkpoint not sent`, cause));
    }
    try {
      state.socket.close();
    } catch {
      // Already closed: nothing left to release.
    }
  }

  #sendNow(state: DatagramState, line: string): void {
    try {
      state.socket.send(line, (error) => {
        if (error !== null) {
          this.#report(describe(`syslog ${this.#label}: checkpoint not sent`, error));
        }
      });
    } catch (error) {
      // A send that throws is a socket that cannot be used again: report it and start over next time.
      this.#report(describe(`syslog ${this.#label}: checkpoint not sent`, error));
      this.#failDatagram(state, error);
    }
  }

  #sendStream(address: SyslogAddress, line: string): void {
    let socket = this.#stream;
    if (socket === undefined || socket.destroyed) {
      const fresh =
        address.transport === 'unix'
          ? createConnection({ path: address.path })
          : createConnection({
              host: address.host,
              port: address.port,
              ...(this.#options.lookup !== undefined ? { lookup: this.#options.lookup } : {}),
            });
      // Resolution, refusal and a dropped connection all arrive here; the dead socket is dropped,
      // so the next checkpoint resolves and connects afresh.
      fresh.on('error', (error) => {
        this.#report(describe(`syslog ${this.#label}`, error));
        fresh.destroy();
        if (this.#stream === fresh) this.#stream = undefined;
      });
      // A peer that never answers must not hold checkpoints forever: give up, and say so.
      fresh.setTimeout(CONNECT_TIMEOUT_MS, () =>
        fresh.destroy(new Error(`connecting timed out after ${CONNECT_TIMEOUT_MS}ms`)),
      );
      fresh.once('connect', () => fresh.setTimeout(0));
      fresh.unref();
      this.#stream = fresh;
      socket = fresh;
    }
    if (socket.writableLength > MAX_QUEUED_BYTES) {
      throw new Error('the socket is not draining');
    }
    // Per write, so every checkpoint a failed connection costs is accounted for.
    socket.write(`${line}\n`, (error) => {
      if (error !== null && error !== undefined) {
        this.#report(describe(`syslog ${this.#label}: checkpoint not delivered`, error));
      }
    });
  }
}
