import { createSocket } from 'node:dgram';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type AuditFields, parsePolicy, type SecurityEvent } from '@tunedness/mcpguard-core';
import { afterEach, describe, expect, it } from 'vitest';
import { AuditWriter } from '../audit-writer.js';
import { checkpointFailureReporter, checkpointSinkFor } from './sink.js';
import {
  formatSyslogMessage,
  parseSyslogTarget,
  SyslogCheckpointSink,
  type SyslogOptions,
} from './syslog.js';

/**
 * The syslog checkpoint sink: the line is RFC 5424, it reaches a real listener,
 * and no checkpoint ever goes missing without a trace. A failure never reaches
 * the audit writer as an exception and never passes without an `onError`, on
 * every transport.
 */

const AT = new Date('2026-11-17T10:20:30.456Z');
const RFC5424 =
  /^<(\d{1,3})>1 (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z) (\S+) (\S+) (\S+) (\S+) (-|\[.*?\]) (.*)$/s;

const cleanups: (() => void | Promise<void>)[] = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

/** Waits until `done` holds, or fails the test after `ms`. */
async function until(done: () => boolean, what: string, ms = 3_000): Promise<void> {
  const start = Date.now();
  while (!done()) {
    if (Date.now() - start > ms) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/** A UDP listener on a free loopback port; resolves each datagram it receives. */
async function udpListener(): Promise<{ port: number; next: () => Promise<string> }> {
  const socket = createSocket('udp4');
  const inbox: string[] = [];
  let waiting: ((message: string) => void) | undefined;
  socket.on('message', (buffer) => {
    const message = buffer.toString('utf8');
    if (waiting !== undefined) {
      const resolve = waiting;
      waiting = undefined;
      resolve(message);
    } else inbox.push(message);
  });
  await new Promise<void>((resolve) => socket.bind(0, '127.0.0.1', resolve));
  cleanups.push(() => {
    socket.close();
  });
  return {
    port: socket.address().port,
    next: () =>
      new Promise<string>((resolve, reject) => {
        const queued = inbox.shift();
        if (queued !== undefined) return resolve(queued);
        const timer = setTimeout(() => reject(new Error('no datagram within 2s')), 2_000);
        waiting = (message) => {
          clearTimeout(timer);
          resolve(message);
        };
      }),
  };
}

/** A UDP port nobody holds: bound to learn it, then released. */
async function deadUdpPort(): Promise<number> {
  const socket = createSocket('udp4');
  await new Promise<void>((resolve) => socket.bind(0, '127.0.0.1', resolve));
  const { port } = socket.address();
  await new Promise<void>((resolve) => socket.close(resolve));
  return port;
}

/** What a stream listener (TCP or unix) is: lines received, and a way to stop it. */
interface StreamListener {
  readonly lines: string[];
  /** The TCP port it listens on; 0 for a unix socket. */
  port: number;
  /** Hangs up on every connected client, as a restarting daemon would. */
  dropConnections(): Promise<void>;
  close(): Promise<void>;
}

/** Listens on `where` (a TCP port on loopback, or a socket path), collecting the lines it is sent. */
function streamListener(where: { port: number } | { path: string }): Promise<StreamListener> {
  const lines: string[] = [];
  const connections = new Set<Socket>();
  const server: Server = createServer((connection) => {
    connections.add(connection);
    connection.on('close', () => connections.delete(connection));
    let buffered = '';
    connection.on('data', (chunk) => {
      buffered += chunk.toString('utf8');
      for (;;) {
        const end = buffered.indexOf('\n');
        if (end < 0) break;
        lines.push(buffered.slice(0, end));
        buffered = buffered.slice(end + 1);
      }
    });
  });
  const listener: StreamListener & { port: number } = {
    lines,
    port: 0,
    dropConnections: async () => {
      for (const connection of connections) connection.destroy();
      await new Promise((resolve) => setTimeout(resolve, 20));
    },
    close: async () => {
      for (const connection of connections) connection.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    const ready = () => {
      const address = server.address();
      listener.port = typeof address === 'object' && address !== null ? address.port : 0;
      cleanups.push(() => listener.close().catch(() => {}));
      resolve(listener);
    };
    if ('port' in where) server.listen(where.port, '127.0.0.1', ready);
    else server.listen(where.path, ready);
  });
}

/** A TCP port nobody holds: listened on to learn it, then released. */
async function deadTcpPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

/**
 * A unix socket path in a fresh directory, or `undefined` where the environment
 * will not let a process bind one (a locked-down sandbox answers EPERM); the test
 * then skips and says why, rather than failing on something the code did not do.
 */
async function bindableUnixPath(): Promise<string | undefined> {
  const dir = mkdtempSync(join(tmpdir(), 'sl-'));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 's');
  const probe = createServer();
  try {
    await new Promise<void>((resolve, reject) => {
      probe.once('error', reject);
      probe.listen(path, resolve);
    });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'EPERM' || code === 'EACCES') return undefined;
    throw error;
  }
  await new Promise((resolve) => probe.close(resolve));
  return path;
}

function sinkTo(
  target: string,
  over: Partial<SyslogOptions> = {},
): { sink: SyslogCheckpointSink; errors: Error[] } {
  const errors: Error[] = [];
  const sink = new SyslogCheckpointSink({
    address: parseSyslogTarget(target),
    facility: 'authpriv',
    onError: (error) => errors.push(error),
    clock: () => AT.getTime(),
    hostname: 'host-1',
    ...over,
  });
  cleanups.push(() => sink.close());
  return { sink, errors };
}

const fieldsAt = (at: number): AuditFields => ({
  at,
  sessionId: 's',
  kind: 'tool_call',
  serverName: 'echo',
  toolName: 'echo',
  action: 'allow',
  score: undefined,
  findings: [],
  piiKinds: [],
  maskedContent: '',
  sessionExact: true,
  sessionSource: 'connection',
});

const BODY = JSON.stringify({ event: 'audit_checkpoint', seq: 1, head: 'ab'.repeat(32) });
const CHECKPOINT = `[mcpguard] ${BODY}\n`;

/** The MSG of a received line, parsed: syslog carries the checkpoint JSON and nothing else. */
function checkpointOf(line: string): { event: string; seq: number; head: string } {
  const message = RFC5424.exec(line)?.[8];
  expect(message).toBeDefined();
  return JSON.parse(message ?? '') as { event: string; seq: number; head: string };
}

describe('parseSyslogTarget', () => {
  it.each([
    ['udp://127.0.0.1:5514', { transport: 'udp', host: '127.0.0.1', port: 5514 }],
    ['udp://logs.example.com', { transport: 'udp', host: 'logs.example.com', port: 514 }],
    ['udp://[::1]:514', { transport: 'udp', host: '::1', port: 514 }],
    ['tcp://logs.example.com:601', { transport: 'tcp', host: 'logs.example.com', port: 601 }],
    ['tcp://127.0.0.1', { transport: 'tcp', host: '127.0.0.1', port: 514 }],
    ['unix:///run/mcpguard.sock', { transport: 'unix', path: '/run/mcpguard.sock' }],
  ])('reads %s', (target, expected) => {
    expect(parseSyslogTarget(target)).toEqual(expected);
  });

  it.each([
    'https://127.0.0.1:514',
    'udp://',
    'udp://host:0',
    'tcp://host:70000',
    'udp://host name',
    'unix:/run/mcpguard.sock',
    'unix://relative/path',
    'unix://',
    '/dev/log',
    '127.0.0.1:514',
    '',
  ])('refuses %j, naming the three forms', (target) => {
    expect(() => parseSyslogTarget(target)).toThrow(/syslog target/);
    expect(() => parseSyslogTarget(target)).toThrow(/udp:\/\/.*tcp:\/\/.*unix:\/\/\//);
  });

  it('accepts exactly what the policy schema accepts', () => {
    const targets = [
      'udp://127.0.0.1',
      'udp://h:65535',
      'tcp://h:514',
      'unix:///a',
      'unix:/a',
      'unix://a',
      'http://h',
      'udp://h:99999',
      '',
    ];
    const accepted = (run: () => unknown): boolean => {
      try {
        run();
        return true;
      } catch {
        return false;
      }
    };
    for (const target of targets) {
      const schemaOk = accepted(() =>
        parsePolicy({ version: 1, audit: { checkpoint_to: 'syslog', syslog: { target } } }),
      );
      expect([target, accepted(() => parseSyslogTarget(target))]).toEqual([target, schemaOk]);
    }
  });
});

describe('formatSyslogMessage', () => {
  const format = (message: string, over: Partial<Parameters<typeof formatSyslogMessage>[1]> = {}) =>
    formatSyslogMessage(message, { facility: 'authpriv', at: AT, hostname: 'host-1', ...over });

  it('is RFC 5424: PRI, version 1, UTC timestamp, host, app, nil procid, msgid, nil SD, message', () => {
    const line = format('hello');
    expect(line).toBe('<86>1 2026-11-17T10:20:30.456Z host-1 mcpguard - audit_checkpoint - hello');
    const match = RFC5424.exec(line);
    expect(match?.[1]).toBe('86');
    expect(match?.[8]).toBe('hello');
  });

  it('computes PRI as facility * 8 + 6 (informational)', () => {
    expect(format('x', { facility: 'local0' })).toMatch(/^<134>1 /);
    expect(format('x', { facility: 'daemon' })).toMatch(/^<30>1 /);
    expect(format('x', { facility: 'local7' })).toMatch(/^<190>1 /);
  });

  it('uses the nil value for a hostname that is not printable ASCII without spaces', () => {
    expect(format('x', { hostname: '' })).toContain(' - mcpguard ');
    expect(format('x', { hostname: 'bad host' })).toContain('Z - mcpguard ');
    expect(format('x', { hostname: 'ünï' })).toContain('Z - mcpguard ');
  });

  it('keeps one message to one line: control characters become spaces, the trailing newline goes', () => {
    const line = format('a\nb\r\nc\u0000d\n');
    expect(line.endsWith(' - a b c d')).toBe(true);
    expect(line.includes('\n') || line.includes('\r') || line.includes('\u0000')).toBe(false);
  });

  it('cuts a message that would not fit a datagram', () => {
    expect(Buffer.byteLength(format('x'.repeat(10_000)))).toBeLessThanOrEqual(2_048);
  });

  it('never exceeds the limit or splits a character, whichever byte the cut lands on', () => {
    // A 3-byte character at every offset: the cut lands on all three of its bytes in turn.
    for (let pad = 0; pad < 4; pad++) {
      const line = format(`${'x'.repeat(pad)}${'€'.repeat(2_000)}`);
      expect(Buffer.byteLength(line)).toBeLessThanOrEqual(2_048);
      expect(line).not.toContain('�');
    }
  });
});

describe('SyslogCheckpointSink over UDP', () => {
  it('delivers an RFC 5424 line whose MSG is the checkpoint JSON and nothing else', async () => {
    const listener = await udpListener();
    const { sink, errors } = sinkTo(`udp://127.0.0.1:${listener.port}`);

    expect(sink.write(CHECKPOINT)).toBe(true);

    const line = await listener.next();
    const match = RFC5424.exec(line);
    expect(match?.[1]).toBe('86');
    expect(match?.[2]).toBe('2026-11-17T10:20:30.456Z');
    expect(match?.[3]).toBe('host-1');
    expect(match?.[4]).toBe('mcpguard');
    expect(match?.[6]).toBe('audit_checkpoint');
    expect(match?.[8]?.startsWith('{')).toBe(true);
    expect(checkpointOf(line)).toEqual({
      event: 'audit_checkpoint',
      seq: 1,
      head: 'ab'.repeat(32),
    });
    expect(errors).toEqual([]);
  });

  it('is what AuditWriter publishes to every checkpoint_every records, and only then', async () => {
    const listener = await udpListener();
    const { sink } = sinkTo(`udp://127.0.0.1:${listener.port}`);
    const writer = new AuditWriter({
      path: '/unused',
      auditKey: undefined,
      checkpointEvery: 2,
      checkpoint: sink,
      append: () => {},
    });

    writer.record(fieldsAt(1), '');
    writer.record(fieldsAt(1), '');
    const body = checkpointOf(await listener.next());
    expect(body.seq).toBe(1);
    expect(body.head).toBe(writer.head);

    writer.record(fieldsAt(1), '');
    await expect(listener.next()).rejects.toThrow('no datagram');
  }, 10_000);

  it('reports a checkpoint sent to a port nobody holds, and the audit writer is undisturbed', async () => {
    const port = await deadUdpPort();
    const { sink, errors } = sinkTo(`udp://127.0.0.1:${port}`);
    const appended: string[] = [];
    const writer = new AuditWriter({
      path: '/unused',
      auditKey: undefined,
      checkpointEvery: 1,
      checkpoint: sink,
      append: (_path, line) => appended.push(line),
    });

    for (let i = 0; i < 3; i++) expect(() => writer.record(fieldsAt(i), '')).not.toThrow();
    await until(() => errors.length > 0, 'the refused port to be reported');

    // Not silent: the stack told us, and the report says which target.
    expect(errors[0]?.message).toContain(`udp://127.0.0.1:${port}`);
    expect((errors[0] as NodeJS.ErrnoException).code).toBe('ECONNREFUSED');
    // And no effect on the call: every record was appended.
    expect(appended).toHaveLength(3);
    expect(writer.count).toBe(3);
  });

  it('reports a checkpoint it could not format, and does not throw', () => {
    const { sink, errors } = sinkTo('udp://127.0.0.1:9', {
      clock: () => {
        throw new Error('the clock broke');
      },
    });

    expect(sink.write(CHECKPOINT)).toBe(false);
    expect(errors).toHaveLength(1);
    expect(errors[0]?.message).toContain('checkpoint dropped');
    expect(errors[0]?.message).toContain('the clock broke');
  });

  it('reports a write after close, and sends nothing', async () => {
    const listener = await udpListener();
    const { sink, errors } = sinkTo(`udp://127.0.0.1:${listener.port}`);
    sink.close();

    expect(sink.write(CHECKPOINT)).toBe(false);
    expect(errors).toHaveLength(1);
    expect(errors[0]?.message).toContain('closed');
    await expect(listener.next()).rejects.toThrow('no datagram');
  }, 10_000);

  it('survives an onError that throws', () => {
    const { sink } = sinkTo('udp://127.0.0.1:9', {
      onError: () => {
        throw new Error('reporter broke');
      },
      clock: () => {
        throw new Error('forces a report');
      },
    });
    expect(() => sink.write(CHECKPOINT)).not.toThrow();
  });
});

/**
 * A resolver the test controls: `failing` it says ENOTFOUND (what a DNS outage says),
 * `answering` it gives 127.0.0.1, `held` it keeps the callback until `release` is called.
 */
function controlledLookup() {
  let mode: 'failing' | 'answering' | 'held' = 'failing';
  const held: (() => void)[] = [];
  const calls = { count: 0 };
  const answer = (
    options: { all?: boolean },
    callback: (...args: never[]) => void,
    failure: boolean,
  ): void => {
    const cb = callback as unknown as (...args: unknown[]) => void;
    if (failure) {
      cb(Object.assign(new Error('getaddrinfo ENOTFOUND down.example'), { code: 'ENOTFOUND' }));
    } else if (options.all === true) cb(null, [{ address: '127.0.0.1', family: 4 }]);
    else cb(null, '127.0.0.1', 4);
  };
  const lookup = ((_host: string, options: { all?: boolean }, callback: never) => {
    calls.count++;
    if (mode === 'held') held.push(() => answer(options, callback, true));
    else answer(options, callback, mode === 'failing');
  }) as unknown as NonNullable<SyslogOptions['lookup']>;
  return {
    lookup,
    calls,
    setMode: (next: typeof mode) => {
      mode = next;
    },
    release: () => {
      for (const fire of held.splice(0)) fire();
    },
  };
}

const crashes: Error[] = [];
process.on('uncaughtException', (error) => crashes.push(error));
afterEach(() => {
  // An exception thrown from a socket callback has no `try` above it: it would end the process.
  expect(crashes.splice(0).map((e) => e.message)).toEqual([]);
});

describe('a target whose host does not resolve (the crash that took the process down)', () => {
  it('udp, a real unresolvable host: reports the lookup failure with its real cause and keeps the process up', async () => {
    const { sink, errors } = sinkTo('udp://nonexistent-host.invalid:514');

    expect(() => sink.write(CHECKPOINT)).not.toThrow();
    await until(() => errors.length > 0, 'the lookup failure to be reported', 8_000);

    // The cause, not a symptom of it: ERR_SOCKET_BAD_PORT is what a socket that never connected says.
    expect(errors.map((e) => (e as NodeJS.ErrnoException).code)).not.toContain(
      'ERR_SOCKET_BAD_PORT',
    );
    expect(errors[0]?.message).toContain('udp://nonexistent-host.invalid:514');
  }, 30_000);

  it.each(['udp', 'tcp'])(
    '%s, resolution fails: the real cause (ENOTFOUND) is reported for the failure and for the checkpoint it cost',
    async (scheme) => {
      const resolver = controlledLookup();
      const { sink, errors } = sinkTo(`${scheme}://down.example:514`, { lookup: resolver.lookup });

      expect(() => sink.write(CHECKPOINT)).not.toThrow();
      await until(() => errors.length >= 1, 'the lookup failure to be reported');

      expect(errors.some((e) => (e as NodeJS.ErrnoException).code === 'ENOTFOUND')).toBe(true);
      expect(errors.map((e) => (e as NodeJS.ErrnoException).code)).not.toContain(
        'ERR_SOCKET_BAD_PORT',
      );
      // One checkpoint lost, at least one report that says so.
      expect(errors.some((e) => /not (sent|delivered)/.test(e.message))).toBe(true);
    },
  );

  it('udp: recovers on the next checkpoint once resolution works, resolving afresh', async () => {
    const listener = await udpListener();
    const resolver = controlledLookup();
    const { sink, errors } = sinkTo(`udp://down.example:${listener.port}`, {
      lookup: resolver.lookup,
    });
    sink.write(CHECKPOINT);
    await until(() => errors.length > 0, 'the lookup failure to be reported');
    const lookupsBefore = resolver.calls.count;

    resolver.setMode('answering');
    expect(sink.write(CHECKPOINT)).toBe(true);

    expect(checkpointOf(await listener.next()).event).toBe('audit_checkpoint');
    expect(resolver.calls.count).toBeGreaterThan(lookupsBefore);
  });

  it('tcp: recovers on the next checkpoint once resolution works, resolving afresh', async () => {
    const server = await streamListener({ port: 0 });
    const resolver = controlledLookup();
    const { sink, errors } = sinkTo(`tcp://down.example:${server.port}`, {
      lookup: resolver.lookup,
    });
    sink.write(CHECKPOINT);
    await until(() => errors.length > 0, 'the lookup failure to be reported');

    resolver.setMode('answering');
    sink.write(CHECKPOINT);
    await until(() => server.lines.length === 1, 'the line after resolution recovered');
  });

  it('udp: a failure that comes later keeps working: every write after it gets a fresh attempt, one at a time', async () => {
    const resolver = controlledLookup();
    const { sink, errors } = sinkTo('udp://down.example:514', { lookup: resolver.lookup });

    for (let i = 1; i <= 3; i++) {
      sink.write(CHECKPOINT);
      await until(() => resolver.calls.count === i, `lookup attempt ${i}`);
      await until(() => errors.length >= i * 2, `the reports of attempt ${i}`);
    }

    // One lookup per checkpoint: a retry is driven by the next write, never by a loop of its own.
    expect(resolver.calls.count).toBe(3);
  });

  it('udp: bounds what waits on a connection that is being made, and reports every checkpoint it loses', async () => {
    const resolver = controlledLookup();
    resolver.setMode('held');
    const { sink, errors } = sinkTo('udp://slow.example:514', { lookup: resolver.lookup });

    for (let i = 0; i < 20; i++) sink.write(CHECKPOINT);
    // 16 wait, the other 4 are refused at once and said so.
    expect(errors.filter((e) => e.message.includes('queue full'))).toHaveLength(4);

    resolver.release();
    await until(
      () => errors.filter((e) => e.message.includes('not sent')).length >= 16,
      'the 16 waiting to be reported',
    );
    // 20 checkpoints, 20 reports that name one.
    expect(errors.filter((e) => /queue full|not sent/.test(e.message))).toHaveLength(20);
  });

  it('udp: a sink closed while a checkpoint waits reports it', async () => {
    const resolver = controlledLookup();
    resolver.setMode('held');
    const { sink, errors } = sinkTo('udp://slow.example:514', { lookup: resolver.lookup });
    sink.write(CHECKPOINT);
    sink.close();

    expect(errors.filter((e) => e.message.includes('closed before'))).toHaveLength(1);
    resolver.release();
    await new Promise((resolve) => setTimeout(resolve, 30));
  });
});

describe('SyslogCheckpointSink over TCP', () => {
  it('delivers one RFC 5424 line per checkpoint', async () => {
    const server = await streamListener({ port: 0 });
    const { sink, errors } = sinkTo(`tcp://127.0.0.1:${server.port}`);

    sink.write(CHECKPOINT);
    sink.write(CHECKPOINT);
    await until(() => server.lines.length === 2, 'two lines');

    for (const line of server.lines) {
      expect(RFC5424.exec(line)?.[1]).toBe('86');
      expect(checkpointOf(line).event).toBe('audit_checkpoint');
    }
    expect(errors).toEqual([]);
  });

  it('reports every checkpoint a refused connection cost, and does not throw', async () => {
    const port = await deadTcpPort();
    const { sink, errors } = sinkTo(`tcp://127.0.0.1:${port}`);

    for (let i = 0; i < 3; i++) expect(() => sink.write(CHECKPOINT)).not.toThrow();
    await until(() => errors.length >= 3, 'one report per lost checkpoint');

    expect(errors.every((e) => e.message.includes(`tcp://127.0.0.1:${port}`))).toBe(true);
    expect(errors.some((e) => (e as NodeJS.ErrnoException).code === 'ECONNREFUSED')).toBe(true);
  });

  it('reconnects on the next checkpoint once the listener is back', async () => {
    const port = await deadTcpPort();
    const { sink, errors } = sinkTo(`tcp://127.0.0.1:${port}`);
    sink.write(CHECKPOINT);
    await until(() => errors.length > 0, 'the refused connection to be reported');

    const server = await streamListener({ port });
    sink.write(CHECKPOINT);
    await until(() => server.lines.length === 1, 'the line after the listener returned');

    expect(checkpointOf(server.lines[0] ?? '').event).toBe('audit_checkpoint');
  });

  it('a connection dropped between checkpoints: the next one is delivered or reported, never neither, and the one after is delivered', async () => {
    const server = await streamListener({ port: 0 });
    const { sink, errors } = sinkTo(`tcp://127.0.0.1:${server.port}`);
    sink.write(CHECKPOINT);
    await until(() => server.lines.length === 1, 'the first line');

    await server.dropConnections();
    await new Promise((resolve) => setTimeout(resolve, 100));
    sink.write(CHECKPOINT);
    await until(
      () => server.lines.length + errors.length >= 2,
      'the second to be delivered or reported',
    );
    sink.write(CHECKPOINT);
    await until(() => server.lines.length >= 2, 'a later checkpoint to arrive after the drop');
  });

  it('reports a write after close', () => {
    const { sink, errors } = sinkTo('tcp://127.0.0.1:9');
    sink.close();

    expect(sink.write(CHECKPOINT)).toBe(false);
    expect(errors).toHaveLength(1);
    expect(errors[0]?.message).toContain('closed');
  });
});

describe('SyslogCheckpointSink over a unix socket', () => {
  it('delivers one RFC 5424 line per checkpoint', async (context) => {
    const path = await bindableUnixPath();
    if (path === undefined) {
      return context.skip('this environment does not allow binding a unix socket');
    }
    const server = await streamListener({ path });
    const { sink, errors } = sinkTo(`unix://${path}`);

    sink.write(CHECKPOINT);
    sink.write(CHECKPOINT);
    await until(() => server.lines.length === 2, 'two lines');

    for (const line of server.lines) expect(checkpointOf(line).event).toBe('audit_checkpoint');
    expect(errors).toEqual([]);
  });

  it('reports every checkpoint a missing socket cost, and does not throw', async () => {
    const { sink, errors } = sinkTo('unix:///nonexistent-dir/mcpguard.sock');

    for (let i = 0; i < 3; i++) expect(() => sink.write(CHECKPOINT)).not.toThrow();
    await until(() => errors.length >= 3, 'one report per lost checkpoint');

    expect(errors.every((e) => e.message.includes('unix:///nonexistent-dir/mcpguard.sock'))).toBe(
      true,
    );
    expect(errors.some((e) => (e as NodeJS.ErrnoException).code === 'ENOENT')).toBe(true);
  });

  it('reconnects on the next checkpoint once the listener is back', async (context) => {
    const path = await bindableUnixPath();
    if (path === undefined) {
      return context.skip('this environment does not allow binding a unix socket');
    }
    const { sink, errors } = sinkTo(`unix://${path}`);
    sink.write(CHECKPOINT);
    await until(() => errors.length > 0, 'the missing socket to be reported');

    const server = await streamListener({ path });
    sink.write(CHECKPOINT);
    await until(() => server.lines.length === 1, 'the line after the listener returned');
  });

  it('a connection dropped between checkpoints: the next one is delivered or reported, and a later one arrives', async (context) => {
    const path = await bindableUnixPath();
    if (path === undefined) {
      return context.skip('this environment does not allow binding a unix socket');
    }
    const server = await streamListener({ path });
    const { sink, errors } = sinkTo(`unix://${path}`);
    sink.write(CHECKPOINT);
    await until(() => server.lines.length === 1, 'the first line');

    await server.dropConnections();
    await new Promise((resolve) => setTimeout(resolve, 100));
    sink.write(CHECKPOINT);
    await until(
      () => server.lines.length + errors.length >= 2,
      'the second to be delivered or reported',
    );
    sink.write(CHECKPOINT);
    await until(() => server.lines.length >= 2, 'a later checkpoint to arrive after the drop');
  });

  it('reports a write after close', () => {
    const { sink, errors } = sinkTo('unix:///nonexistent-dir/mcpguard.sock');
    sink.close();

    expect(sink.write(CHECKPOINT)).toBe(false);
    expect(errors).toHaveLength(1);
  });
});

describe('no transport loses a checkpoint without a trace', () => {
  it.each([
    ['udp', async () => `udp://127.0.0.1:${await deadUdpPort()}`],
    ['tcp', async () => `tcp://127.0.0.1:${await deadTcpPort()}`],
    ['unix', async () => 'unix:///nonexistent-dir/mcpguard.sock'],
  ])(
    '%s: a dead target is reported, through the same hook the host wires to stderr and the security event',
    async (_name, target) => {
      const events: SecurityEvent[] = [];
      const lines: string[] = [];
      const report = checkpointFailureReporter({
        out: (event, detail) => lines.push(JSON.stringify({ event, ...detail })),
        telemetry: { emit: (event) => events.push(event) },
        clock: () => 1_000,
        sessionId: 'S',
        serverName: 'srv',
      });
      const { sink } = sinkTo(await target(), { onError: report });

      sink.write(CHECKPOINT);
      await until(() => events.length > 0, 'the failure to be reported');

      expect(lines[0]).toContain('"event":"checkpoint_error"');
      expect(events[0]).toMatchObject({
        type: 'security_event',
        kind: 'audit_checkpoint',
        action: 'checkpoint_failed',
        sessionId: 'S',
        serverName: 'srv',
      });
      expect(events[0]?.evidence[0]).toMatch(/^syslog\.[A-Z0-9_]+$/);
    },
  );
});

describe('checkpointFailureReporter', () => {
  const reporter = () => {
    const events: SecurityEvent[] = [];
    const lines: { event: string; detail: Record<string, unknown> }[] = [];
    const report = checkpointFailureReporter({
      out: (event, detail) => lines.push({ event, detail }),
      telemetry: { emit: (event) => events.push(event) },
      clock: () => 42,
      sessionId: 'S',
      serverName: '*',
    });
    return { report, events, lines };
  };

  it('writes the stderr line and the security event, with the error code as evidence', () => {
    const { report, events, lines } = reporter();
    const error = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });

    report(error);

    expect(lines).toEqual([
      {
        event: 'checkpoint_error',
        detail: { sink: 'syslog', code: 'ECONNREFUSED', message: 'connect ECONNREFUSED' },
      },
    ]);
    expect(events).toEqual([
      {
        type: 'security_event',
        kind: 'audit_checkpoint',
        at: 42,
        sessionId: 'S',
        serverName: '*',
        toolName: undefined,
        score: undefined,
        action: 'checkpoint_failed',
        evidence: ['syslog.ECONNREFUSED'],
      },
    ]);
  });

  it('does not put free text in the event: a code that is not an identifier becomes ERROR', () => {
    const { report, events } = reporter();
    report(Object.assign(new Error('x'), { code: 'bad code; <script>' }));
    report(new Error('no code'));

    expect(events.map((e) => e.evidence)).toEqual([['syslog.ERROR'], ['syslog.ERROR']]);
  });
});

describe('checkpointSinkFor', () => {
  const audit = (over: Record<string, unknown>) => parsePolicy({ version: 1, audit: over }).audit;
  const stderr = { write: () => true };

  it('gives stderr for stderr, nothing for none, and a syslog sink for syslog', () => {
    expect(checkpointSinkFor(audit({}), stderr, () => {})).toBe(stderr);
    expect(checkpointSinkFor(audit({ checkpoint_to: 'none' }), stderr, () => {})).toBeUndefined();
    const sink = checkpointSinkFor(
      audit({ checkpoint_to: 'syslog', syslog: { target: 'udp://127.0.0.1:514' } }),
      stderr,
      () => {},
    );
    expect(sink).toBeInstanceOf(SyslogCheckpointSink);
    (sink as SyslogCheckpointSink).close();
  });

  it('reaches the target the policy names, under the facility it names', async () => {
    const listener = await udpListener();
    const sink = checkpointSinkFor(
      audit({
        checkpoint_to: 'syslog',
        syslog: { target: `udp://127.0.0.1:${listener.port}`, facility: 'local3' },
      }),
      stderr,
      () => {},
    );
    cleanups.push(() => (sink as SyslogCheckpointSink).close());

    sink?.write(CHECKPOINT);

    expect(RFC5424.exec(await listener.next())?.[1]).toBe('158');
  });

  it('throws at startup on a syslog policy with no target, rather than run with a checkpoint that goes nowhere', () => {
    // The schema refuses this policy; this is the sink's own refusal, for a policy built by hand.
    const hand = { ...audit({}), checkpoint_to: 'syslog' as const };
    expect(() => checkpointSinkFor(hand, stderr, () => {})).toThrow(/syslog\.target is not set/);
  });
});
