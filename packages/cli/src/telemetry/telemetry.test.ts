import type { SecurityEvent } from '@tunedness/mcpguard-core';
import { parseTraceparent } from '@tunedness/mcpguard-proxy';
import { describe, expect, it } from 'vitest';
import { toLogRecord, toLogsPayload } from './otlp.js';
import { NULL_TELEMETRY, OtlpTelemetrySink } from './sink.js';

/**
 * The hand-written OTLP path (ADR-007). The record shape is checked because a
 * collector will reject a malformed one silently, and the sink is checked for
 * the one promise it must keep: telemetry can never block or crash a call.
 */

function event(over: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    type: 'security_event',
    kind: 'injection_detected',
    at: 1_700_000_000_000,
    sessionId: 'sess-1',
    serverName: 'web',
    toolName: 'fetch',
    score: 80,
    action: 'flag',
    evidence: ['inj.en.override.ignore-previous'],
    ...over,
  };
}

describe('toLogRecord', () => {
  it('names the event in the tunedness vocabulary', () => {
    const record = toLogRecord(event(), 'mcpguard');
    expect(record.eventName).toBe('tunedness.security_event');
    const attrs = record.attributes as { key: string; value: Record<string, unknown> }[];
    expect(attrs.find((a) => a.key === 'tunedness.action')?.value).toEqual({ stringValue: 'flag' });
    expect(attrs.find((a) => a.key === 'tunedness.score')?.value).toEqual({ intValue: 80 });
  });

  it('carries the judge model, outcome and effect when the judge was asked, and nothing when not', () => {
    const attrs = (over: Partial<SecurityEvent>) =>
      toLogRecord(event(over), 'mcpguard').attributes as { key: string; value: unknown }[];
    const judged = attrs({
      judge: { model: 'qwen3:4b', outcome: 'injection', effect: 'raised_to_flag' },
    });
    expect(judged.find((a) => a.key === 'tunedness.judge_model')?.value).toEqual({
      stringValue: 'qwen3:4b',
    });
    expect(judged.find((a) => a.key === 'tunedness.judge_outcome')?.value).toEqual({
      stringValue: 'injection',
    });
    expect(judged.find((a) => a.key === 'tunedness.judge_effect')?.value).toEqual({
      stringValue: 'raised_to_flag',
    });
    expect(attrs({}).some((a) => a.key.startsWith('tunedness.judge_'))).toBe(false);
  });

  it('encodes a timestamp in nanoseconds', () => {
    expect(toLogRecord(event(), 'mcpguard').timeUnixNano).toBe('1700000000000000000');
  });

  it('omits an attribute whose value is absent', () => {
    const record = toLogRecord(event({ toolName: undefined, score: undefined }), 'mcpguard');
    const attrs = record.attributes as { key: string }[];
    expect(attrs.some((a) => a.key === 'tunedness.tool')).toBe(false);
    expect(attrs.some((a) => a.key === 'tunedness.score')).toBe(false);
  });
});

describe('toLogRecord caller identity', () => {
  const attrsOf = (over: Partial<SecurityEvent>) =>
    toLogRecord(event(over), 'mcpguard').attributes as {
      key: string;
      value: Record<string, unknown>;
    }[];

  it('carries the resolution and the rejection note, so none is told from rejected', () => {
    const rejected = attrsOf({
      callerIdentity: {
        identity: undefined,
        source: 'none',
        exact: false,
        note: 'client_info_rejected',
      },
    });
    expect(rejected.find((a) => a.key === 'tunedness.identity_source')?.value).toEqual({
      stringValue: 'none',
    });
    expect(rejected.find((a) => a.key === 'tunedness.identity_note')?.value).toEqual({
      stringValue: 'client_info_rejected',
    });

    const plain = attrsOf({
      callerIdentity: { identity: undefined, source: 'none', exact: false },
    });
    expect(plain.some((a) => a.key === 'tunedness.identity_note')).toBe(false);
  });
});

describe('toLogRecord session attribution', () => {
  const attrsOf = (over: Partial<SecurityEvent>) =>
    toLogRecord(event(over), 'mcpguard').attributes as {
      key: string;
      value: Record<string, unknown>;
    }[];

  it('says which rung resolved the session and whether that is exact (ADR-006)', () => {
    const guessed = attrsOf({ sessionSource: 'client-address', sessionExact: false });
    expect(guessed.find((a) => a.key === 'tunedness.session_source')?.value).toEqual({
      stringValue: 'client-address',
    });
    expect(guessed.find((a) => a.key === 'tunedness.session_exact')?.value).toEqual({
      stringValue: 'false',
    });
    const token = attrsOf({ callerIdentity: { identity: 'alice', source: 'token', exact: true } });
    expect(token.find((a) => a.key === 'tunedness.identity_source')?.value).toEqual({
      stringValue: 'token',
    });
  });

  it('omits both for an event that does not carry them', () => {
    const plain = attrsOf({});
    expect(plain.some((a) => a.key === 'tunedness.session_source')).toBe(false);
    expect(plain.some((a) => a.key === 'tunedness.session_exact')).toBe(false);
  });
});

describe('toLogsPayload', () => {
  it('wraps records in the OTLP resourceLogs envelope', () => {
    const payload = toLogsPayload([toLogRecord(event(), 'mcpguard')], 'mcpguard') as {
      resourceLogs: { scopeLogs: { logRecords: unknown[] }[] }[];
    };
    expect(payload.resourceLogs[0]?.scopeLogs[0]?.logRecords).toHaveLength(1);
  });
});

describe('OtlpTelemetrySink', () => {
  it('batches and flushes to the poster', async () => {
    const posted: unknown[] = [];
    const sink = new OtlpTelemetrySink({
      service: 'mcpguard',
      post: async (p) => void posted.push(p),
      batchSize: 2,
    });
    sink.emit(event());
    expect(posted).toHaveLength(0); // not yet full
    sink.emit(event());
    // The batch filled and flushed. Give the microtask a turn.
    await Promise.resolve();
    expect(posted).toHaveLength(1);
  });

  it('never throws at the caller when the collector fails', async () => {
    let reported: Error | undefined;
    const sink = new OtlpTelemetrySink({
      service: 'mcpguard',
      post: async () => {
        throw new Error('collector down');
      },
      onError: (e) => {
        reported = e;
      },
    });
    sink.emit(event());
    // The emit does not throw; the failure surfaces on flush, reported not raised.
    await expect(sink.flush()).resolves.toBeUndefined();
    expect(reported?.message).toBe('collector down');
  });

  it('the null sink accepts events and does nothing', () => {
    expect(() => NULL_TELEMETRY.emit(event())).not.toThrow();
  });
});

describe('parseTraceparent', () => {
  const TRACE = '4bf92f3577b34da6a3ce929d0e0e4736';
  const SPAN = '00f067aa0ba902b7';

  it('reads the trace and span ids of a version 00 value', () => {
    expect(parseTraceparent(`00-${TRACE}-${SPAN}-01`)).toEqual({ traceId: TRACE, spanId: SPAN });
    expect(parseTraceparent(`00-${TRACE}-${SPAN}-00`)).toEqual({ traceId: TRACE, spanId: SPAN });
  });

  it('reads a later version by its first four fields, as the spec asks', () => {
    expect(parseTraceparent(`01-${TRACE}-${SPAN}-01-extra-fields`)).toEqual({
      traceId: TRACE,
      spanId: SPAN,
    });
  });

  it.each([
    ['not a string', 42],
    ['undefined', undefined],
    ['empty', ''],
    ['too few fields', `00-${TRACE}-${SPAN}`],
    ['version 00 with a fifth field', `00-${TRACE}-${SPAN}-01-extra`],
    ['version ff', `ff-${TRACE}-${SPAN}-01`],
    ['upper-case hex', `00-${TRACE.toUpperCase()}-${SPAN}-01`],
    ['all-zero trace id', `00-${'0'.repeat(32)}-${SPAN}-01`],
    ['all-zero span id', `00-${TRACE}-${'0'.repeat(16)}-01`],
    ['short trace id', `00-${TRACE.slice(1)}-${SPAN}-01`],
    ['long span id', `00-${TRACE}-${SPAN}0-01`],
    ['non-hex flags', `00-${TRACE}-${SPAN}-zz`],
    ['non-hex version', `0g-${TRACE}-${SPAN}-01`],
    ['oversized', `01-${TRACE}-${SPAN}-01-${'a'.repeat(600)}`],
  ])('ignores %s, without throwing', (_name, value) => {
    expect(parseTraceparent(value)).toBeUndefined();
  });
});

describe('toLogRecord trace context', () => {
  it('writes traceId and spanId when the event carries a trace', () => {
    const record = toLogRecord(
      event({ trace: { traceId: 'a'.repeat(32), spanId: 'b'.repeat(16) } }),
      'mcpguard',
    );
    expect(record.traceId).toBe('a'.repeat(32));
    expect(record.spanId).toBe('b'.repeat(16));
  });

  it('writes neither field when it does not', () => {
    const record = toLogRecord(event(), 'mcpguard');
    expect('traceId' in record).toBe(false);
    expect('spanId' in record).toBe(false);
  });

  it('puts the same traceId in the payload a sink posts', async () => {
    const posted: unknown[] = [];
    const sink = new OtlpTelemetrySink({
      service: 'mcpguard',
      post: async (payload) => {
        posted.push(payload);
      },
    });
    sink.emit(event({ trace: { traceId: 'c'.repeat(32), spanId: 'd'.repeat(16) } }));
    await sink.flush();

    const payload = posted[0] as {
      resourceLogs: { scopeLogs: { logRecords: { traceId?: string }[] }[] }[];
    };
    expect(payload.resourceLogs[0]?.scopeLogs[0]?.logRecords[0]?.traceId).toBe('c'.repeat(32));
  });
});
