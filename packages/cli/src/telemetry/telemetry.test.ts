import type { SecurityEvent } from '@mcpguard/core';
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
