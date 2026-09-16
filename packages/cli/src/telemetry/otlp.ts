/**
 * Building an OTLP/HTTP log record by hand.
 *
 * The umbrella's telemetry decision (ADR-007) keeps `@opentelemetry/*` out of
 * the tree: a security proxy's dependency surface should be short enough to
 * audit, and the OTLP log shape is a small, stable JSON. This module produces
 * that JSON; posting it is the exporter's job.
 *
 * The event names come from the shared `tunedness.*` vocabulary. `security_event`
 * is this tool's, reserved for it by the umbrella; a test keeps the sibling from
 * emitting it and this is the other side of that contract.
 */
import type { SecurityEvent } from '@mcpguard/core';

/** The OTLP attribute encoding: `{ key, value: { stringValue | intValue } }`. */
type OtlpAttribute = { key: string; value: Record<string, unknown> };

function str(value: string): { key: string; value: { stringValue: string } } {
  return { key: '', value: { stringValue: value } };
}

function attr(key: string, value: string | number | undefined): OtlpAttribute | undefined {
  if (value === undefined) return undefined;
  return typeof value === 'number'
    ? { key, value: { intValue: value } }
    : { key, value: { stringValue: value } };
}

/** One OTLP log record for one security event. */
export function toLogRecord(event: SecurityEvent, service: string): Record<string, unknown> {
  const attributes = [
    attr('event.name', `tunedness.${event.type}`),
    attr('tunedness.kind', event.kind),
    attr('tunedness.session_id', event.sessionId),
    attr('tunedness.server', event.serverName),
    attr('tunedness.tool', event.toolName),
    attr('tunedness.action', event.action),
    attr('tunedness.score', event.score),
    attr('tunedness.evidence', event.evidence.join(',')),
    attr('service.name', service),
  ].filter((a): a is OtlpAttribute => a !== undefined);

  return {
    timeUnixNano: `${event.at * 1_000_000}`,
    severityNumber: event.type === 'security_event' ? 13 : 9,
    severityText: event.type === 'security_event' ? 'WARN' : 'INFO',
    eventName: `tunedness.${event.type}`,
    body: str(event.kind).value,
    attributes,
  };
}

/** The full OTLP/HTTP logs payload wrapping a batch of records. */
export function toLogsPayload(
  records: readonly Record<string, unknown>[],
  service: string,
): unknown {
  return {
    resourceLogs: [
      {
        resource: { attributes: [{ key: 'service.name', value: { stringValue: service } }] },
        scopeLogs: [{ scope: { name: 'mcpguard' }, logRecords: records }],
      },
    ],
  };
}
