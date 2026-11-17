---
'@tunedness/mcpguard': minor
'@tunedness/mcpguard-core': minor
'@tunedness/mcpguard-proxy': minor
---

Two telemetry gaps closed, with no new dependency.

A request's W3C trace context now reaches the telemetry. A valid `_meta.traceparent` (or, on
`serve`, the `traceparent` header; `_meta` wins) is written to the OTLP log record's `traceId` and
`spanId`, so McpGuard's events join the caller's trace, and AgentFuse's, in one collector. A
malformed value is ignored and never throws. It correlates and nothing else: no decision reads it
and the audit record is unchanged. The session ladder's trace rung and the telemetry now read the
header with one parser, so a session named by a trace id is always a record that carries that trace;
as a consequence a `traceparent` that is not well-formed W3C (a zero span id, version `ff`, a
non-hex flags field) no longer names a session and falls to the next rung.

`audit.checkpoint_to: syslog` now works instead of being refused at startup. The chain-head
checkpoint goes out as an RFC 5424 line to `audit.syslog.target`, which is required and has no
default: `udp://127.0.0.1:514`, `tcp://logs.example.com:514` or `unix:///run/mcpguard/syslog.sock`
(a stream socket; `/dev/log` is a datagram socket Node cannot open). `validate` and startup refuse
a syslog policy with no target and show the three forms.

Delivery differs by transport, and the docs say so. UDP gives no delivery guarantee: with nothing
listening, a checkpoint can be lost; use `tcp://` or `unix://` when it must arrive. The UDP socket is
connected, so what the local stack learns (a refused loopback port, a failed lookup or send) comes
back as an error. For every transport, a failure never stops a call and is never silent: each
checkpoint that was refused, dropped or not delivered is written to stderr as `checkpoint_error` and
emitted as a `security_event` (`audit_checkpoint`, action `checkpoint_failed`).
A sink failure never takes the process down, whatever the transport: a host that does not resolve,
a refused connection, a connection dropped mid-write and a missing socket file are each reported
with their real cause, and the next checkpoint resolves and connects afresh. At most 16 checkpoints
wait on a UDP socket that is still connecting; the rest are dropped and reported.
