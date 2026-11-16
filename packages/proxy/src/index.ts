/**
 * `@tunedness/mcpguard-proxy` — the MCP adapter.
 *
 * Three gates and one blind seam. `bridge.ts`, `era.ts`, `remap.ts` and
 * `diagnostics.ts` are kept free of both engine packages so the transport
 * skeleton stays liftable into a shared internal package later;
 * `boundary.test.ts` fails the build if that stops being true. `guard.ts` and
 * `content.ts` are the engine-facing half — where McpGuard rewrites the message
 * that AgentFuse only decides whether to forward.
 */
export type {
  Bridge,
  BridgedRequest,
  BridgeOptions,
  Gates,
  UpstreamPhase,
} from './bridge.js';
export { createBridge, PASSTHROUGH_RESULT } from './bridge.js';
export type { ResultLike, TextBlockRef } from './content.js';
export { extractText, replaceText } from './content.js';
export { DIAGNOSTIC_PREFIX, type DiagnosticSink, Diagnostics } from './diagnostics.js';
export {
  assertSameEra,
  type Era,
  EraMismatchError,
  eraOf,
  FIRST_MODERN_PROTOCOL_VERSION,
} from './era.js';
export type { GuardContext, GuardedResult } from './guard.js';
export { blockedResult, guardCall, guardResource, guardResult } from './guard.js';
export type { AuthResult, BearerAuthenticator, BearerToken } from './http-auth.js';
export { createBearerAuthenticator, hashToken, unauthorizedResponse } from './http-auth.js';
export type {
  GatewayCallInput,
  GatewayServer,
  GatewayTiming,
  HttpGateway,
  HttpGatewayOptions,
  ServerProbe,
} from './http-gateway.js';
export { createHttpGateway } from './http-gateway.js';
export { GATEWAY_ERROR, jsonRpcError } from './http-response.js';
export type { ListToolsOptions, ListUpstreamOptions } from './list-tools.js';
export { listAllTools, listStdioTools, listUpstreamTools } from './list-tools.js';
export type {
  FetchHandler,
  HttpEndpoint,
  HttpEndpointOptions,
  RequestContext,
} from './node-http.js';
export {
  DEFAULT_MAX_BODY_BYTES,
  DEFAULT_MAX_INFLIGHT,
  startHttpEndpoint,
} from './node-http.js';
export {
  BAGGAGE_META_KEY,
  baggageEntry,
  type ClientIdentity,
  clientInfoOf,
  injectSession,
  type MetaBag,
  SESSION_BAGGAGE_KEY,
  traceparentOf,
} from './remap.js';
export type {
  LadderSource,
  SessionKeyInput,
  SessionKeyResolution,
  SessionKeyResolverOptions,
} from './session-ladder.js';
export {
  clientAddressKey,
  isSupportedSessionKey,
  MAX_SESSION_ID_LENGTH,
  SessionKeyResolver,
  traceIdOf,
} from './session-ladder.js';
export type {
  ConnectionPoolOptions,
  DropReason,
  Lease,
  PooledSession,
  SessionPoolOptions,
} from './session-pool.js';
export { ConnectionPool, SessionPool } from './session-pool.js';
export type { WrapHandle, WrapOptions } from './stdio-wrap.js';
export { assertRunnable, wrapStdioServer } from './stdio-wrap.js';
export type { ConnectOptions, SharedUpstreamOptions, UpstreamTarget } from './upstream.js';
export {
  connectUpstream,
  endUpstreamSession,
  limitedFetch,
  SharedUpstream,
  UpstreamResponseTooLarge,
} from './upstream.js';
export { PROXY_VERSION } from './version.js';
