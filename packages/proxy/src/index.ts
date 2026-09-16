/**
 * `@mcpguard/proxy` — the MCP adapter.
 *
 * Three gates and one blind seam. `bridge.ts`, `era.ts`, `remap.ts` and
 * `diagnostics.ts` are kept free of both engine packages so the transport
 * skeleton stays liftable into a shared internal package later;
 * `boundary.test.ts` fails the build if that stops being true. `guard.ts` and
 * `content.ts` are the engine-facing half — where McpGuard rewrites the message
 * that AgentFuse only decides whether to forward.
 */
export type { Bridge, BridgeOptions, Gates } from './bridge.js';
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
export {
  BAGGAGE_META_KEY,
  baggageEntry,
  injectSession,
  type MetaBag,
  SESSION_BAGGAGE_KEY,
} from './remap.js';
export type { WrapHandle, WrapOptions } from './stdio-wrap.js';
export { wrapStdioServer } from './stdio-wrap.js';
export { PROXY_VERSION } from './version.js';
