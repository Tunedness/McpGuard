/**
 * `@mcpguard/proxy` — the MCP adapter.
 *
 * Three gates and one blind seam:
 *
 * ```
 * downstream ⇄ Server ── explicit: tools/call, tools/list, resources/read
 *                     ── fallbackRequestHandler      → client.request
 *                     ── fallbackNotificationHandler → client.notification
 * upstream   ⇄ Client ── fallbackRequestHandler      → server.request
 *                     ── fallbackNotificationHandler → server.notification
 * ```
 *
 * Everything else passes through with no schema of ours in the way. A proxy is
 * not a validator: a method it has never heard of has to work.
 *
 * `bridge.ts`, `era.ts`, `remap.ts` and `diagnostics.ts` are kept free of both
 * engine packages, so the transport skeleton stays liftable into a shared
 * internal package later. `boundary.test.ts` fails the build if that stops
 * being true.
 */
export { PROXY_VERSION } from './version.js';
