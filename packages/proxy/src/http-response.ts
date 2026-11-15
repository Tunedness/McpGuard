/**
 * The few responses the gateway writes itself, as JSON-RPC errors.
 *
 * Everything the SDK answers keeps the SDK's own shape; these are the answers
 * that never reach it — an unknown path, a refused credential, a full table —
 * and a client that speaks MCP reads them the way it reads any other error.
 * None of them carries anything the caller sent: not a header value, not a
 * token, not a path segment.
 *
 * This module imports neither engine package. See `boundary.test.ts`.
 */

/** JSON-RPC codes the gateway uses beyond the SDK's own. */
export const GATEWAY_ERROR = {
  invalidRequest: -32600,
  internal: -32603,
  /** The SDK's code for an unsupported protocol version. */
  unsupportedProtocolVersion: -32022,
  /** Not defined by the SDK: a request refused before it was served. */
  refused: -32000,
} as const;

/** Builds a JSON-RPC error response with an HTTP status. */
export function jsonRpcError(
  status: number,
  code: number,
  message: string,
  data?: Record<string, unknown>,
  headers?: Record<string, string>,
  id: string | number | null = null,
): Response {
  return new Response(
    JSON.stringify({
      jsonrpc: '2.0',
      error: { code, message, ...(data !== undefined ? { data } : {}) },
      id,
    }),
    { status, headers: { 'content-type': 'application/json', ...headers } },
  );
}
