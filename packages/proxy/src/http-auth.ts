/**
 * Static bearer tokens, checked by hash (ADR-011).
 *
 * The policy holds the SHA-256 of each token and never the token, so the policy
 * file can live in version control. A presented token is hashed and compared
 * against every configured digest with `timingSafeEqual`, all of them, with no
 * early exit: how long the check takes says nothing about which digest was
 * close. The SDK's own `verifyBearerToken` is not used because it insists on an
 * expiry, which a static token does not have.
 *
 * The token is never logged, never put in an error and never stored; only the
 * identity it maps to leaves this module.
 *
 * This module imports neither engine package. See `boundary.test.ts`.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { GATEWAY_ERROR, jsonRpcError } from './http-response.js';

/** One configured token: who it names, and the SHA-256 of the token itself. */
export interface BearerToken {
  readonly identity: string;
  /** 64 lowercase hex digits. */
  readonly tokenSha256: string;
}

/** The result of checking one request. */
export type AuthResult =
  /** No token is configured: nothing to check, and no identity from here. */
  | { readonly kind: 'open' }
  | { readonly kind: 'ok'; readonly identity: string }
  | { readonly kind: 'refused'; readonly reason: 'missing' | 'malformed' | 'unknown' };

/** Checks `Authorization` headers against a fixed set of tokens. */
export interface BearerAuthenticator {
  /** Whether any token is configured. When true, every request must present one. */
  readonly required: boolean;
  authenticate(headers: Headers): AuthResult;
}

/** The longest credential considered; a real token is a few dozen characters. */
const MAX_TOKEN_LENGTH = 4_096;

const BEARER = /^Bearer[ ]+([^\s,]+)$/i;

function digestOf(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

/** Builds the checker for a fixed token set. An empty set means open. */
export function createBearerAuthenticator(tokens: readonly BearerToken[]): BearerAuthenticator {
  const configured = tokens.map((token) => ({
    identity: token.identity,
    digest: Buffer.from(token.tokenSha256, 'hex'),
  }));
  for (const entry of configured) {
    if (entry.digest.length !== 32) {
      throw new Error('a bearer token digest must be 64 hex digits (SHA-256)');
    }
  }
  return {
    required: configured.length > 0,
    authenticate(headers) {
      if (configured.length === 0) return { kind: 'open' };
      const header = headers.get('authorization');
      if (header === null) return { kind: 'refused', reason: 'missing' };
      const match = BEARER.exec(header.trim());
      const presented = match?.[1];
      if (presented === undefined || presented.length > MAX_TOKEN_LENGTH) {
        return { kind: 'refused', reason: 'malformed' };
      }
      const digest = digestOf(presented);
      let identity: string | undefined;
      for (const entry of configured) {
        // Every entry is compared, so the loop's length does not depend on a hit.
        if (timingSafeEqual(digest, entry.digest) && identity === undefined) {
          identity = entry.identity;
        }
      }
      return identity === undefined
        ? { kind: 'refused', reason: 'unknown' }
        : { kind: 'ok', identity };
    },
  };
}

/** The `401` for a request that did not present an acceptable token. */
export function unauthorizedResponse(): Response {
  return jsonRpcError(
    401,
    GATEWAY_ERROR.refused,
    'Unauthorized: present a valid bearer token',
    { reason: 'unauthorized' },
    { 'www-authenticate': 'Bearer' },
  );
}

/** The SHA-256 of a token, as the policy stores it. */
export function hashToken(token: string): string {
  return digestOf(token).toString('hex');
}
