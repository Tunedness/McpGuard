import { describe, expect, it } from 'vitest';
import { createBearerAuthenticator, hashToken, unauthorizedResponse } from './http-auth.js';

const headers = (authorization?: string): Headers =>
  new Headers(authorization === undefined ? {} : { authorization });

const alice = { identity: 'alice', tokenSha256: hashToken('alice-secret') };
const bob = { identity: 'bob', tokenSha256: hashToken('bob-secret') };

describe('static bearer tokens, checked by hash', () => {
  it('is open when no token is configured, and says it has no identity to give', () => {
    const auth = createBearerAuthenticator([]);
    expect(auth.required).toBe(false);
    expect(auth.authenticate(headers())).toEqual({ kind: 'open' });
    expect(auth.authenticate(headers('Bearer anything'))).toEqual({ kind: 'open' });
  });

  it('maps a presented token to the identity that holds it', () => {
    const auth = createBearerAuthenticator([alice, bob]);
    expect(auth.required).toBe(true);
    expect(auth.authenticate(headers('Bearer bob-secret'))).toEqual({
      kind: 'ok',
      identity: 'bob',
    });
    expect(auth.authenticate(headers('bearer   alice-secret'))).toEqual({
      kind: 'ok',
      identity: 'alice',
    });
  });

  it('lets several tokens name one identity, which is how a token is rotated', () => {
    const rotated = { identity: 'alice', tokenSha256: hashToken('alice-secret-2') };
    const auth = createBearerAuthenticator([alice, rotated]);
    expect(auth.authenticate(headers('Bearer alice-secret'))).toMatchObject({ identity: 'alice' });
    expect(auth.authenticate(headers('Bearer alice-secret-2'))).toMatchObject({
      identity: 'alice',
    });
  });

  it.each([
    ['no header', undefined, 'missing'],
    ['another scheme', 'Basic YWxpY2U6eA==', 'malformed'],
    ['no token', 'Bearer', 'malformed'],
    ['two tokens', 'Bearer alice-secret, Bearer bob-secret', 'malformed'],
    ['a token with a space in it', 'Bearer alice secret', 'malformed'],
    ['a wrong token', 'Bearer alice-secreT', 'unknown'],
    ['the hash instead of the token', `Bearer ${alice.tokenSha256}`, 'unknown'],
  ] as const)('refuses %s', (_label, value, reason) => {
    const auth = createBearerAuthenticator([alice, bob]);
    expect(auth.authenticate(headers(value))).toEqual({ kind: 'refused', reason });
  });

  it('refuses a credential longer than any real token without hashing it', () => {
    const auth = createBearerAuthenticator([alice]);
    expect(auth.authenticate(headers(`Bearer ${'x'.repeat(5_000)}`))).toEqual({
      kind: 'refused',
      reason: 'malformed',
    });
  });

  it('refuses at construction a digest that is not a SHA-256', () => {
    expect(() => createBearerAuthenticator([{ identity: 'x', tokenSha256: 'abcd' }])).toThrow(
      /SHA-256/,
    );
  });

  it('answers 401 with a challenge and nothing the caller sent', async () => {
    const response = unauthorizedResponse();
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toBe('Bearer');
    const body = (await response.json()) as { error: { code: number; data: { reason: string } } };
    expect(body.error.data.reason).toBe('unauthorized');
  });

  it('hashes the way the policy stores it', () => {
    expect(hashToken('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});
