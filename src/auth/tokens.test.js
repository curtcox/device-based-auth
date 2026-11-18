import { describe, it, expect } from 'vitest';
import { signToken, verifyToken } from './tokens.js';

const SECRET = 'test-secret';

describe('signed tokens', () => {
  it('round-trips and rejects other prefixes, keys and expired payloads', async () => {
    const token = await signToken('dbx_', { a: 1 }, SECRET);
    expect(await verifyToken(token, 'dbx_', SECRET)).toEqual({ a: 1 });
    expect(await verifyToken(token, 'dby_', SECRET)).toBeNull();
    expect(await verifyToken(token, 'dbx_', 'other')).toBeNull();
    expect(await verifyToken(`${token}.x`, 'dbx_', SECRET)).toBeNull();
    expect(await verifyToken(await signToken('dbx_', { exp: 1 }, SECRET), 'dbx_', SECRET)).toBeNull();
  });

  it('accepts only the canonical spelling of the tag', async () => {
    // A 32-byte HMAC is 43 base64url characters; the last one carries 2 spare bits, so the
    // characters A–D (and E–H, …) decode to the same bytes. Only the canonical one may verify.
    const token = await signToken('dbx_', { a: 1 }, SECRET);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(token.at(-1));
    expect(last % 4).toBe(0);
    for (let spare = 1; spare < 4; spare++) {
      const variant = token.slice(0, -1) + alphabet[last + spare];
      expect(await verifyToken(variant, 'dbx_', SECRET)).toBeNull();
    }
  });
});
