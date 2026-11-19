import { describe, it, expect } from 'vitest';
import { hotp, matchStep, base32, otpauthUri } from './totp.js';
import { seal, unseal } from './sealing.js';
import { verifyRegistration, verifyAssertion, creationOptions, answerChallenge } from './webauthn.js';
import { softAuthenticator } from '../../test-utils/authenticator.js';

const ascii = s => new TextEncoder().encode(s);

describe('TOTP', () => {
  it('matches RFC 6238 appendix B (SHA-1) and RFC 4648 base32', async () => {
    const secret = ascii('12345678901234567890');
    expect(await hotp(secret, Math.floor(59 / 30), 8)).toBe('94287082');
    expect(await hotp(secret, Math.floor(1111111109 / 30), 8)).toBe('07081804');
    expect(await hotp(secret, Math.floor(2000000000 / 30), 8)).toBe('69279037');
    expect(base32(ascii('foobar'))).toBe('MZXW6YTBOI');
    expect(otpauthUri({ secret: ascii('foobar'), label: 'Phone' })).toBe('otpauth://totp/devicebasedauth.org%3APhone?secret=MZXW6YTBOI&issuer=devicebasedauth.org&algorithm=SHA1&digits=6&period=30');
  });
  it('accepts one step either side, and never a step already used', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(20));
    const now = 1795017600000; const step = Math.floor(now / 30000);
    expect(await matchStep(secret, await hotp(secret, step), now)).toBe(step);
    expect(await matchStep(secret, await hotp(secret, step - 1), now)).toBe(step - 1);
    expect(await matchStep(secret, await hotp(secret, step - 2), now)).toBe(null);
    expect(await matchStep(secret, await hotp(secret, step), now, step)).toBe(null);
    expect(await matchStep(secret, '12345', now)).toBe(null);
  });
});

describe('sealing', () => {
  const env = { GATE_SEALING_KEYS: JSON.stringify([{ kid: 'k2', key: btoa(String.fromCharCode(...new Uint8Array(32).fill(2))) }, { kid: 'k1', key: btoa(String.fromCharCode(...new Uint8Array(32).fill(1))) }]) };
  it('round-trips, binds blobs to their gate, and opens blobs sealed with an older key', async () => {
    const blob = await seal(env, { account: 'a', gateId: 'g' }, ascii('seed'));
    expect(blob.kid).toBe('k2');
    expect(new TextDecoder().decode(await unseal(env, { account: 'a', gateId: 'g' }, blob))).toBe('seed');
    await expect(unseal(env, { account: 'a', gateId: 'other' }, blob)).rejects.toThrow();
    const old = await seal({ GATE_SEALING_KEYS: JSON.stringify([{ kid: 'k1', key: btoa(String.fromCharCode(...new Uint8Array(32).fill(1))) }]) }, { account: 'a', gateId: 'g' }, ascii('old'));
    expect(new TextDecoder().decode(await unseal(env, { account: 'a', gateId: 'g' }, old))).toBe('old');
  });
});

describe('WebAuthn', () => {
  const origin = 'https://devicebasedauth.org'; const rpId = 'devicebasedauth.org';
  it('registers an ES256 key and checks assertions bound to a request and decision', async () => {
    const key = await softAuthenticator();
    const options = creationOptions({ challenge: 'c1', rpId, userId: 'dXNlcg', label: 'YubiKey' });
    const registered = await verifyRegistration(await key.register(options, origin), { challenge: 'c1', origin, rpId });
    expect(registered).toMatchObject({ credential_id: key.id, sign_count: 0, public_jwk: { kty: 'EC', crv: 'P-256' } });
    const challenge = await answerChallenge({ requestId: 'gtr_1', entry: 0, decision: 'allow', salt: 's' });
    const answer = await key.assert({ challenge, rpId }, origin);
    expect(await verifyAssertion(answer, { challenge, origin, rpId, credential: registered })).toMatchObject({ sign_count: 1 });
    // The same assertion cannot deny, nor answer from another site, nor replay with an old counter.
    const deny = await answerChallenge({ requestId: 'gtr_1', entry: 0, decision: 'deny', salt: 's' });
    await expect(verifyAssertion(answer, { challenge: deny, origin, rpId, credential: registered })).rejects.toThrow(/challenge/);
    await expect(verifyAssertion(answer, { challenge, origin: 'https://evil.example', rpId, credential: registered })).rejects.toThrow(/origin/);
    await expect(verifyAssertion(answer, { challenge, origin, rpId, credential: { ...registered, sign_count: 1 } })).rejects.toThrow(/counter/);
    await expect(verifyRegistration(await key.register(options, origin), { challenge: 'c1', origin, rpId: 'other.org' })).rejects.toThrow(/not for/);
  });
  it('requires user verification when the gate asks for it', async () => {
    const key = await softAuthenticator({ uv: false });
    const options = creationOptions({ challenge: 'c', rpId, userId: 'dQ', label: 'k' });
    await expect(verifyRegistration(await key.register(options, origin), { challenge: 'c', origin, rpId, requireUV: true })).rejects.toThrow(/verify the user/);
  });
});

describe('Duo request signing', () => {
  it('matches the example in Duo\'s API documentation', async () => {
    const { duoSign } = await import('./vendors.js');
    const signed = await duoSign({ method: 'POST', host: 'api-xxxxxxxx.duosecurity.com', path: '/accounts/v1/account/list', params: { realname: 'First Last', username: 'root' }, ikey: 'DIWJ8X6AEYOR5OMC6TQ1', skey: 'Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep', date: 'Tue, 21 Aug 2012 17:29:18 -0000' });
    expect(signed.body).toBe('realname=First%20Last&username=root');
    expect(atob(signed.headers.Authorization.slice(6))).toBe('DIWJ8X6AEYOR5OMC6TQ1:2d97d6166319781b5a3a07af39d366f491234edc');
  });
});
