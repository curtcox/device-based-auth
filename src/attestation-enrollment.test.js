import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { testEnv, call, newDevice } from '../test-utils/env.js';
import { inspectCredential, signJws } from '../packages/verify/src/index.js';
import { attestationAuthority, attestationChain } from '../test-utils/android-attestation.js';
import { resetRevocationCache, createChallenge, verifyAttestation } from './services/attestation.js';

let authority; let env;
beforeAll(async () => { authority = await attestationAuthority(); });
beforeEach(async () => {
  env = await testEnv({ ANDROID_ATTESTATION_TEST_ROOT: authority.rootPin });
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
  resetRevocationCache();
  // Google's revocation list, as the Worker would fetch it.
  vi.stubGlobal('fetch', vi.fn(async url => String(url).startsWith('https://android.googleapis.com/attestation/status') ? Response.json({ entries: { dead: { status: 'REVOKED' } } }) : new Response('unexpected', { status: 500 })));
});
afterEach(() => { vi.unstubAllGlobals(); resetRevocationCache(); });

const publicKeyOf = device => crypto.subtle.importKey('jwk', device.publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);

/** Get a challenge, attest the device key with it, and start an enrollment. */
async function attestedStart(device, { description, challengeOverride } = {}) {
  const { body: { challenge } } = await call(env, 'POST', '/api/v1/enrollments/attestation-challenge');
  const x5c = await attestationChain(authority, await publicKeyOf(device), { challenge: new TextEncoder().encode(challengeOverride ?? challenge), description });
  const request = await device.enrollRequest({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], device: { name: 'Pixel', kind: 'phone', key_protection: 'software' }, attestation: { format: 'android-key', challenge, x5c } });
  return call(env, 'POST', '/api/v1/enrollments', { body: { request } });
}

describe('attested enrollment (B5, Android)', () => {
  it('shows the verified attestation to the approver and signs it into the credential', async () => {
    const device = await newDevice();
    const start = await attestedStart(device);
    expect(start.status).toBe(200);
    const described = await call(env, 'POST', '/api/v1/enrollments/describe', { body: { request: start.body.request } });
    expect(described.body.device).toMatchObject({ key_protection: 'android-keystore', attestation: { format: 'android-key', security_level: 'strongbox', verified_boot: 'verified', device_locked: true } });

    const approved = await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: start.body.request } });
    expect(approved.status).toBe(200);
    const { payload } = inspectCredential(approved.body.credential);
    expect(payload.device).toMatchObject({ name: 'Pixel', kind: 'phone', key_protection: 'android-keystore', attestation: { format: 'android-key', security_level: 'strongbox', attestation_version: 200 } });
    expect(payload.device.attestation.verified_at).toBe(payload.iat);

    // Renewal keeps it; rotating to a key nobody attested drops it.
    const path = `/api/v1/credentials/${payload.cid}/renew`;
    const renewed = await call(env, 'POST', path, { headers: await device.headers('POST', path, approved.body.credential), body: {} });
    expect(inspectCredential(renewed.body.credential).payload.device.attestation).toMatchObject({ security_level: 'strongbox' });
    const next = await newDevice();
    const keyProof = await signJws({ typ: 'dba-rotate+jwt', jwk: next.publicJwk }, { cid: payload.cid, iat: Math.floor(Date.now() / 1000) }, next.privateKey);
    const rotated = await call(env, 'POST', path, { headers: await device.headers('POST', path, renewed.body.credential), body: { new_key_proof: keyProof } });
    expect(rotated.body.rotated).toBe(true);
    const after = inspectCredential(rotated.body.credential).payload.device;
    expect(after.attestation).toBeUndefined();
    expect(after.name).toBe('Pixel');
  });

  it('carries the attestation through enrollment-token redemption', async () => {
    const token = await call(env, 'POST', '/api/v1/enrollment-tokens', { auth: 'alice', body: { name: 'Phones', aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], lifetime_seconds: 3600, max_uses: 5, expires_in_days: 1 } });
    const device = await newDevice();
    const { body: { challenge } } = await call(env, 'POST', '/api/v1/enrollments/attestation-challenge');
    const x5c = await attestationChain(authority, await publicKeyOf(device), { challenge: new TextEncoder().encode(challenge), description: { securityLevel: 1 } });
    const request = await device.enrollRequest({ device: { name: 'Kiosk', kind: 'phone' }, attestation: { format: 'android-key', challenge, x5c } });
    const redeemed = await call(env, 'POST', '/api/v1/enrollments/redeem', { body: { enrollment_token: token.body.token, request } });
    expect(redeemed.status).toBe(200);
    expect(inspectCredential(redeemed.body.credential).payload.device).toMatchObject({ key_protection: 'android-keystore', attestation: { security_level: 'tee' } });
  });

  it('refuses bad attestations instead of enrolling without them', async () => {
    expect((await attestedStart(await newDevice(), { description: { securityLevel: 0 } })).body.code).toBe('invalid_attestation');
    expect((await attestedStart(await newDevice(), { challengeOverride: 'not-the-challenge' })).body.code).toBe('invalid_attestation');
    const device = await newDevice();
    const forged = await device.enrollRequest({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], attestation: { format: 'android-key', challenge: 'A'.repeat(43), x5c: [] } });
    expect((await call(env, 'POST', '/api/v1/enrollments', { body: { request: forged } })).body).toMatchObject({ code: 'invalid_attestation' });
    const apple = await device.enrollRequest({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], attestation: { format: 'apple-appattest' } });
    expect((await call(env, 'POST', '/api/v1/enrollments', { body: { request: apple } })).body.code).toBe('invalid_attestation');
  });

  it('fails closed when Google\'s revocation list is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('down', { status: 503 })));
    const start = await attestedStart(await newDevice());
    expect(start).toMatchObject({ status: 503, body: { code: 'attestation_unavailable' } });
  });

  it('never takes an attestation from a request body or a device claim', async () => {
    const device = await newDevice();
    const fake = { format: 'android-key', security_level: 'strongbox' };
    const request = await device.enrollRequest({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], device: { name: 'Liar', kind: 'phone', attestation: fake } });
    const start = await call(env, 'POST', '/api/v1/enrollments', { body: { request } });
    const approved = await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: start.body.request } });
    expect(inspectCredential(approved.body.credential).payload.device.attestation).toBeUndefined();
    const issued = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: (await newDevice()).publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], device: { name: 'API', attestation: fake }, attestation: fake } });
    expect(issued.status).toBe(200);
    expect(inspectCredential(issued.body.credential).payload.device.attestation).toBeUndefined();
  });

  it('trusts the test root only on a local server', async () => {
    const device = await newDevice();
    const { challenge } = await createChallenge('test-token-key');
    const attestation = { format: 'android-key', challenge, x5c: await attestationChain(authority, await publicKeyOf(device), { challenge: new TextEncoder().encode(challenge) }) };
    const local = { ENVIRONMENT: 'local', TOKEN_SIGNING_KEY: 'test-token-key', ANDROID_ATTESTATION_TEST_ROOT: authority.rootPin };
    await expect(verifyAttestation(attestation, device.publicJwk, local)).resolves.toMatchObject({ security_level: 'strongbox' });
    await expect(verifyAttestation(attestation, device.publicJwk, { ...local, ENVIRONMENT: 'production' })).rejects.toThrow(/Google attestation root/);
  });
});
