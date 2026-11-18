import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { testEnv, call, newDevice } from '../test-utils/env.js';
import { inspectCredential, signJws, createVerifier, createProof } from '../packages/verify/src/index.js';
import { ORIGIN, worker } from '../test-utils/env.js';
import { attestationAuthority, attestationChain } from '../test-utils/android-attestation.js';
import { appleAuthority, appleAttestation } from '../test-utils/apple-attestation.js';
import { resetRevocationCache, createChallenge, verifyAttestation } from './services/attestation.js';
import { appleClientData } from './services/apple-attestation.js';
import { tpmAuthority, tpmAttestation, tpmCrl } from '../test-utils/tpm-attestation.js';
import { tpmQualifyingData, resetTpmCrlCache, MICROSOFT_TPM_CRL_URL } from './services/tpm-attestation.js';
import { jwkThumbprint } from '../packages/verify/src/jose.js';

let authority; let apple; let tpm; let env; let tpmCrlResponse;
beforeAll(async () => { authority = await attestationAuthority(); apple = await appleAuthority(); tpm = await tpmAuthority(); });
beforeEach(async () => {
  env = await testEnv({ ANDROID_ATTESTATION_TEST_ROOT: authority.rootPin, APPLE_ATTESTATION_TEST_ROOT: apple.rootSpkiB64u, TPM_ATTESTATION_TEST_ROOT: tpm.rootSpkiB64u });
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
  resetRevocationCache(); resetTpmCrlCache();
  tpmCrlResponse = async () => new Response(await tpmCrl(tpm, ['7f']));
  // Google's revocation list and the TPM root's CRL, as the Worker would fetch them.
  vi.stubGlobal('fetch', vi.fn(async url => {
    if (String(url).startsWith('https://android.googleapis.com/attestation/status')) return Response.json({ entries: { dead: { status: 'REVOKED' } } });
    if (String(url) === MICROSOFT_TPM_CRL_URL) return tpmCrlResponse();
    return new Response('unexpected', { status: 500 });
  }));
});
afterEach(() => { vi.unstubAllGlobals(); resetRevocationCache(); resetTpmCrlCache(); });

const publicKeyOf = device => crypto.subtle.importKey('jwk', device.publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);

/** Get a challenge, attest the device key with it, and start an enrollment. */
async function attestedStart(device, { description, challengeOverride, grants = [{ actions: ['hashbin:content:write'] }] } = {}) {
  const { body: { challenge } } = await call(env, 'POST', '/api/v1/enrollments/attestation-challenge');
  const x5c = await attestationChain(authority, await publicKeyOf(device), { challenge: new TextEncoder().encode(challengeOverride ?? challenge), description });
  const request = await device.enrollRequest({ aud: ['hashbin.org'], grants, device: { name: 'Pixel', kind: 'phone', key_protection: 'software' }, attestation: { format: 'android-key', challenge, x5c } });
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

  it('lets grants require an attested key, checked offline and online', async () => {
    const grants = [{ actions: ['hashbin:content:write'], require: { attestation: 'strongbox', verified_boot: true } }];
    const verifier = createVerifier({ issuer: ORIGIN, audience: 'hashbin.org', fetch: (url, init) => worker.fetch(new Request(url, init), env) });
    const attempt = async (device, credential) => verifier.verifyRequest(new Request('https://hashbin.org/api/content', { method: 'POST', headers: { Authorization: `DBA ${credential}`, DPoP: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url: 'https://hashbin.org/api/content', credential }) } }), { action: 'hashbin:content:write' });

    const strong = await newDevice();
    const start = await attestedStart(strong, { grants });
    const credential = (await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: start.body.request } })).body.credential;
    expect((await attempt(strong, credential)).allow).toBe(true);
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'operator', body: { amount_microdollars: 1_000_000 } });
    const url = 'https://hashbin.org/api/content';
    const proof = await createProof({ privateKey: strong.privateKey, publicJwk: strong.publicJwk, method: 'POST', url, credential });
    const online = await call(env, 'POST', '/api/v1/authorize', { auth: 'operator', body: { credential, proof, request: { method: 'POST', url }, action: 'hashbin:content:write', audience: 'hashbin.org' } });
    expect(online.body, JSON.stringify(online.body)).toMatchObject({ allow: true });

    // A TEE key on an unlocked phone, and a key with no attestation at all, are refused offline.
    const tee = await newDevice();
    const teeStart = await attestedStart(tee, { grants, description: { securityLevel: 1, locked: false } });
    const teeCredential = (await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: teeStart.body.request } })).body.credential;
    expect(await attempt(tee, teeCredential)).toMatchObject({ allow: false, status: 403, reasons: [['attestation_required', 'verified_boot_required']] });
    const plain = await newDevice();
    const plainStart = await call(env, 'POST', '/api/v1/enrollments', { body: { request: await plain.enrollRequest({ aud: ['hashbin.org'], grants }) } });
    const plainCredential = (await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: plainStart.body.request } })).body.credential;
    expect((await attempt(plain, plainCredential)).reasons).toEqual([['attestation_required', 'verified_boot_required']]);
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

const APP = 'ABCDE12345.org.example.wallet';

/** An iOS app's enrollment: App Attest vouches for the Secure Enclave key by its thumbprint. */
async function appleStart(device, { grants = [{ actions: ['hashbin:content:write'] }], appId = APP, environment, bindTo } = {}) {
  const { body: { challenge } } = await call(env, 'POST', '/api/v1/enrollments/attestation-challenge');
  const jkt = await jwkThumbprint((bindTo ?? device).publicJwk);
  const { object, keyId } = await appleAttestation(apple, { appId, clientData: appleClientData(challenge, jkt), environment });
  const request = await device.enrollRequest({ aud: ['hashbin.org'], grants, device: { name: 'iPhone', kind: 'phone' }, attestation: { format: 'apple-appattest', challenge, app_id: APP, key_id: keyId, object } });
  return call(env, 'POST', '/api/v1/enrollments', { body: { request } });
}

describe('attested enrollment (B5, Apple App Attest)', () => {
  it('signs the app attestation into the credential and lets grants pin the app', async () => {
    const pinned = [{ actions: ['hashbin:content:write'], require: { attestation: 'hardware', app_ids: [APP] } }];
    const device = await newDevice();
    const start = await appleStart(device, { grants: pinned });
    expect(start.status, JSON.stringify(start.body)).toBe(200);
    const described = await call(env, 'POST', '/api/v1/enrollments/describe', { body: { request: start.body.request } });
    expect(described.body.device).toMatchObject({ key_protection: 'secure-enclave', attestation: { format: 'apple-appattest', security_level: 'secure_enclave', app_id: APP, environment: 'production' } });
    const credential = (await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: start.body.request } })).body.credential;
    expect(inspectCredential(credential).payload.device.attestation).toMatchObject({ format: 'apple-appattest', app_id: APP });

    const verifier = createVerifier({ issuer: ORIGIN, audience: 'hashbin.org', fetch: (url, init) => worker.fetch(new Request(url, init), env) });
    const attempt = async (d, c) => verifier.verifyRequest(new Request('https://hashbin.org/api/content', { method: 'POST', headers: { Authorization: `DBA ${c}`, DPoP: await createProof({ privateKey: d.privateKey, publicJwk: d.publicJwk, method: 'POST', url: 'https://hashbin.org/api/content', credential: c }) } }), { action: 'hashbin:content:write' });
    expect((await attempt(device, credential)).allow).toBe(true);

    // The same attestation does not satisfy a grant that does not name the app.
    const unpinned = await newDevice();
    const plainStart = await appleStart(unpinned, { grants: [{ actions: ['hashbin:content:write'], require: { attestation: 'hardware' } }] });
    const plainCredential = (await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: plainStart.body.request } })).body.credential;
    expect((await attempt(unpinned, plainCredential)).reasons).toEqual([['attestation_required']]);
  });

  it('refuses an attestation that vouches for another key, app or challenge', async () => {
    const device = await newDevice();
    expect((await appleStart(device, { bindTo: await newDevice() })).body).toMatchObject({ code: 'invalid_attestation', error: expect.stringContaining('nonce does not match') });
    expect((await appleStart(device, { appId: 'ABCDE12345.org.example.other' })).body).toMatchObject({ code: 'invalid_attestation', error: expect.stringContaining('another app') });
  });

  it('trusts the test root only on a local server', async () => {
    const device = await newDevice();
    const { challenge } = await createChallenge('test-token-key');
    const { object, keyId } = await appleAttestation(apple, { appId: APP, clientData: appleClientData(challenge, await jwkThumbprint(device.publicJwk)) });
    const attestation = { format: 'apple-appattest', challenge, app_id: APP, key_id: keyId, object };
    const local = { ENVIRONMENT: 'local', TOKEN_SIGNING_KEY: 'test-token-key', APPLE_ATTESTATION_TEST_ROOT: apple.rootSpkiB64u };
    await expect(verifyAttestation(attestation, device.publicJwk, local)).resolves.toMatchObject({ app_id: APP });
    await expect(verifyAttestation(attestation, device.publicJwk, { ...local, ENVIRONMENT: 'production' })).rejects.toThrow(/Apple App Attestation Root CA/);
  });
});

/** A PC's enrollment: the TPM's attestation key certifies the TPM-resident device key. */
async function tpmStart(device, { grants = [{ actions: ['hashbin:content:write'] }], bindTo, overrides } = {}) {
  const { body: { challenge } } = await call(env, 'POST', '/api/v1/enrollments/attestation-challenge');
  const qualifying = await tpmQualifyingData(challenge, await jwkThumbprint((bindTo ?? device).publicJwk));
  const members = await tpmAttestation(tpm, device.publicJwk, qualifying, overrides);
  const request = await device.enrollRequest({ aud: ['hashbin.org'], grants, device: { name: 'Work laptop', kind: 'desktop', key_protection: 'software' }, attestation: { format: 'tpm', challenge, ...members } });
  return call(env, 'POST', '/api/v1/enrollments', { body: { request } });
}

describe('attested enrollment (B5, TPM 2.0)', () => {
  it('signs the TPM attestation into the credential, and hardware grants accept it', async () => {
    const device = await newDevice();
    const start = await tpmStart(device, { grants: [{ actions: ['hashbin:content:write'], require: { attestation: 'hardware' } }] });
    expect(start.status, JSON.stringify(start.body)).toBe(200);
    const described = await call(env, 'POST', '/api/v1/enrollments/describe', { body: { request: start.body.request } });
    expect(described.body.device).toMatchObject({ key_protection: 'tpm', attestation: { format: 'tpm', security_level: 'tpm', tpm_manufacturer: 'NTC' } });
    const credential = (await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: start.body.request } })).body.credential;
    expect(inspectCredential(credential).payload.device).toMatchObject({ key_protection: 'tpm', attestation: { format: 'tpm', tpm_manufacturer: 'NTC' } });

    const verifier = createVerifier({ issuer: ORIGIN, audience: 'hashbin.org', fetch: (url, init) => worker.fetch(new Request(url, init), env) });
    const proof = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url: 'https://hashbin.org/api/content', credential });
    const decision = await verifier.verifyRequest(new Request('https://hashbin.org/api/content', { method: 'POST', headers: { Authorization: `DBA ${credential}`, DPoP: proof } }), { action: 'hashbin:content:write' });
    expect(decision.allow).toBe(true);
  });

  it('refuses an attestation for another key or an exportable key', async () => {
    const device = await newDevice();
    expect((await tpmStart(device, { bindTo: await newDevice() })).body).toMatchObject({ code: 'invalid_attestation', error: expect.stringContaining('qualifying data does not match') });
    expect((await tpmStart(device, { overrides: { attributes: 0x00040070 } })).body).toMatchObject({ code: 'invalid_attestation', error: expect.stringContaining('fixedTPM') });
  });

  it('checks the root\'s CRL, and fails closed when it cannot', async () => {
    tpmCrlResponse = async () => new Response(await tpmCrl(tpm, [tpm.interSerial]));
    expect((await tpmStart(await newDevice())).body).toMatchObject({ code: 'invalid_attestation', error: expect.stringContaining('revoked by Microsoft') });
    resetTpmCrlCache();
    tpmCrlResponse = async () => new Response('down', { status: 503 });
    const down = await tpmStart(await newDevice());
    expect(down.status).toBe(503);
    expect(down.body.code).toBe('attestation_unavailable');
    resetTpmCrlCache();
    tpmCrlResponse = async () => new Response(await tpmCrl(tpm, [], { thisUpdate: Date.UTC(2024, 0, 1), nextUpdate: Date.UTC(2024, 3, 1) }));
    expect((await tpmStart(await newDevice())).status).toBe(503);
  });

  it('trusts the test root only on a local server', async () => {
    const device = await newDevice();
    const { challenge } = await createChallenge('test-token-key');
    const members = await tpmAttestation(tpm, device.publicJwk, await tpmQualifyingData(challenge, await jwkThumbprint(device.publicJwk)));
    const attestation = { format: 'tpm', challenge, ...members };
    const local = { ENVIRONMENT: 'local', TOKEN_SIGNING_KEY: 'test-token-key', TPM_ATTESTATION_TEST_ROOT: tpm.rootSpkiB64u };
    await expect(verifyAttestation(attestation, device.publicJwk, local)).resolves.toMatchObject({ format: 'tpm' });
    await expect(verifyAttestation(attestation, device.publicJwk, { ...local, ENVIRONMENT: 'production' })).rejects.toThrow(/Microsoft TPM Root/);
    await expect(verifyAttestation({ ...attestation, cert_info: undefined }, device.publicJwk, local)).rejects.toThrow(/cert_info is required/);
  });
});
