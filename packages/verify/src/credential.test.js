import { describe, it, expect } from 'vitest';
import { generateKeyPair, exportPublicJwk, jwkThumbprint, b64u, unb64u, decodeJws, signJws } from './jose.js';
import { verifyCredential, createProof, verifyProof, ReplayCache, inspectCredential, CONFIRMATION_TYP } from './credential.js';
import { issuerSigner, jwksFor, signCredential, signStatusList, signAccessToken } from './issuer.js';
import { getBit, setBit, encodeStatusList, decodeStatusList } from './status-list.js';
import { createVerifier } from './verifier.js';

const ISSUER = 'https://devicebasedauth.org';
const NOW = 1795017600;
async function issuerKey(kid = 'test-1') {
  const pair = await generateKeyPair(true);
  return { kid, jwk: await crypto.subtle.exportKey('jwk', pair.privateKey) };
}
async function device() {
  const pair = await generateKeyPair(false);
  const jwk = await exportPublicJwk(pair.publicKey);
  return { privateKey: pair.privateKey, publicJwk: jwk, jkt: await jwkThumbprint(jwk) };
}
function payload(dev, extra = {}) {
  return { iss: ISSUER, sub: 'dev_ABCDEFGH12', acct: 'acct_1', aud: ['hashbin.org'], cid: 'crd_ABCDEFGH12', jti: 'crd_ABCDEFGH12.1', iat: NOW, nbf: NOW, exp: NOW + 86400, cnf: { jkt: dev.jkt }, grants: [{ actions: ['hashbin:content:write'] }], status: { status_list: { idx: 5, uri: `${ISSUER}/status/v1/lists/0` } }, ver: 1, ...extra };
}

describe('jose', () => {
  it('round-trips base64url', () => { const bytes = crypto.getRandomValues(new Uint8Array(60000)); expect(unb64u(b64u(bytes))).toEqual(bytes); });
  it('computes the RFC 7638 example thumbprint', async () => {
    // RFC 7638 §3.1 uses RSA; this is the RFC 9449 §6.1 P-256 example thumbprint input recomputed.
    const jwk = { kty: 'EC', crv: 'P-256', x: 'l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs', y: '9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA' };
    expect(await jwkThumbprint(jwk)).toBe('0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I');
  });
  it('signs with an external signer (a key in a TPM or HSM) as with a CryptoKey', async () => {
    const dev = await device();
    let signed = null;
    const signer = { async sign(bytes) { signed = bytes; return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, dev.privateKey, bytes)); } };
    const proof = await createProof({ privateKey: signer, publicJwk: dev.publicJwk, method: 'GET', url: 'https://hashbin.org/x', now: NOW });
    expect(new TextDecoder().decode(signed)).toBe(proof.split('.').slice(0, 2).join('.'));
    expect((await verifyProof(proof, { method: 'GET', url: 'https://hashbin.org/x', jkt: dev.jkt, now: NOW })).htm).toBe('GET');
    await expect(createProof({ privateKey: { sign: async () => new Uint8Array(70) }, publicJwk: dev.publicJwk, method: 'GET', url: 'https://hashbin.org/x' })).rejects.toThrow(/64 bytes/);
  });
});

describe('credentials', () => {
  it('signs, verifies and rejects tampering, expiry and wrong audience', async () => {
    const key = await issuerKey(); const signer = await issuerSigner(key); const jwks = jwksFor([key]); const dev = await device();
    const jws = await signCredential(payload(dev), signer);
    expect((await verifyCredential(jws, { jwks, audience: 'hashbin.org', now: NOW + 10 })).payload.sub).toBe('dev_ABCDEFGH12');
    expect(inspectCredential(jws).header).toMatchObject({ typ: 'dba-device+jwt', alg: 'ES256', kid: 'test-1' });
    const [h, , s] = jws.split('.');
    const forged = `${h}.${b64u(JSON.stringify({ ...payload(dev), grants: [{ actions: ['hashbin:*'] }] }))}.${s}`;
    await expect(verifyCredential(forged, { jwks, now: NOW })).rejects.toMatchObject({ code: 'invalid_signature' });
    await expect(verifyCredential(jws, { jwks, now: NOW + 86400 + 61 })).rejects.toMatchObject({ code: 'expired' });
    await expect(verifyCredential(jws, { jwks, audience: 'cronly.org', now: NOW })).rejects.toMatchObject({ code: 'wrong_audience' });
    await expect(verifyCredential(jws, { jwks: jwksFor([await issuerKey('other')]), now: NOW })).rejects.toMatchObject({ code: 'unknown_kid' });
    await expect(verifyCredential(jws, { jwks, now: NOW, typ: 'access' })).rejects.toMatchObject({ code: 'wrong_type' });
  });
  it('refuses to sign invalid payloads', async () => {
    const signer = await issuerSigner(await issuerKey()); const dev = await device();
    await expect(signCredential(payload(dev, { grants: [{ actions: ['bad'] }] }), signer)).rejects.toThrow(/namespace/);
  });
});

describe('proofs', () => {
  it('binds a request to the device key and the credential', async () => {
    const dev = await device(); const other = await device(); const credential = 'a.b.c';
    const proof = await createProof({ ...dev, method: 'post', url: 'https://hashbin.org/api/upload?x=1', credential, now: NOW, location: { lat: 1, lon: 2, acc_m: 10, t: NOW } });
    const replay = new ReplayCache();
    const verified = await verifyProof(proof, { method: 'POST', url: 'https://hashbin.org/api/upload', credential, jkt: dev.jkt, now: NOW + 5, replay });
    expect(verified.loc).toEqual({ lat: 1, lon: 2, acc_m: 10, t: NOW });
    await expect(verifyProof(proof, { method: 'POST', url: 'https://hashbin.org/api/upload', credential, jkt: dev.jkt, now: NOW + 5, replay })).rejects.toMatchObject({ code: 'replayed_proof' });
    await expect(verifyProof(proof, { method: 'POST', url: 'https://hashbin.org/api/upload', credential, jkt: other.jkt, now: NOW })).rejects.toMatchObject({ code: 'key_mismatch' });
    await expect(verifyProof(proof, { method: 'GET', url: 'https://hashbin.org/api/upload', credential, jkt: dev.jkt, now: NOW })).rejects.toMatchObject({ code: 'invalid_proof' });
    await expect(verifyProof(proof, { method: 'POST', url: 'https://hashbin.org/api/upload', credential: 'x.y.z', jkt: dev.jkt, now: NOW })).rejects.toMatchObject({ code: 'invalid_proof' });
    await expect(verifyProof(proof, { method: 'POST', url: 'https://hashbin.org/api/upload', credential, jkt: dev.jkt, now: NOW + 200 })).rejects.toMatchObject({ code: 'stale_proof' });
  });
  it('refuses a proof whose jwk is not a point on the curve as invalid_proof, not a crash', async () => {
    const dev = await device(); const credential = 'a.b.c';
    const proof = await createProof({ ...dev, method: 'GET', url: 'https://hashbin.org/x', credential, now: NOW });
    const [h, p, sig] = proof.split('.');
    const header = JSON.parse(new TextDecoder().decode(unb64u(h)));
    header.jwk = { ...header.jwk, y: b64u(new Uint8Array(32).fill(1)) };
    const forged = `${b64u(new TextEncoder().encode(JSON.stringify(header)))}.${p}.${sig}`;
    await expect(verifyProof(forged, { method: 'GET', url: 'https://hashbin.org/x', credential, now: NOW })).rejects.toMatchObject({ code: 'invalid_proof' });
  });
  it('keeps the replay cache bounded', () => {
    const cache = new ReplayCache(10, 3);
    for (const id of ['a', 'b', 'c', 'd']) expect(cache.check(id, 0)).toBe(true);
    expect(cache.seen.size).toBe(3);
    expect(cache.check('d', 1)).toBe(false);
    expect(cache.check('d', 20)).toBe(true);
  });
});

describe('status lists', () => {
  it('uses LSB-first bit order and zlib', async () => {
    let bytes = new Uint8Array(1); bytes = setBit(bytes, 0); bytes = setBit(bytes, 9); bytes = setBit(bytes, 100000);
    expect(bytes[0]).toBe(1); expect(bytes[1]).toBe(2);
    const decoded = await decodeStatusList(await encodeStatusList(bytes));
    expect([0, 1, 9, 100000, 5e6].map(i => getBit(decoded, i))).toEqual([1, 0, 1, 1, 0]);
  });
  it('stops inflating a list that is too large', async () => {
    const { deflate, inflate } = await import('./status-list.js');
    const bomb = await deflate(new Uint8Array(1 << 20));
    await expect(inflate(bomb, 1024)).rejects.toThrow(/too large/);
    expect((await inflate(bomb)).length).toBe(1 << 20);
  });
  it('decodes the IETF draft example', async () => {
    // draft-ietf-oauth-status-list §4.1 example: status[0]=1, [1]=0, [2]=0, [3]=1, [4]=1, [5]=1, [6]=0, [7]=1, [8]=1, [9]=1, ...
    const bytes = await decodeStatusList({ bits: 1, lst: 'eNrbuRgAAhcBXQ' });
    expect([0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map(i => getBit(bytes, i))).toEqual([1, 0, 0, 1, 1, 1, 0, 1, 1, 1]);
  });
});

describe('verifier', () => {
  async function setup({ revoked = false, grants, catalog } = {}) {
    const key = await issuerKey(); const signer = await issuerSigner(key); const dev = await device();
    const credential = await signCredential(payload(dev, grants ? { grants } : {}), signer);
    const uri = `${ISSUER}/status/v1/lists/0`;
    const list = await signStatusList({ uri, bytes: revoked ? setBit(new Uint8Array(1), 5) : new Uint8Array(1), issuer: ISSUER, now: NOW }, signer);
    let fetches = 0;
    const fetch = async url => { fetches++; if (url.endsWith('/.well-known/jwks.json')) return Response.json(jwksFor([key])); if (url === uri) return new Response(list); return new Response('nope', { status: 404 }); };
    const verifier = createVerifier({ audience: 'hashbin.org', fetch, now: () => NOW + 1, catalog });
    const request = async (method = 'POST', url = 'https://hashbin.org/api/content', extra = {}) => new Request(url, { method, headers: { Authorization: `DBA ${credential}`, DPoP: await createProof({ ...dev, method, url, credential, now: NOW }), ...extra } });
    return { verifier, request, credential, signer, fetches: () => fetches, dev };
  }
  it('checks a DBA-Confirmation header for credentials that need one (spec/credential.md §9)', async () => {
    const { verifier, request, signer, dev } = await setup({ grants: [{ actions: ['hashbin:content:write'], require: { confirmation: true } }], catalog: [{ action: 'hashbin:content:write', gates: { fail_open: false } }] });
    const confirm = extra => signJws({ typ: CONFIRMATION_TYP, kid: signer.kid }, { iss: ISSUER, sub: 'dev_ABCDEFGH12', aud: ['hashbin.org'], cid: 'crd_ABCDEFGH12', cnf: { jkt: dev.jkt }, iat: NOW, exp: NOW + 3600, gates: [], by_timeout: false, ...extra }, signer.key);
    const check = { action: 'hashbin:content:write' };
    expect(await verifier.verifyRequest(await request(), check)).toMatchObject({ allow: false, reasons: [['confirmation_required']] });
    expect(await verifier.verifyRequest(await request('POST', undefined, { 'DBA-Confirmation': await confirm() }), check)).toMatchObject({ allow: true });
    expect(await verifier.verifyRequest(await request('POST', undefined, { 'DBA-Confirmation': await confirm({ iat: NOW - 3600, exp: NOW - 60 }) }), check)).toMatchObject({ allow: false, reasons: [['confirmation_expired']] });
    expect(await verifier.verifyRequest(await request('POST', undefined, { 'DBA-Confirmation': await confirm({ by_timeout: true }) }), check)).toMatchObject({ allow: false, reasons: [['confirmation_by_timeout_refused']] });
    expect(await verifier.verifyRequest(await request('POST', undefined, { 'DBA-Confirmation': await confirm({ cid: 'crd_OTHER00001' }) }), check)).toMatchObject({ allow: false, status: 401, code: 'confirmation_wrong_credential' });
  });
  it('makes actions whose catalog entry requires gates online only', async () => {
    const { verifier, request } = await setup({ catalog: [{ action: 'hashbin:content:write', gates: { require: true } }] });
    expect(await verifier.verifyRequest(await request(), { action: 'hashbin:content:write' })).toMatchObject({ allow: false, code: 'online_required', online_required: true });
  });
  it('allows a granted action and caches the JWKS and status list', async () => {
    const { verifier, request, fetches } = await setup();
    const result = await verifier.verifyRequest(await request(), { action: 'hashbin:content:write' });
    expect(result).toMatchObject({ allow: true, status: 200, device: 'dev_ABCDEFGH12', account: 'acct_1' });
    await verifier.verifyRequest(await request(), { action: 'hashbin:content:write' });
    expect(fetches()).toBe(2);
  });
  it('denies ungranted actions, revoked credentials and missing proofs', async () => {
    const ok = await setup();
    expect(await ok.verifier.verifyRequest(await ok.request(), { action: 'hashbin:content:delete' })).toMatchObject({ allow: false, status: 403, code: 'forbidden' });
    const missing = new Request('https://hashbin.org/api/content', { method: 'POST', headers: { Authorization: `DBA ${ok.credential}` } });
    expect(await ok.verifier.verifyRequest(missing, { action: 'hashbin:content:write' })).toMatchObject({ allow: false, code: 'proof_required' });
    const revoked = await setup({ revoked: true });
    expect(await revoked.verifier.verifyRequest(await revoked.request(), { action: 'hashbin:content:write' })).toMatchObject({ allow: false, status: 401, code: 'revoked' });
  });
  it('treats auth schemes case-insensitively and backs off while the issuer is down', async () => {
    const { verifier, credential, dev } = await setup();
    const url = 'https://hashbin.org/api/content';
    const lower = new Request(url, { method: 'POST', headers: { Authorization: `dba ${credential}`, DPoP: await createProof({ ...dev, method: 'POST', url, credential, now: NOW }) } });
    expect((await verifier.verifyRequest(lower, { action: 'hashbin:content:write' })).allow).toBe(true);
    let calls = 0;
    const down = createVerifier({ audience: 'hashbin.org', fetch: async () => { calls++; throw new Error('offline'); }, now: () => NOW });
    const request = () => new Request(url, { method: 'POST', headers: { Authorization: `DBA ${credential}`, DPoP: 'x' } });
    expect(await down.verifyRequest(request(), { action: 'hashbin:content:write' })).toMatchObject({ allow: false, status: 503, code: 'jwks_unavailable' });
    await down.verifyRequest(request(), { action: 'hashbin:content:write' });
    expect(calls).toBe(1);
    expect(await down.verifyRequest(new Request(url, { headers: { Authorization: 'DBA not-a-jws' } }), { action: 'x:y' })).toMatchObject({ code: 'invalid_format' });
    expect(calls).toBe(1);
  });
  it('keeps a revocation it has seen when a stale copy of the list comes back, and refuses lists without exp', async () => {
    const key = await issuerKey(); const signer = await issuerSigner(key); const dev = await device();
    const credential = await signCredential(payload(dev), signer);
    const uri = `${ISSUER}/status/v1/lists/0`;
    const fresh = await signStatusList({ uri, bytes: setBit(new Uint8Array(1), 5), issuer: ISSUER, now: NOW }, signer);
    const stale = await signStatusList({ uri, bytes: new Uint8Array(1), issuer: ISSUER, now: NOW - 3600 }, signer);
    let served = fresh; let now = NOW + 1;
    const fetch = async url => url.endsWith('/.well-known/jwks.json') ? Response.json(jwksFor([key])) : new Response(served);
    const verifier = createVerifier({ audience: 'hashbin.org', fetch, now: () => now });
    await expect(verifier.verify(credential)).rejects.toMatchObject({ code: 'revoked' });
    // A CDN edge that still holds the list from before the revocation cannot undo it.
    served = stale; now += 301;
    await expect(verifier.verify(credential)).rejects.toMatchObject({ code: 'revoked' });
    const noExp = await signJws({ typ: 'statuslist+jwt', kid: signer.kid }, { iss: ISSUER, sub: uri, iat: NOW, ttl: 60, status_list: await encodeStatusList(new Uint8Array(1)) }, signer.key);
    served = noExp;
    const other = createVerifier({ audience: 'hashbin.org', fetch, now: () => now });
    await expect(other.verify(credential)).rejects.toMatchObject({ code: 'status_unavailable' });
  });
  it('refetches the JWKS for an unknown kid at most once per cooldown', async () => {
    const key = await issuerKey(); const newKey = await issuerKey('k2'); const dev = await device();
    let published = [key]; let fetches = 0; let now = NOW + 1;
    const fetch = async url => { if (url.endsWith('/.well-known/jwks.json')) fetches++; return Response.json(jwksFor(published)); };
    const verifier = createVerifier({ audience: 'hashbin.org', fetch, now: () => now });
    await verifier.jwks();
    const made = await signCredential(payload(dev), await issuerSigner(newKey));
    // Junk kids (anyone can send them) cost no fetch inside the cooldown.
    for (let i = 0; i < 5; i++) await expect(verifier.verify(made)).rejects.toMatchObject({ code: 'unknown_kid' });
    expect(fetches).toBe(1);
    // A key published since is picked up once the cooldown has passed.
    published = [key, newKey]; now += 30;
    await expect(verifier.verify(made)).rejects.not.toMatchObject({ code: 'unknown_kid' });
    expect(fetches).toBe(2);
  });
  it('accepts access tokens as bearer credentials', async () => {
    const { verifier, signer } = await setup();
    const token = await signAccessToken({ ...payload({ jkt: 'x' }), jti: 'tok_1', exp: NOW + 600, cnf: undefined }, signer);
    expect(decodeJws(token).header.typ).toBe('dba-access+jwt');
    const result = await verifier.verifyRequest(new Request('https://hashbin.org/x', { headers: { Authorization: `Bearer ${token}` } }), { action: 'hashbin:content:write' });
    expect(result.allow).toBe(true);
  });
});
