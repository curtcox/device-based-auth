import { describe, it, expect, beforeEach } from 'vitest';
import { testEnv, call, newDevice, enroll, worker, ORIGIN } from '../test-utils/env.js';
import { createVerifier, createProof, generateKeyPair, inspectCredential, signCredential, issuerSigner } from '../packages/verify/src/index.js';

// Master plan §10 "mass force-renew": after an issuer key is withdrawn (compromised), devices renew
// the credentials it signed instead of re-enrolling, and nothing signed with it is trusted otherwise.

const fund = (env, account) => call(env, 'POST', '/api/v1/dev/deposit', { auth: account, body: { amount_microdollars: 1_000_000 } });
const balance = async (env, account) => (await call(env, 'GET', '/api/v1/account', { auth: account })).body.balance_microdollars;

let env; let oldKey;
beforeEach(async () => {
  env = await testEnv();
  oldKey = JSON.parse(env.ISSUER_KEYS)[0];
});

/** Withdraw the test key and make a fresh one active, as the runbook says. */
async function withdraw() {
  const pair = await generateKeyPair(true);
  const fresh = { kid: 'test-2', jwk: await crypto.subtle.exportKey('jwk', pair.privateKey) };
  env.ISSUER_KEYS = JSON.stringify([fresh, { ...oldKey, withdrawn: true }]);
}

describe('issuer key withdrawal and recovery renewal', () => {
  it('drops a withdrawn key from the JWKS and the CA bundle', async () => {
    await withdraw();
    const jwks = (await call(env, 'GET', '/.well-known/jwks.json')).body;
    expect(jwks.keys.map(k => k.kid)).toEqual(['test-2']);
    const bundle = (await call(env, 'GET', '/.well-known/dba-ca.pem')).body;
    expect(bundle.match(/BEGIN CERTIFICATE/g)).toHaveLength(1);
  });

  it('renews a credential signed by a withdrawn key for free, once, with the new key', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { lifetime_seconds: 3600 })).approve.body.credential;
    const { cid, status } = inspectCredential(credential).payload;
    await withdraw();
    const before = await balance(env, 'alice');

    // Relying parties refuse it: the key is no longer in the JWKS.
    const verifier = createVerifier({ issuer: ORIGIN, audience: 'hashbin.org', fetch: (url, init) => worker.fetch(new Request(url, init), env) });
    const url = 'https://hashbin.org/api/content';
    const request = new Request(url, { method: 'POST', headers: { Authorization: `DBA ${credential}`, DPoP: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential }) } });
    expect(await verifier.verifyRequest(request, { action: 'hashbin:content:write' })).toMatchObject({ allow: false, code: 'unknown_kid' });

    // DBA's own API says what to do instead of a bare unknown_kid.
    const tokenPath = '/api/v1/token';
    const refused = await call(env, 'POST', tokenPath, { headers: await device.headers('POST', tokenPath, credential), body: { audience: 'hashbin.org' } });
    expect(refused.status).toBe(401);
    expect(refused.body).toMatchObject({ code: 'reissue_required', cid });

    const path = `/api/v1/credentials/${cid}/renew`;
    const renewed = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: {} });
    expect(renewed.status).toBe(200);
    expect(renewed.body).toMatchObject({ cid, jti: `${cid}.2`, recovered: true, cost_microdollars: 0 });
    const fresh = inspectCredential(renewed.body.credential);
    expect(fresh.header.kid).toBe('test-2');
    expect(fresh.payload.status).toEqual(status);
    expect(await balance(env, 'alice')).toBe(before);

    const again = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: {} });
    expect(again.body.code).toBe('superseded');

    const audit = await call(env, 'GET', '/api/v1/audit', { auth: 'alice' });
    expect(audit.body.items.some(e => e.type === 'credential.recovered' && e.cid === cid)).toBe(true);
  });

  it('refuses a credential forged with the leaked key, even one reusing a real cid and jti', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { lifetime_seconds: 3600 })).approve.body.credential;
    const { payload } = inspectCredential(credential);
    await withdraw();
    // The attacker holds the old private key and re-signs the real credential with wider grants.
    const forged = await signCredential({ ...payload, grants: [{ actions: ['hashbin:*'] }] }, await issuerSigner(oldKey));
    const path = `/api/v1/credentials/${payload.cid}/renew`;
    const refused = await call(env, 'POST', path, { headers: await device.headers('POST', path, forged), body: {} });
    expect(refused.status).toBe(403);
    expect(refused.body.code).toBe('unknown_credential');
  });

  it('still refuses revoked credentials and credentials signed by keys never configured', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { lifetime_seconds: 3600 })).approve.body.credential;
    const { cid } = inspectCredential(credential).payload;
    expect((await call(env, 'DELETE', `/api/v1/credentials/${cid}`, { auth: 'alice' })).status).toBe(200);
    await withdraw();
    const path = `/api/v1/credentials/${cid}/renew`;
    expect((await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: {} })).body.code).toBe('revoked');

    const stranger = await generateKeyPair(true);
    const unknown = await signCredential(inspectCredential(credential).payload, await issuerSigner({ kid: 'nobody', jwk: await crypto.subtle.exportKey('jwk', stranger.privateKey) }));
    expect((await call(env, 'POST', path, { headers: await device.headers('POST', path, unknown), body: {} })).body.code).toBe('unknown_kid');
  });
});
