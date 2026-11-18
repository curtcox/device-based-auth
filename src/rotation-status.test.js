import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';
import { createProof, inspectCredential, signJws } from '../packages/verify/src/index.js';

// STATUS L12: status-list indexes are per shard, so a credential rotated into another shard can get
// the same index it had before. Only the (index, list) pair identifies its entry; comparing the
// index alone let the replaced key keep using the old, unexpired version.

let env;
beforeEach(async () => {
  env = await testEnv({ STATUS_SHARDS: '2' });
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'operator', body: { amount_microdollars: 1_000_000 } });
});
afterEach(() => vi.restoreAllMocks());

/** Enroll in shard 0, then rotate into shard 1: both versions hold index 0. */
async function rotatedAcrossShards() {
  const random = vi.spyOn(Math, 'random');
  const device = await newDevice(); const next = await newDevice();
  random.mockReturnValue(0);
  const credential = (await enroll(env, 'alice', device)).approve.body.credential;
  const { cid } = inspectCredential(credential).payload;
  random.mockReturnValue(0.99);
  const path = `/api/v1/credentials/${cid}/renew`;
  const keyProof = await signJws({ typ: 'dba-rotate+jwt', jwk: next.publicJwk }, { cid, iat: Math.floor(Date.now() / 1000) }, next.privateKey);
  const rotated = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: { new_key_proof: keyProof } });
  random.mockRestore();
  expect(rotated.body.rotated).toBe(true);
  const before = inspectCredential(credential).payload.status.status_list;
  const after = inspectCredential(rotated.body.credential).payload.status.status_list;
  expect(after.idx).toBe(before.idx);
  expect(after.uri).not.toBe(before.uri);
  return { device, next, credential, rotated: rotated.body.credential };
}

describe('a rotated-away credential version', () => {
  it('cannot call devicebasedauth.org even when its index repeats in another shard', async () => {
    const { device, next, credential, rotated } = await rotatedAcrossShards();
    const old = await call(env, 'POST', '/api/v1/token', { headers: await device.headers('POST', '/api/v1/token', credential), body: { audience: 'hashbin.org' } });
    expect(old.status).toBe(401);
    expect(old.body.code).toBe('revoked');
    const current = await call(env, 'POST', '/api/v1/token', { headers: await next.headers('POST', '/api/v1/token', rotated), body: { audience: 'hashbin.org' } });
    expect(current.status).toBe(200);
  });

  it('is denied by online authorize even when its index repeats in another shard', async () => {
    const { device, next, credential, rotated } = await rotatedAcrossShards();
    const key = await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'verifier', scopes: ['authorize'] } });
    const url = 'https://hashbin.org/api/content';
    const ask = async (holder, jws) => (await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key.body.secret}`, body: {
      credential: jws, proof: await createProof({ privateKey: holder.privateKey, publicJwk: holder.publicJwk, method: 'POST', url, credential: jws }),
      request: { method: 'POST', url }, audience: 'hashbin.org', action: 'hashbin:content:write'
    } })).body;
    expect(await ask(device, credential)).toMatchObject({ allow: false, code: 'revoked' });
    expect(await ask(next, rotated)).toMatchObject({ allow: true });
  });
});

describe('DPoP proofs on devicebasedauth.org\'s own API', () => {
  it('accepts each proof once, so captured headers cannot be replayed with another body (STATUS L12)', async () => {
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { aud: ['hashbin.org', 'cronly.org'], grants: [{ actions: ['hashbin:content:write', 'cronly:run'] }] })).approve.body.credential;
    const headers = await device.headers('POST', '/api/v1/token', credential);
    expect((await call(env, 'POST', '/api/v1/token', { headers, body: { audience: 'hashbin.org' } })).status).toBe(200);
    const replayed = await call(env, 'POST', '/api/v1/token', { headers, body: { audience: 'cronly.org' } });
    expect(replayed.status).toBe(401);
    expect(replayed.body.code).toBe('replayed_proof');
    const fresh = await call(env, 'POST', '/api/v1/token', { headers: await device.headers('POST', '/api/v1/token', credential), body: { audience: 'cronly.org' } });
    expect(fresh.status).toBe(200);
  });
});
