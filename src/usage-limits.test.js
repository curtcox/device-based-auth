import { describe, it, expect, beforeEach } from 'vitest';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';
import { createProof, inspectCredential } from '../packages/verify/src/index.js';
import { sharedUsage } from './services/credentials.js';
import { usageCounter } from './durable-objects/account-do.js';

// A `limits.uses` must not multiply: not through delegation (each delegate used to get its own
// counter) and not through access tokens (whose grant indexes differ from the credential's).
// STATUS L12.

const fund = (env, account) => call(env, 'POST', '/api/v1/dev/deposit', { auth: account, body: { amount_microdollars: 1_000_000 } });
const URL_ = 'https://hashbin.org/api/content';

let env; let verifierKey;
beforeEach(async () => {
  env = await testEnv();
  await fund(env, 'alice'); await fund(env, 'operator');
  verifierKey = (await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'hashbin verifier', scopes: ['authorize'] } })).body.secret;
});

async function askWithDevice(device, credential, action = 'hashbin:content:write') {
  const proof = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url: URL_, credential });
  return (await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${verifierKey}`, body: { credential, proof, request: { method: 'POST', url: URL_ }, audience: 'hashbin.org', action } })).body;
}
const askWithToken = async (token, action = 'hashbin:content:write') =>
  (await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${verifierKey}`, body: { credential: token, audience: 'hashbin.org', action } })).body;

describe('usage limits through delegation', () => {
  it('makes a delegate spend its parent\'s counter', async () => {
    const limited = { actions: ['hashbin:content:write'], limits: { uses: { count: 2, per: 'day' } } };
    const parent = await newDevice();
    const credential = (await enroll(env, 'alice', parent, { aud: ['devicebasedauth.org', 'hashbin.org'], grants: [{ actions: ['dba:credentials:issue'] }, limited] })).approve.body.credential;
    const delegate = async () => {
      const child = await newDevice();
      const issued = await call(env, 'POST', '/api/v1/credentials', { headers: await parent.headers('POST', '/api/v1/credentials', credential), body: { public_jwk: child.publicJwk, aud: ['hashbin.org'], grants: [limited] } });
      expect(issued.status).toBe(200);
      return { child, credential: issued.body.credential };
    };
    const first = await delegate(); const second = await delegate();
    expect((await askWithDevice(first.child, first.credential)).allow).toBe(true);
    expect((await askWithDevice(second.child, second.credential)).allow).toBe(true);
    // Two uses a day in all: neither the parent nor a third delegate gets more.
    expect(await askWithDevice(parent, credential)).toMatchObject({ allow: false, reasons: ['usage_limit_reached'] });
    const third = await delegate();
    expect(await askWithDevice(third.child, third.credential)).toMatchObject({ allow: false, reasons: ['usage_limit_reached'] });
  });

  it('keeps a delegate\'s own counter when its limit is its own', async () => {
    const parent = await newDevice();
    const credential = (await enroll(env, 'alice', parent, { aud: ['devicebasedauth.org', 'hashbin.org'], grants: [{ actions: ['dba:credentials:issue'] }, { actions: ['hashbin:content:*'] }] })).approve.body.credential;
    const child = await newDevice();
    const issued = await call(env, 'POST', '/api/v1/credentials', { headers: await parent.headers('POST', '/api/v1/credentials', credential), body: { public_jwk: child.publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'], limits: { uses: { count: 1, per: 'day' } } }] } });
    expect((await askWithDevice(child, issued.body.credential)).allow).toBe(true);
    expect((await askWithDevice(child, issued.body.credential)).reasons).toEqual(['usage_limit_reached']);
  });
});

describe('usage limits through access tokens', () => {
  it('counts a token\'s uses on the credential grant it came from', async () => {
    const device = await newDevice();
    // The token for hashbin.org carries only grant 1, at index 0.
    const credential = (await enroll(env, 'alice', device, { aud: ['cronly.org', 'hashbin.org'], grants: [{ actions: ['cronly:*'], limits: { uses: { count: 5, per: 'day' } } }, { actions: ['hashbin:content:write'], limits: { uses: { count: 2, per: 'day' } } }] })).approve.body.credential;
    const token = (await call(env, 'POST', '/api/v1/token', { headers: await device.headers('POST', '/api/v1/token', credential), body: { audience: 'hashbin.org' } })).body.access_token;
    expect(inspectCredential(token).payload.grants).toHaveLength(1);
    expect((await askWithToken(token)).allow).toBe(true);
    expect((await askWithDevice(device, credential)).allow).toBe(true);
    expect(await askWithToken(token)).toMatchObject({ allow: false, reasons: ['usage_limit_reached'] });
    expect(await askWithDevice(device, credential)).toMatchObject({ allow: false, reasons: ['usage_limit_reached'] });
  });
});

describe('usageCounter and sharedUsage', () => {
  const cred = { cid: 'crd_child', parent_cid: 'crd_parent', usage_from: [null, 3], grants: [{ actions: ['cronly:run'] }, { actions: ['hashbin:content:write'] }] };
  it('maps token indexes and delegated grants', () => {
    expect(usageCounter(cred, 0)).toBe('crd_child:0');
    expect(usageCounter(cred, 1)).toBe('crd_parent:3');
    expect(usageCounter(cred, 0, 'hashbin')).toBe('crd_parent:3');
    expect(usageCounter(cred, 1, 'hashbin')).toBeNull();
    expect(usageCounter(cred, 2)).toBeNull();
  });
  it('shares only limits that came from the parent', () => {
    const uses = { uses: { count: 3, per: 'day' } };
    expect(sharedUsage([{ actions: ['hashbin:content:write'] }], [{ actions: ['hashbin:*'], limits: uses }])).toBeUndefined();
    expect(sharedUsage([{ actions: ['hashbin:content:write'], limits: uses }], [{ actions: ['dba:session'] }, { actions: ['hashbin:*'], limits: uses }])).toEqual([1]);
    expect(sharedUsage([{ actions: ['hashbin:content:write'], limits: uses }], [{ actions: ['hashbin:*'], limits: uses }, { actions: ['hashbin:*'] }])).toBeUndefined();
  });
});
