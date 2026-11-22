import { describe, it, expect, beforeEach } from 'vitest';
import { price } from './utils/pricing.js';
import { testEnv, call, newDevice } from '../test-utils/env.js';
import { inspectCredential } from '../packages/verify/src/index.js';

// Master plan §7.1: Idempotency-Key on POSTs that cost money. A repeated key must return what the
// first request made, never a second thing for the first one's price.

const fund = (env, account, amount = 1_000_000) => call(env, 'POST', '/api/v1/dev/deposit', { auth: account, body: { amount_microdollars: amount } });
const balance = async (env, account) => (await call(env, 'GET', '/api/v1/account', { auth: account })).body.balance_microdollars;
const listed = async (env, account) => (await call(env, 'GET', '/api/v1/credentials', { auth: account })).body.items;

let env;
beforeEach(async () => { env = await testEnv(); await fund(env, 'alice'); });

describe('Idempotency-Key on POST /api/v1/credentials', () => {
  it('returns the first credential for a retried request, charging and storing once', async () => {
    const body = { public_jwk: (await newDevice()).publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], device: { name: 'fleet 1' } };
    const before = await balance(env, 'alice');
    const first = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body, headers: { 'Idempotency-Key': 'retry-1' } });
    expect(first.status).toBe(200);
    const again = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body, headers: { 'Idempotency-Key': 'retry-1' } });
    expect(again.status).toBe(200);
    expect(again.body).toMatchObject({ credential: first.body.credential, cid: first.body.cid, device_id: first.body.device_id, cost_microdollars: 0, idempotent_replay: true });
    expect(again.headers.get('X-DBA-Cost-Microdollars')).toBe('0');
    expect(await balance(env, 'alice')).toBe(before - price('issue'));
    expect((await listed(env, 'alice')).map(c => c.cid)).toEqual([first.body.cid]);
  });

  it('refuses the same key for a different request (another key, audience or grants)', async () => {
    const body = { public_jwk: (await newDevice()).publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }] };
    await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body, headers: { 'Idempotency-Key': 'k' } });
    const before = await balance(env, 'alice');
    for (const other of [{ ...body, public_jwk: (await newDevice()).publicJwk }, { ...body, aud: ['hashbin.org', 'cronly.org'] }, { ...body, grants: [{ actions: ['hashbin:content:write'], require: { online: true } }] }]) {
      const reused = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: other, headers: { 'Idempotency-Key': 'k' } });
      expect(`${reused.status} ${reused.body.code}`).toBe('422 idempotency_key_reused');
    }
    expect(await balance(env, 'alice')).toBe(before);
    expect(await listed(env, 'alice')).toHaveLength(1);
  });

  it('keeps keys apart per account, and issues anew without a key', async () => {
    await fund(env, 'bob');
    const body = { public_jwk: (await newDevice()).publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }] };
    const alice = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body, headers: { 'Idempotency-Key': 'same' } });
    const bob = await call(env, 'POST', '/api/v1/credentials', { auth: 'bob', body, headers: { 'Idempotency-Key': 'same' } });
    expect(bob.status).toBe(200);
    expect(inspectCredential(bob.body.credential).payload.acct).toBe('bob');
    expect(bob.body.cid).not.toBe(alice.body.cid);
    const plain = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body });
    expect(plain.body.cid).not.toBe(alice.body.cid);
    expect(await listed(env, 'alice')).toHaveLength(2);
  });

  it('refuses an overlong key', async () => {
    const body = { public_jwk: (await newDevice()).publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }] };
    const response = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body, headers: { 'Idempotency-Key': 'x'.repeat(129) } });
    expect(response.status).toBe(400);
    expect(response.body.code).toBe('invalid_idempotency_key');
  });
});

describe('approving one enrollment twice at once', () => {
  it('issues and charges once; both approvals return the same credential', async () => {
    const device = await newDevice();
    const start = await call(env, 'POST', '/api/v1/enrollments', { body: { request: await device.enrollRequest({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], device: { name: 'double click', kind: 'cli' } }) } });
    const before = await balance(env, 'alice');
    const approve = () => call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: start.body.request } });
    const results = await Promise.all([approve(), approve()]);
    const ok = results.filter(r => r.status === 200);
    expect(ok.length).toBeGreaterThanOrEqual(1);
    for (const r of results) if (r.status !== 200) expect(r.body.code).toBe('already_decided');
    expect(new Set(ok.map(r => r.body.cid)).size).toBe(1);
    expect(await balance(env, 'alice')).toBe(before - price('issue'));
    expect(await listed(env, 'alice')).toHaveLength(1);
  });
});
