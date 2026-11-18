import { describe, it, expect, beforeEach } from 'vitest';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';
import { inspectCredential, signJws } from '../packages/verify/src/index.js';

// Master plan §7.1: every billable route takes ?dry_run=1, and billable responses carry the cost
// and, for callers allowed to read the account, the remaining balance.

const fund = (env, account, amount = 1_000_000) => call(env, 'POST', '/api/v1/dev/deposit', { auth: account, body: { amount_microdollars: amount } });
const balance = async (env, account) => (await call(env, 'GET', '/api/v1/account', { auth: account })).body.balance_microdollars;

let env;
beforeEach(async () => { env = await testEnv(); });

describe('dry runs', () => {
  it('quotes an issue without validating, issuing or charging', async () => {
    await fund(env, 'alice');
    const before = await balance(env, 'alice');
    const quote = await call(env, 'POST', '/api/v1/credentials?dry_run=1', { auth: 'alice', body: { nonsense: true } });
    expect(quote.status).toBe(200);
    expect(quote.body).toEqual({ dry_run: true, op: 'issue', price_microdollars: 85, balance_microdollars: before, sufficient: true, cost_microdollars: 0 });
    expect(quote.headers.get('X-DBA-Balance-Microdollars')).toBe(String(before));
    expect(await balance(env, 'alice')).toBe(before);
    expect((await call(env, 'GET', '/api/v1/credentials', { auth: 'alice' })).body.items).toHaveLength(0);
  });

  it('says when the balance would not cover the price', async () => {
    await fund(env, 'bob', 50);
    const quote = await call(env, 'POST', '/api/v1/enrollments/approve?dry_run=1', { auth: 'bob', body: {} });
    expect(quote.body).toMatchObject({ op: 'issue', price_microdollars: 85, balance_microdollars: 50, sufficient: false });
  });

  it('still requires authentication and access', async () => {
    expect((await call(env, 'POST', '/api/v1/credentials?dry_run=1', { body: {} })).status).toBe(401);
  });

  it('quotes renewal and rotation for a device without revealing the owner\'s balance', async () => {
    await fund(env, 'alice');
    const device = await newDevice(); const next = await newDevice();
    const credential = (await enroll(env, 'alice', device)).approve.body.credential;
    const { cid } = inspectCredential(credential).payload;
    const path = `/api/v1/credentials/${cid}/renew`;
    const renew = await call(env, 'POST', `${path}?dry_run=1`, { headers: await device.headers('POST', path, credential), body: {} });
    expect(renew.body).toEqual({ dry_run: true, op: 'renew', price_microdollars: 25, cost_microdollars: 0 });
    const keyProof = await signJws({ typ: 'dba-rotate+jwt', jwk: next.publicJwk }, { cid, iat: Math.floor(Date.now() / 1000) }, next.privateKey);
    const rotate = await call(env, 'POST', `${path}?dry_run=1`, { headers: await device.headers('POST', path, credential), body: { new_key_proof: keyProof } });
    expect(rotate.body).toMatchObject({ op: 'issue', price_microdollars: 85 });
    // Nothing happened: the credential is still version 1 and renews for real afterwards.
    const real = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: {} });
    expect(real.body).toMatchObject({ jti: `${cid}.2`, cost_microdollars: 25 });
    expect(real.body.balance_microdollars).toBeUndefined();
  });

  it('quotes the public enrollment-token redemption with the price only', async () => {
    const quote = await call(env, 'POST', '/api/v1/enrollments/redeem?dry_run=1', { body: {} });
    expect(quote.body).toEqual({ dry_run: true, op: 'issue', price_microdollars: 85, cost_microdollars: 0 });
  });
});

describe('balance after billable calls', () => {
  it('reports the remaining balance to the paying owner', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const { approve } = await enroll(env, 'alice', device);
    expect(approve.body).toMatchObject({ cost_microdollars: 85, balance_microdollars: 1_000_000 - 85 });
    const created = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: (await newDevice()).publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }] } });
    expect(created.body).toMatchObject({ cost_microdollars: 85, balance_microdollars: 1_000_000 - 170 });
    expect(created.headers.get('X-DBA-Balance-Microdollars')).toBe(String(1_000_000 - 170));
  });

  it('reports it to API keys that may read the account, not to others', async () => {
    await fund(env, 'alice');
    const key = async scopes => `ApiKey ${(await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: scopes.join(' '), scopes } })).body.secret}`;
    const reader = await key(['credentials:read', 'account:read']);
    const blind = await key(['credentials:read']);
    const seen = await call(env, 'GET', '/api/v1/credentials', { auth: reader });
    expect(seen.body).toMatchObject({ cost_microdollars: 5, balance_microdollars: 1_000_000 - 5 });
    const hidden = await call(env, 'GET', '/api/v1/credentials', { auth: blind });
    expect(hidden.body.cost_microdollars).toBe(5);
    expect(hidden.body.balance_microdollars).toBeUndefined();
    expect(hidden.headers.get('X-DBA-Balance-Microdollars')).toBeNull();
  });

  it('charges an API key\'s dry run as a read, since it reads the balance', async () => {
    await fund(env, 'alice');
    const created = await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'issuer', scopes: ['credentials:issue', 'account:read'] } });
    const quote = await call(env, 'POST', '/api/v1/credentials?dry_run=1', { auth: `ApiKey ${created.body.secret}`, body: {} });
    expect(quote.body).toEqual({ dry_run: true, op: 'issue', price_microdollars: 85, balance_microdollars: 1_000_000 - 5, sufficient: true, cost_microdollars: 5 });
  });
});
