import { describe, it, expect, beforeEach } from 'vitest';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';
import { inspectCredential } from '../packages/verify/src/index.js';

const fund = (env, account, dollars = 1) => call(env, 'POST', '/api/v1/dev/deposit', { auth: account, body: { amount_microdollars: dollars * 1_000_000 } });
const TEMPLATE = { name: 'Build agents', aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write', 'hashbin:content:extend'] }], lifetime_seconds: 3600, max_uses: 2, expires_in_days: 1 };

let env;
beforeEach(async () => { env = await testEnv(); await fund(env, 'alice'); });

const create = (body = TEMPLATE, auth = 'alice') => call(env, 'POST', '/api/v1/enrollment-tokens', { auth, body });
const redeem = async (token, device, payload = {}) => call(env, 'POST', '/api/v1/enrollments/redeem', { body: { enrollment_token: token, request: await device.enrollRequest({ device: { name: 'agent', kind: 'agent' }, ...payload }) } });

describe('enrollment tokens (B2)', () => {
  it('lets devices enroll without a per-device approval, up to max_uses', async () => {
    const created = await create();
    expect(created.status).toBe(200);
    expect(created.body).toMatchObject({ name: 'Build agents', max_uses: 2, uses: 0, state: 'active', cost_microdollars: 0 });
    expect(created.body.token).toMatch(/^dbae_/);
    expect(created.body.hash).toBeUndefined();

    const first = await redeem(created.body.token, await newDevice());
    expect(first.status).toBe(200);
    expect(first.body).toMatchObject({ status: 'approved', cost_microdollars: 85 });
    const { payload } = inspectCredential(first.body.credential);
    expect(payload).toMatchObject({ acct: 'alice', aud: ['hashbin.org'], grants: TEMPLATE.grants });
    expect(payload.exp - payload.iat).toBe(3600);

    // A device may ask for less than the template, never more.
    const narrower = await redeem(created.body.token, await newDevice(), { aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:extend'] }], lifetime_seconds: 600 });
    expect(narrower.status).toBe(200);
    expect(inspectCredential(narrower.body.credential).payload.exp - inspectCredential(narrower.body.credential).payload.iat).toBe(600);

    const third = await redeem(created.body.token, await newDevice());
    expect(third.status).toBe(403);
    expect(third.body.code).toBe('enrollment_token_inactive');

    const list = await call(env, 'GET', '/api/v1/enrollment-tokens', { auth: 'alice' });
    expect(list.body.items[0]).toMatchObject({ uses: 2, state: 'used_up' });
    const detail = await call(env, 'GET', `/api/v1/credentials/${first.body.cid}`, { auth: 'alice' });
    expect(detail.body).toMatchObject({ source: 'enrollment-token', enrollment_token: created.body.id });
  });

  it('refuses wider grants, other audiences, forged or revoked tokens, and stores nothing', async () => {
    const created = await create({ ...TEMPLATE, max_uses: 5 });
    const token = created.body.token;
    expect((await redeem(token, await newDevice(), { grants: [{ actions: ['hashbin:content:delete'] }] })).body.code).toBe('not_narrower');
    expect((await redeem(token, await newDevice(), { aud: ['cronly.org'], grants: [{ actions: ['cronly:*'] }] })).body.code).toBe('not_narrower');
    expect((await redeem(`${token.slice(0, -2)}xx`, await newDevice())).status).toBe(401);
    expect((await redeem('dbak_nope', await newDevice())).body.code).toBe('invalid_enrollment_token');
    expect((await call(env, 'GET', '/api/v1/enrollment-tokens', { auth: 'alice' })).body.items[0].uses).toBe(0);

    await call(env, 'DELETE', `/api/v1/enrollment-tokens/${created.body.id}`, { auth: 'alice' });
    const after = await redeem(token, await newDevice());
    expect(after.status).toBe(403);
    expect(after.body.error).toContain('revoked');
    expect((await call(env, 'GET', '/api/v1/credentials', { auth: 'alice' })).body.items).toHaveLength(0);
  });

  it('validates the template like an issuance, and needs funds at redemption', async () => {
    expect((await create({ ...TEMPLATE, grants: [{ actions: ['hashbin:nope'] }] })).body.code).toBe('invalid_grants');
    expect((await create({ ...TEMPLATE, max_uses: 0 })).body.code).toBe('invalid_max_uses');
    expect((await create({ ...TEMPLATE, expires_in_days: 91 })).body.code).toBe('invalid_expiry');
    expect((await call(env, 'POST', '/api/v1/enrollment-tokens', { body: TEMPLATE })).status).toBe(401);
    const created = await create(TEMPLATE, 'bob');
    const broke = await redeem(created.body.token, await newDevice());
    expect(broke.status).toBe(402);
    expect((await call(env, 'GET', '/api/v1/enrollment-tokens', { auth: 'bob' })).body.items[0].uses).toBe(0);
  });

  it('does not let a delegating device mint tokens', async () => {
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:credentials:issue'] }] })).approve.body.credential;
    const path = '/api/v1/enrollment-tokens';
    const response = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: TEMPLATE });
    expect(response.status).toBe(403);
  });

  it('stops redemptions that expire', async () => {
    const created = await create({ ...TEMPLATE, expires_in_days: 0.0000001 });
    await new Promise(resolve => setTimeout(resolve, 20));
    const late = await redeem(created.body.token, await newDevice());
    expect(late.body).toMatchObject({ code: 'enrollment_token_inactive', error: 'Enrollment token is expired' });
  });
});
