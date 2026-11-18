import { describe, it, expect, beforeEach } from 'vitest';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';
import { inspectCredential } from '../packages/verify/src/index.js';

// Master plan §10: removing a revocation needs a recent sign-in. Issuing to a revoked device's key
// reinstates the device, so only a person who signed in recently may do it; a fleet enrollment
// token or a delegating device never brings a revoked device back.

const session = (sub, fva) => `Bearer ${btoa(JSON.stringify({ sub, sid: 'sess_1', fva }))}`;
const fresh = sub => session(sub, [2, -1]);
const stale = sub => session(sub, [45, -1]);
const GRANTS = [{ actions: ['hashbin:content:write'] }];

let env;
beforeEach(async () => {
  env = await testEnv({ CLERK_SECRET_KEY: 'sk_test', CLERK_VERIFY_TOKEN: async token => JSON.parse(atob(token)) });
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
});

/** A device enrolled and then revoked (as after a theft). */
async function revokedDevice() {
  const device = await newDevice();
  const { approve } = await enroll(env, 'alice', device);
  const deviceId = approve.body.device_id;
  expect((await call(env, 'POST', `/api/v1/devices/${deviceId}/revoke`, { auth: 'alice', body: {} })).status).toBe(200);
  return { device, deviceId };
}
const deviceState = async id => (await call(env, 'GET', `/api/v1/devices/${id}`, { auth: 'alice' })).body;

describe('a revoked device stays revoked', () => {
  it('refuses a fleet enrollment token redeemed with the revoked key', async () => {
    const { device, deviceId } = await revokedDevice();
    const token = await call(env, 'POST', '/api/v1/enrollment-tokens', { auth: 'alice', body: { name: 'Laptops', aud: ['hashbin.org'], grants: GRANTS, lifetime_seconds: 3600, max_uses: 5, expires_in_days: 1 } });
    const redeemed = await call(env, 'POST', '/api/v1/enrollments/redeem', { body: { enrollment_token: token.body.token, request: await device.enrollRequest({ device: { name: 'stolen laptop' } }) } });
    expect(redeemed.status).toBe(403);
    expect(redeemed.body).toMatchObject({ code: 'device_revoked', device_id: deviceId });
    expect((await deviceState(deviceId)).revoked_at).toBeTruthy();
    // Nothing was charged or counted for the refusal.
    const tokens = await call(env, 'GET', '/api/v1/enrollment-tokens', { auth: 'alice' });
    expect(tokens.body.items[0].uses).toBe(0);
    // A fresh key on the same token works.
    const other = await newDevice();
    expect((await call(env, 'POST', '/api/v1/enrollments/redeem', { body: { enrollment_token: token.body.token, request: await other.enrollRequest({ device: { name: 'new laptop' } }) } })).status).toBe(200);
  });

  it('refuses a delegating device issuing to the revoked key', async () => {
    const { device } = await revokedDevice();
    const admin = await newDevice();
    const credential = (await enroll(env, 'alice', admin, { aud: ['devicebasedauth.org', 'hashbin.org'], grants: [{ actions: ['dba:credentials:issue'] }, ...GRANTS] })).approve.body.credential;
    const issued = await call(env, 'POST', '/api/v1/credentials', { headers: await admin.headers('POST', '/api/v1/credentials', credential), body: { public_jwk: device.publicJwk, aud: ['hashbin.org'], grants: GRANTS } });
    expect(issued.status).toBe(403);
    expect(issued.body.code).toBe('device_revoked');
  });

  it('asks a signed-in owner to sign in again before approving the revoked device, then reinstates it', async () => {
    const { device, deviceId } = await revokedDevice();
    const start = await call(env, 'POST', '/api/v1/enrollments', { body: { request: await device.enrollRequest({ aud: ['hashbin.org'], grants: GRANTS, device: { name: 'found it' } }) } });
    const refused = await call(env, 'POST', '/api/v1/enrollments/approve', { auth: stale('alice'), body: { request: start.body.request } });
    expect(refused.status).toBe(403);
    expect(refused.body).toMatchObject({ code: 'reverification_required', clerk_error: { reason: 'reverification-error' } });
    expect(refused.body.error).toContain('revoked');
    expect((await deviceState(deviceId)).revoked_at).toBeTruthy();

    const approved = await call(env, 'POST', '/api/v1/enrollments/approve', { auth: fresh('alice'), body: { request: start.body.request } });
    expect(approved.status).toBe(200);
    expect(inspectCredential(approved.body.credential).payload.sub).toBe(deviceId);
    const state = await deviceState(deviceId);
    expect(state.revoked_at).toBeUndefined();
    expect(state.reinstated_at).toBeTruthy();
    const audit = await call(env, 'GET', '/api/v1/audit', { auth: 'alice' });
    expect(JSON.stringify(audit.body)).toContain('device.reinstated');
  });

  it('lets an API key (made after a recent sign-in) or a fresh dashboard session issue to it directly', async () => {
    const { device } = await revokedDevice();
    const body = { public_jwk: device.publicJwk, aud: ['hashbin.org'], grants: GRANTS };
    expect((await call(env, 'POST', '/api/v1/credentials', { auth: stale('alice'), body })).body.code).toBe('reverification_required');
    expect((await call(env, 'POST', '/api/v1/credentials', { auth: fresh('alice'), body })).status).toBe(200);
  });

  it('needs no recent sign-in for devices that were never revoked', async () => {
    const start = await call(env, 'POST', '/api/v1/enrollments', { body: { request: await (await newDevice()).enrollRequest({ aud: ['hashbin.org'], grants: GRANTS }) } });
    expect((await call(env, 'POST', '/api/v1/enrollments/approve', { auth: stale('alice'), body: { request: start.body.request } })).status).toBe(200);
  });
});
