import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv, call, newDevice } from '../test-utils/env.js';
import { clerkFreeEnv, signUp, asDevice } from '../test-utils/signup.js';
import { inspectCredential } from '../packages/verify/src/index.js';

// Paid accounts without Clerk, phase A3 (todo/clerk_free_accounts.md §3.5, STATUS B9): after
// losing every device, the owner puts a new device on the account with a recovery code.

const MINUTE = 60000;
let env; let stripe; const realNow = Date.now; let t;
let account; let laptop; let as; let codes;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  ({ env, stripe } = await clerkFreeEnv());
  laptop = await newDevice();
  let credential;
  ({ account, credential } = await signUp(env, stripe, laptop));
  as = asDevice(env, laptop, credential);
  const made = await as('POST', '/api/v1/settings/recovery-codes');
  expect(made.body).toMatchObject({ account, codes: expect.any(Array) });
  codes = made.body.codes;
  t += 60 * MINUTE;
});
afterEach(() => { Date.now = realNow; });

const recover = async (device, body = {}) => call(env, 'POST', '/api/v1/recover', { body: { account, via: 'code', code: codes[0], request: await device.enrollRequest({ device: { name: 'New phone', kind: 'browser' } }), ...body } });

describe('recovery onto a new device (B9, phase A3)', () => {
  it('puts a new dashboard device on the account with a recovery code, free', async () => {
    const before = (await as('GET', '/api/v1/account')).body.balance_microdollars;
    const phone = await newDevice();
    const recovered = await recover(phone);
    expect(recovered.body).toMatchObject({ status: 'recovered', account, recovery_codes_left: 9 });
    const { payload } = inspectCredential(recovered.body.credential);
    expect(payload).toMatchObject({ acct: account, cnf: { jkt: phone.jkt }, aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }], device: { name: 'New phone' } });
    const asPhone = asDevice(env, phone, recovered.body.credential);
    expect((await asPhone('GET', '/api/v1/account')).body.balance_microdollars).toBe(before);
    // It counts as a recent sign-in: the owner can revoke the lost laptop and make new codes now.
    const laptopId = (await asPhone('GET', '/api/v1/devices')).body.items.find(d => d.name === 'Laptop browser').id;
    expect((await asPhone('POST', `/api/v1/devices/${laptopId}/revoke`)).status).toBe(200);
    expect((await as('GET', '/api/v1/account')).body.code).toBe('revoked');
    expect((await asPhone('POST', '/api/v1/settings/recovery-codes')).body.codes).toHaveLength(10);
    const audit = (await asPhone('GET', '/api/v1/audit')).body.items.map(e => e.type);
    expect(audit).toContain('recovery_code.used');
    // Ten minutes later it is an ordinary dashboard device again.
    t += 11 * MINUTE;
    expect((await asPhone('POST', '/api/v1/settings/recovery-codes')).body.code).toBe('reverification_required');
  });

  it('takes each code once, and only for its account', async () => {
    expect((await recover(await newDevice())).status).toBe(200);
    expect((await recover(await newDevice())).body.code).toBe('invalid_recovery_code');
    expect((await recover(await newDevice(), { code: codes[1].toLowerCase().replaceAll('-', '') })).status).toBe(200);
    // Another account's id with a real code: refused, and nothing is created for that id.
    const other = 'acct_00000000000000000000000000';
    expect((await recover(await newDevice(), { account: other, code: codes[2] })).body.code).toBe('invalid_recovery_code');
    expect(env.ACCOUNTS.get(other).storage.rows.size).toBe(0);
  });

  it('stops after five wrong codes in fifteen minutes', async () => {
    for (let i = 0; i < 5; i++) expect((await recover(await newDevice(), { code: `WRONG-CODE-${i}` })).body.code).toBe('invalid_recovery_code');
    expect((await recover(await newDevice())).body.code).toBe('too_many_attempts');
    t += 16 * MINUTE;
    expect((await recover(await newDevice())).body.status).toBe('recovered');
  });

  it('needs a fresh request signed by the new key', async () => {
    const phone = await newDevice();
    const stale = await phone.enrollRequest({ iat: Math.floor(t / 1000) - 3600 });
    expect((await recover(phone, { request: stale })).body.code).toBe('invalid_request');
    expect((await recover(phone, { request: 'not-a-jws' })).body.code).toBe('invalid_request');
    expect((await recover(phone, { via: 'email' })).body.code).toBe('invalid_recovery');
    // A refused request uses no code.
    expect((await recover(phone)).body.recovery_codes_left).toBe(9);
  });
});

describe('recovery status', () => {
  it('warns until there are recovery codes or the owner accepts having none', async () => {
    const fresh = await testEnv();
    const get = () => call(fresh, 'GET', '/api/v1/account/recovery', { auth: 'bob' });
    await call(fresh, 'POST', '/api/v1/dev/deposit', { auth: 'bob', body: { amount_microdollars: 1_000_000 } });
    expect((await get()).body).toMatchObject({ recovery_codes_left: 0, no_recovery_acknowledged_at: null, at_risk: true });
    expect((await call(fresh, 'POST', '/api/v1/account/recovery', { auth: 'bob', body: {} })).body.code).toBe('invalid_request');
    expect((await call(fresh, 'POST', '/api/v1/account/recovery', { auth: 'bob', body: { acknowledge_no_recovery: true } })).body).toMatchObject({ at_risk: false, no_recovery_acknowledged_at: expect.any(Number) });
    await call(fresh, 'POST', '/api/v1/settings/recovery-codes', { auth: 'bob' });
    expect((await get()).body).toMatchObject({ recovery_codes_left: 10, at_risk: false });
  });

  it('recovers an account with no balance, and a Clerk account the same way', async () => {
    const local = await testEnv();
    const owner = 'user_2clerkLikeId';
    const sheet = (await call(local, 'POST', '/api/v1/settings/recovery-codes', { auth: owner })).body;
    expect(sheet.account).toBe(owner);
    expect((await call(local, 'GET', '/api/v1/account', { auth: owner })).body.balance_microdollars).toBe(0);
    const phone = await newDevice();
    const recovered = await call(local, 'POST', '/api/v1/recover', { body: { account: owner, code: sheet.codes[0], request: await phone.enrollRequest({ device: { name: 'Phone' } }) } });
    expect(recovered.body).toMatchObject({ status: 'recovered', account: owner, cost_microdollars: 0 });
  });
});
