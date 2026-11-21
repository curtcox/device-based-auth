import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv, call, newDevice, ORIGIN } from '../test-utils/env.js';
import { clerkFreeEnv, signUp, asDevice } from '../test-utils/signup.js';
import { softAuthenticator } from '../test-utils/authenticator.js';
import { createProof, inspectCredential } from '../packages/verify/src/index.js';
import { answerChallenge } from './services/webauthn.js';

// Paid accounts without Clerk, phases A3 and A4 (todo/clerk_free_accounts.md §3.5, STATUS B9):
// after losing every device, the owner puts a new device on the account with a recovery code, or
// with a passkey or another of their devices approving.

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
  passkey = await softAuthenticator();
  const created = (await as('POST', '/api/v1/gates', { body: { kind: 'webauthn', label: 'Passkey' } })).body;
  expect((await as('POST', `/api/v1/gates/${created.id}/activate`, { body: { registration: await passkey.register(created.setup.public_key, ORIGIN) } })).body.state).toBe('active');
  passkeyGate = created.id;
  t += 60 * MINUTE;
});
let passkey; let passkeyGate;
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

describe('recovery by passkey or another device (B9, phase A4)', () => {
  const askGate = async (device, who = account) => call(env, 'POST', '/api/v1/recover', { body: { account: who, via: 'gate', request: await device.enrollRequest({ device: { name: 'New phone', kind: 'browser' } }) } });
  const complete = async (device, ticket) => {
    const path = '/api/v1/recover/complete';
    return call(env, 'POST', path, { body: { ticket }, headers: { DPoP: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url: `${ORIGIN}${path}`, credential: ticket }) } });
  };

  it('lets a passkey approve on the new device itself, typing the number it shows', async () => {
    const phone = await newDevice();
    const asked = (await askGate(phone)).body;
    expect(asked).toMatchObject({ status: 'pending', account, number: expect.stringMatching(/^\d\d$/), approve_url: expect.stringContaining('/gate.html#'), ticket: expect.stringMatching(/^rcv_/) });
    expect((await complete(phone, asked.ticket)).body).toMatchObject({ status: 'pending' });
    // The approval page, opened on the phone: the passkey signs, and the number must match.
    const link = asked.approve_url.split('#')[1];
    const view = (await call(env, 'GET', `/api/v1/gate-links/${link}`)).body;
    expect(view).toMatchObject({ purpose: 'recover', device_name: 'New phone' });
    expect(view.number).toBeUndefined();
    const sign = async () => passkey.assert({ challenge: await answerChallenge({ requestId: view.id, entry: 0, decision: 'allow', salt: view.factors.salt }), rpId: view.factors.rp_id }, ORIGIN);
    const answer = body => call(env, 'POST', `/api/v1/gate-links/${link}/answer`, { body: { gate: passkeyGate, decision: 'allow', ...body } });
    expect((await answer({ webauthn: await sign(), number: asked.number === '10' ? '11' : '10' })).body.code).toBe('wrong_number');
    expect((await answer({ webauthn: await sign(), number: asked.number })).body.status).toBe('allowed');

    const done = await complete(phone, asked.ticket);
    expect(done.body).toMatchObject({ status: 'recovered', account });
    expect(inspectCredential(done.body.credential).payload).toMatchObject({ acct: account, cnf: { jkt: phone.jkt }, grants: [{ actions: ['dba:session'] }] });
    expect((await complete(phone, asked.ticket)).body.credential).toBe(done.body.credential);
    const asPhone = asDevice(env, phone, done.body.credential);
    expect((await asPhone('POST', '/api/v1/settings/recovery-codes')).status).toBe(200);
    const audit = (await asPhone('GET', '/api/v1/audit')).body.items.map(e => e.type);
    expect(audit).toEqual(expect.arrayContaining(['recovery.requested', 'recovery.approved']));
  });

  it('lets another of the owner\'s dashboard devices approve, as its device gate', async () => {
    // Earlier: a second dashboard browser, added as a gate.
    t -= 60 * MINUTE;
    const desktop = await newDevice();
    const start = await call(env, 'POST', '/api/v1/enrollments', { body: { request: await desktop.enrollRequest({ aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }], device: { name: 'Desktop browser' } }) } });
    const approved = (await as('POST', '/api/v1/enrollments/approve', { body: { request: start.body.request } })).body;
    const gate = (await as('POST', '/api/v1/gates', { body: { kind: 'dba-device', label: 'Desktop', device_id: approved.device_id } })).body.id;
    const asDesktop = asDevice(env, desktop, approved.credential);
    t += 60 * MINUTE;

    const phone = await newDevice();
    const asked = (await askGate(phone)).body;
    const pending = (await asDesktop('GET', '/api/v1/gate-requests')).body.items.find(r => r.purpose === 'recover');
    expect(pending).toMatchObject({ device_name: 'New phone' });
    const path = `/api/v1/gate-requests/${pending.id}/answer`;
    expect((await as('POST', path, { body: { gate, decision: 'allow', number: asked.number } })).body.code).toBe('not_the_gate');
    expect((await asDesktop('POST', path, { body: { gate, decision: 'allow', number: asked.number === '10' ? '11' : '10' } })).body.code).toBe('wrong_number');
    expect((await asDesktop('POST', path, { body: { gate, decision: 'allow', number: asked.number } })).body.status).toBe('allowed');
    expect((await complete(phone, asked.ticket)).body.status).toBe('recovered');
  });

  it('refuses when a gate denies or nobody answers', async () => {
    const phone = await newDevice();
    const asked = (await askGate(phone)).body;
    const link = asked.approve_url.split('#')[1];
    const view = (await call(env, 'GET', `/api/v1/gate-links/${link}`)).body;
    const webauthn = await passkey.assert({ challenge: await answerChallenge({ requestId: view.id, entry: 0, decision: 'deny', salt: view.factors.salt }), rpId: view.factors.rp_id }, ORIGIN);
    expect((await call(env, 'POST', `/api/v1/gate-links/${link}/answer`, { body: { gate: passkeyGate, decision: 'deny', webauthn } })).body.status).toBe('denied');
    expect((await complete(phone, asked.ticket)).body.code).toBe('recovery_denied');
    const slow = await newDevice();
    const other = (await askGate(slow)).body;
    t += 11 * MINUTE;
    expect((await complete(slow, other.ticket)).body.code).toBe('recovery_denied');
  });

  it('keeps strangers from flooding the owner or taking the ticket', async () => {
    const phone = await newDevice();
    const asked = (await askGate(phone)).body;
    // The same key asking again finds the same request.
    expect((await askGate(phone)).body.number).toBe(asked.number);
    expect((await askGate(await newDevice())).status).toBe(200);
    expect((await askGate(await newDevice())).status).toBe(200);
    expect((await askGate(await newDevice())).body.code).toBe('too_many_attempts');
    // Only the key that asked can complete.
    const thief = await newDevice();
    expect((await complete(thief, asked.ticket)).body.code).toBe('key_mismatch');
    expect((await complete(phone, `${asked.ticket}x`)).body.code).toBe('invalid_recovery');
    // An account without such gates, or no account at all: refused, and nothing stored.
    const ghost = 'acct_00000000000000000000000000';
    expect((await askGate(await newDevice(), ghost)).body.code).toBe('no_recovery_gate');
    expect(env.ACCOUNTS.get(ghost).storage.rows.size).toBe(0);
  });

  it('counts a passkey or device gate as a way back in', async () => {
    const status = (await call(env, 'GET', '/api/v1/account/recovery', { headers: await laptop.headers('GET', '/api/v1/account/recovery', (await signUp(env, stripe, laptop)).credential) })).body;
    expect(status).toMatchObject({ recovery_codes_left: 0, recovery_gates: [], at_risk: true });
    expect((await as('GET', '/api/v1/account/recovery')).body).toMatchObject({ recovery_codes_left: 10, recovery_gates: [{ id: passkeyGate, kind: 'webauthn', label: 'Passkey' }], at_risk: false });
  });
});
