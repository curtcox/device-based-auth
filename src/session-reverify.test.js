import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { newDevice } from '../test-utils/env.js';
import { clerkFreeEnv, signUp, asDevice } from '../test-utils/signup.js';
import { inspectCredential } from '../packages/verify/src/index.js';
import { hotp } from './services/totp.js';
import { call } from '../test-utils/env.js';

// Paid accounts without Clerk, phase A2 (done/clerk_free_accounts.md §3.3, §3.4, STATUS B9):
// what a recent Clerk sign-in allows, a Clerk-free owner gets from paying for the sign-up (for
// ten minutes) and afterwards from one of their own gates. Production, every CLERK_* unset.

const MINUTE = 60000;
const unbase32 = text => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0; let value = 0; const out = []; for (const c of text) { value = (value << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } } return new Uint8Array(out); };

let env; let stripe; const realNow = Date.now; let t;
let laptop; let as;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  ({ env, stripe } = await clerkFreeEnv());
  laptop = await newDevice();
  const { credential } = await signUp(env, stripe, laptop);
  as = asDevice(env, laptop, credential);
});
afterEach(() => { Date.now = realNow; });

/** Set up a TOTP gate (needs a recent sign-in); returns its id and a code reader. */
async function totpGate() {
  const created = await as('POST', '/api/v1/gates', { body: { kind: 'totp', label: 'Authenticator' } });
  expect(created.status, JSON.stringify(created.body)).toBe(200);
  const secret = unbase32(created.body.setup.secret);
  const code = (offset = 0) => hotp(secret, Math.floor(t / 30000) + offset);
  expect((await as('POST', `/api/v1/gates/${created.body.id}/activate`, { body: { code: await code() } })).body.state).toBe('active');
  return { gate: created.body.id, code };
}

/** Enroll another device for the account; approving it (dba:* grants) needs a recent sign-in. */
async function approveDevice(grants, name) {
  const device = await newDevice();
  const start = await call(env, 'POST', '/api/v1/enrollments', { body: { request: await device.enrollRequest({ aud: ['devicebasedauth.org'], grants, device: { name, kind: 'browser' } }) } });
  return { device, approve: await as('POST', '/api/v1/enrollments/approve', { body: { request: start.body.request } }) };
}

describe('recent sign-in without Clerk (B9, phase A2)', () => {
  it('counts the ten minutes after paying for the sign-up as a recent sign-in', async () => {
    expect((await as('POST', '/api/v1/settings/recovery-codes')).status).toBe(200);
    t += 9 * MINUTE;
    expect((await as('POST', '/api/v1/keys', { body: { name: 'ci', scopes: ['credentials:read'] } })).status).toBe(200);
    t += 2 * MINUTE;
    const refused = await as('POST', '/api/v1/settings/recovery-codes');
    expect(refused.status).toBe(403);
    expect(refused.body).toMatchObject({ code: 'reverification_required', max_age_minutes: 10, reverify: { url: '/api/v1/session/reverify', method: 'POST' } });
    // Everyday work does not need it.
    expect((await as('GET', '/api/v1/account')).status).toBe(200);
  });

  it('re-verifies through this device\'s own authenticator code', async () => {
    const { gate, code } = await totpGate();
    t += 11 * MINUTE;
    expect((await as('POST', '/api/v1/keys', { body: { name: 'ci', scopes: ['credentials:read'] } })).body.code).toBe('reverification_required');

    const pending = await as('POST', '/api/v1/session/reverify', { body: {} });
    expect(pending.body).toMatchObject({ status: 'pending', gate_request: { purpose: 'reverify', number: expect.stringMatching(/^\d\d$/), factors: { entries: [{ gates: [{ id: gate, kind: 'totp' }] }] } } });
    const right = await code();
    expect((await as('POST', '/api/v1/session/reverify', { body: { gate, totp: { code: right === '123456' ? '654321' : '123456' } } })).body.code).toBe('invalid_code');
    const passed = await as('POST', '/api/v1/session/reverify', { body: { gate, totp: { code: right } } });
    expect(passed.body).toMatchObject({ status: 'reverified', until: t + 10 * MINUTE });

    // Now the account-control operations work: an API key, a second dashboard device.
    expect((await as('POST', '/api/v1/keys', { body: { name: 'ci', scopes: ['credentials:read'] } })).status).toBe(200);
    const { approve } = await approveDevice([{ actions: ['dba:session'] }], 'Desktop browser');
    expect(approve.status, JSON.stringify(approve.body)).toBe(200);
    expect(inspectCredential(approve.body.credential).payload.grants).toEqual([{ actions: ['dba:session'] }]);
    // The code is spent; and ten minutes later it is needed again.
    t += 11 * MINUTE;
    expect((await as('POST', '/api/v1/keys', { body: { name: 'ci2', scopes: ['credentials:read'] } })).body.code).toBe('reverification_required');
    const audit = (await as('GET', '/api/v1/audit')).body.items.map(e => e.type);
    expect(audit).toContain('session.reverified');
  });

  it('re-verifies when another of the owner\'s devices approves, typing the number', async () => {
    const { device: phone, approve } = await approveDevice([{ actions: ['dba:approvals:answer'] }], 'Phone');
    const phoneId = inspectCredential(approve.body.credential).payload.sub;
    const gate = (await as('POST', '/api/v1/gates', { body: { kind: 'dba-device', label: 'Phone', device_id: phoneId } })).body.id;
    const asPhone = asDevice(env, phone, approve.body.credential);
    t += 11 * MINUTE;

    const pending = (await as('POST', '/api/v1/session/reverify', { body: {} })).body;
    expect(pending.status).toBe('pending');
    const { id, number } = pending.gate_request;
    // The phone sees the request, but not the number: it must type what the laptop shows.
    const seen = (await asPhone('GET', `/api/v1/gate-requests/${id}`)).body;
    expect(seen).toMatchObject({ purpose: 'reverify', answer_as: [{ entry: 0, gate }] });
    expect(seen.number).toBeUndefined();
    const path = `/api/v1/gate-requests/${id}/answer`;
    expect((await asPhone('POST', path, { body: { gate, decision: 'allow', number: number === '10' ? '11' : '10' } })).body.code).toBe('wrong_number');
    // The laptop cannot answer for the phone's gate.
    expect((await as('POST', '/api/v1/session/reverify', { body: { gate, totp: { code: '000000' } } })).body.code).toBe('not_a_gate');
    expect((await asPhone('POST', path, { body: { gate, decision: 'allow', number } })).body.status).toBe('allowed');
    expect((await as('POST', '/api/v1/session/reverify', { body: {} })).body.status).toBe('reverified');
    expect((await as('POST', '/api/v1/settings/recovery-codes')).status).toBe(200);
  });

  it('is per device: re-verifying one dashboard device does not unlock another', async () => {
    const { gate, code } = await totpGate();
    const { device: desktop, approve } = await approveDevice([{ actions: ['dba:session'] }], 'Desktop browser');
    const asDesktop = asDevice(env, desktop, approve.body.credential);
    t += 11 * MINUTE;
    await as('POST', '/api/v1/session/reverify', { body: {} });
    expect((await as('POST', '/api/v1/session/reverify', { body: { gate, totp: { code: await code() } } })).body.status).toBe('reverified');
    expect((await asDesktop('POST', '/api/v1/settings/recovery-codes')).body.code).toBe('reverification_required');
  });

  it('says to add a gate when the account has none that can confirm it', async () => {
    t += 11 * MINUTE;
    expect((await as('POST', '/api/v1/session/reverify', { body: {} })).body.code).toBe('no_reverify_gate');
    // The owner gate (this same device) does not count, nor does a gate naming this device itself.
  });

  it('denies when no gate answers in time, and then asks afresh', async () => {
    const { gate, code } = await totpGate();
    t += 11 * MINUTE;
    const first = (await as('POST', '/api/v1/session/reverify', { body: {} })).body.gate_request.id;
    t += 6 * MINUTE;
    expect((await as('POST', '/api/v1/session/reverify', { body: {} })).body).toMatchObject({ status: 'denied', code: 'gate_denied' });
    t += 5 * MINUTE;
    const again = (await as('POST', '/api/v1/session/reverify', { body: {} })).body;
    expect(again.status).toBe('pending');
    expect(again.gate_request.id).not.toBe(first);
    expect((await as('POST', '/api/v1/session/reverify', { body: { gate, totp: { code: await code() } } })).body.status).toBe('reverified');
  });
});
