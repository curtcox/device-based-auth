import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { call, newDevice, ORIGIN, runAlarms } from '../test-utils/env.js';
import { clerkFreeEnv, signUp, asDevice } from '../test-utils/signup.js';
import { createProof, inspectCredential } from '../packages/verify/src/index.js';
import { rpc } from './utils/rpc.js';
import { price } from './utils/pricing.js';
import { EMAIL_RECOVERY_WAIT_MS } from './durable-objects/account/email-address.js';

// Paid accounts without Clerk, phase A5 (done/clerk_free_accounts.md §3.5, §3.7, STATUS B9): an
// address devicebasedauth.org verifies itself gets security email and can recover the account,
// after a wait any signed-in device can cancel. Production, every CLERK_* unset, SES faked.

const SES = { EMAIL_PROVIDER: 'ses', SES_REGION: 'us-east-1', SES_ACCESS_KEY_ID: 'AKIDTEST', SES_SECRET_ACCESS_KEY: 'secret', EMAIL_FROM: 'devicebasedauth.org <security@devicebasedauth.org>' };
const MINUTE = 60000; const HOUR = 60 * MINUTE;
let env; let stripe; let sent; const realNow = Date.now; let t;
let account; let laptop; let as;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  sent = [];
  ({ env, stripe } = await clerkFreeEnv({ ...SES, EMAIL_FETCH: async (url, init) => { sent.push(JSON.parse(init.body)); return new Response(JSON.stringify({ MessageId: 'm' }), { status: 200 }); } }));
  laptop = await newDevice();
  let credential;
  ({ account, credential } = await signUp(env, stripe, laptop));
  as = asDevice(env, laptop, credential);
});
afterEach(() => { Date.now = realNow; });

/** Emails sent so far (after the account's alarms run), newest last. */
async function mail() { await runAlarms(env); return sent.map(s => ({ to: s.Destination.ToAddresses[0], subject: s.Content.Simple.Subject.Data, text: s.Content.Simple.Body.Text.Data })); }
const tokenIn = (text, prefix) => text.match(new RegExp(`/email-link\\.html#(${prefix}[A-Za-z0-9_.-]+)`))[1];

/** Verify `address` for the signed-up account (within its first ten minutes). */
async function verify(address = 'owner@example.com') {
  expect((await as('POST', '/api/v1/account/email', { body: { email: address } })).body).toMatchObject({ pending: true });
  const message = (await mail()).at(-1);
  expect(message).toMatchObject({ to: address, subject: 'Confirm your security email address' });
  return call(env, 'POST', '/api/v1/account/email/verify', { body: { token: tokenIn(message.text, 'emv_') } });
}

const askByEmail = async (device, email = 'Owner@Example.com') => call(env, 'POST', '/api/v1/recover', { body: { via: 'email', email, request: await device.enrollRequest({ device: { name: 'New phone' } }) } });
const complete = async (device, ticket) => {
  const path = '/api/v1/recover/complete';
  return call(env, 'POST', path, { body: { ticket }, headers: { DPoP: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url: `${ORIGIN}${path}`, credential: ticket }) } });
};

describe('a security email address verified here (B9, phase A5)', () => {
  it('verifies an address by its link, charged as one email, and makes it the recovery address', async () => {
    const before = (await as('GET', '/api/v1/account')).body.balance_microdollars;
    const verified = await verify();
    expect(verified.body).toMatchObject({ status: 'verified', security_email_address: 'owner@example.com', security_email_source: 'verified' });
    const after = (await as('GET', '/api/v1/account')).body;
    expect(after).toMatchObject({ security_email_address: 'owner@example.com', security_email_source: 'verified', security_email_pending: null });
    expect(after.balance_microdollars).toBeLessThanOrEqual(before - price('notice'));
    expect((await as('GET', '/api/v1/account/recovery')).body).toMatchObject({ recovery_email: 'owner@example.com', at_risk: false });
    // Security email now goes there.
    await as('POST', '/api/v1/settings/recovery-codes');
    expect((await mail()).at(-1)).toMatchObject({ to: 'owner@example.com', subject: 'New recovery codes' });
  });

  it('refuses a used or stale link, and an address another account recovers by', async () => {
    await as('POST', '/api/v1/account/email', { body: { email: 'owner@example.com' } });
    const token = tokenIn((await mail()).at(-1).text, 'emv_');
    t += 2 * HOUR;
    expect((await call(env, 'POST', '/api/v1/account/email/verify', { body: { token } })).body.code).toBe('invalid_link');
    t -= 2 * HOUR;
    expect((await call(env, 'POST', '/api/v1/account/email/verify', { body: { token } })).status).toBe(200);
    expect((await call(env, 'POST', '/api/v1/account/email/verify', { body: { token } })).body.code).toBe('invalid_link');
    // A second account cannot take the same address for recovery.
    const other = await newDevice();
    const second = asDevice(env, other, (await signUp(env, stripe, other)).credential);
    await second('POST', '/api/v1/account/email', { body: { email: 'OWNER@example.com' } });
    expect((await call(env, 'POST', '/api/v1/account/email/verify', { body: { token: tokenIn((await mail()).at(-1).text, 'emv_') } })).body.code).toBe('email_in_use');
    expect((await as('POST', '/api/v1/account/email', { body: { email: 'not an address' } })).body.code).toBe('invalid_email');
  });

  it('keeps an address verified here when Clerk reports another, and lets Clerk set its own otherwise', async () => {
    await verify();
    await rpc(env.ACCOUNTS, account, 'init', { account, email: 'clerk@example.com' });
    expect((await as('GET', '/api/v1/account')).body).toMatchObject({ security_email_address: 'owner@example.com', security_email_source: 'verified' });
    await rpc(env.ACCOUNTS, 'user_clerk', 'init', { account: 'user_clerk', email: 'clerk@example.com' });
    expect((await rpc(env.ACCOUNTS, 'user_clerk', 'account', {})).security_email_source).toBe('clerk');
  });
});

describe('recovery by email', () => {
  it('emails a link, waits after it is used, then lets the new device in', async () => {
    await verify();
    const phone = await newDevice();
    const asked = (await askByEmail(phone)).body;
    expect(asked).toMatchObject({ status: 'pending', stage: 'waiting_for_link', wait_hours: EMAIL_RECOVERY_WAIT_MS / HOUR, ticket: expect.stringMatching(/^rcv_/) });
    expect(JSON.stringify(asked)).not.toContain(account);
    const link = (await mail()).at(-1);
    expect(link).toMatchObject({ to: 'owner@example.com', subject: 'Recover your devicebasedauth.org account?' });
    expect((await complete(phone, asked.ticket)).body).toMatchObject({ status: 'pending', stage: 'waiting_for_link' });

    const started = await call(env, 'POST', '/api/v1/recover/email-link', { body: { token: tokenIn(link.text, 'erl_') } });
    expect(started.body).toMatchObject({ status: 'waiting', ready_at: t + EMAIL_RECOVERY_WAIT_MS });
    expect((await mail()).at(-1)).toMatchObject({ subject: 'Your account will be recovered by email' });
    expect((await as('GET', '/api/v1/account/recovery')).body.pending_email_recoveries).toMatchObject([{ device_name: 'New phone', state: 'waiting', ready_at: t + EMAIL_RECOVERY_WAIT_MS }]);
    t += EMAIL_RECOVERY_WAIT_MS - MINUTE;
    expect((await complete(phone, asked.ticket)).body).toMatchObject({ status: 'pending', stage: 'waiting' });
    t += 2 * MINUTE;
    const done = await complete(phone, asked.ticket);
    expect(done.body).toMatchObject({ status: 'recovered', account });
    expect(inspectCredential(done.body.credential).payload).toMatchObject({ acct: account, cnf: { jkt: phone.jkt }, grants: [{ actions: ['dba:session'] }] });
    expect((await complete(phone, asked.ticket)).body.credential).toBe(done.body.credential);
    expect((await asDevice(env, phone, done.body.credential)('POST', '/api/v1/settings/recovery-codes')).status).toBe(200);
  });

  it('is cancelled by any signed-in device before the wait ends', async () => {
    await verify();
    const phone = await newDevice();
    const asked = (await askByEmail(phone)).body;
    await call(env, 'POST', '/api/v1/recover/email-link', { body: { token: tokenIn((await mail()).at(-1).text, 'erl_') } });
    const id = (await as('GET', '/api/v1/account/recovery')).body.pending_email_recoveries[0].id;
    expect((await as('POST', '/api/v1/account/recovery', { body: { cancel_email_recovery: id } })).body).toMatchObject({ cancelled: id });
    t += EMAIL_RECOVERY_WAIT_MS + MINUTE;
    expect((await complete(phone, asked.ticket)).body.code).toBe('recovery_denied');
    expect((await as('GET', '/api/v1/account/recovery')).body.pending_email_recoveries).toEqual([]);
  });

  it('answers the same for an address nobody uses, and sends nothing', async () => {
    await verify();
    const before = (await mail()).length;
    const phone = await newDevice();
    const asked = (await askByEmail(phone, 'stranger@example.com')).body;
    expect(Object.keys(asked).sort()).toEqual(Object.keys((await askByEmail(await newDevice())).body).sort());
    expect((await mail()).length).toBe(before + 1);
    t += EMAIL_RECOVERY_WAIT_MS + 2 * HOUR;
    expect((await complete(phone, asked.ticket)).body).toMatchObject({ status: 'pending', stage: 'waiting_for_link' });
  });

  it('expires an unused link, limits requests, and stops when the address is removed', async () => {
    await verify();
    const asked = (await askByEmail(await newDevice())).body;
    const token = tokenIn((await mail()).at(-1).text, 'erl_');
    t += 2 * HOUR;
    expect((await call(env, 'POST', '/api/v1/recover/email-link', { body: { token } })).body.code).toBe('invalid_link');
    expect(asked.status).toBe('pending');
    // Three emails an hour per account; the fourth request sends nothing, even when the account's
    // object restarted in between (it is evicted after a short idle), and the count is on the profile row.
    const before = (await mail()).length;
    for (let i = 0; i < 4; i++) { env.ACCOUNTS.restart(account); await askByEmail(await newDevice()); }
    expect((await mail()).length).toBe(before + 3);
    // Removing the address (back within the sign-up's ten minutes, which count as a recent sign-in) ends recovery by it.
    t -= 2 * HOUR; t += 5 * MINUTE;
    expect((await as('DELETE', '/api/v1/account/email')).body).toMatchObject({ removed: true });
    t += 2 * HOUR;
    const after = (await mail()).length;
    await askByEmail(await newDevice());
    expect((await mail()).length).toBe(after);
    expect((await as('GET', '/api/v1/account')).body.security_email_address).toBeNull();
  });
});
