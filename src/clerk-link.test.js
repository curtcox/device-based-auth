import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { call, newDevice, enroll } from '../test-utils/env.js';
import { clerkFreeEnv, signUp, asDevice } from '../test-utils/signup.js';
import { rpc } from './utils/rpc.js';

// Paid accounts without Clerk, phase A6 (done/clerk_free_accounts.md §3.6, STATUS B9): an account
// made without Clerk adds a password (Clerk) sign-in and can drop it again; a Clerk account keeps
// working with only its devices after its Clerk user is deleted.

const MINUTE = 60000;
const WEBHOOK_KEY = new Uint8Array(24).fill(9);
const WEBHOOK_SECRET = `whsec_${btoa(String.fromCharCode(...WEBHOOK_KEY))}`;
/** A stand-in Clerk session token (the test verifier decodes base64 JSON claims). */
const session = (sub, extra = {}) => btoa(JSON.stringify({ sub, sid: `sess_${sub}`, fva: [1, -1], ...extra }));
const bearer = (sub, extra) => `Bearer ${session(sub, extra)}`;

let env; let stripe; let clerkCalls; let clerkAnswer; const realNow = Date.now; let t;
let account; let laptop; let as;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  ({ env, stripe } = await clerkFreeEnv());
  laptop = await newDevice();
  let credential;
  ({ account, credential } = await signUp(env, stripe, laptop));
  as = asDevice(env, laptop, credential);
  // Later the operator turns on password sign-in (Clerk).
  clerkCalls = []; clerkAnswer = () => new Response('{}', { status: 200 });
  Object.assign(env, { CLERK_SECRET_KEY: 'sk_test', CLERK_VERIFY_TOKEN: async token => JSON.parse(atob(token)), CLERK_WEBHOOK_SECRET: WEBHOOK_SECRET, CLERK_FETCH: async (url, init) => { clerkCalls.push({ url, method: init.method, auth: init.headers.Authorization, body: JSON.parse(init.body) }); return clerkAnswer(); } });
});
afterEach(() => { Date.now = realNow; });

/** Send a Clerk webhook, signed as Svix signs them. */
async function webhook(event, { secret = WEBHOOK_KEY } = {}) {
  const payload = JSON.stringify(event); const id = `msg_${crypto.randomUUID()}`; const ts = String(Math.floor(Date.now() / 1000));
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${id}.${ts}.${payload}`)))));
  return call(env, 'POST', '/webhooks/clerk', { body: payload, headers: { 'svix-id': id, 'svix-timestamp': ts, 'svix-signature': `v1,${sig}` } });
}
const userEvent = (type, id, { email, linked } = {}) => ({ type, object: 'event', data: { id, primary_email_address_id: 'e1', email_addresses: email ? [{ id: 'e1', email_address: email, verification: { status: 'verified' } }] : [], public_metadata: linked ? { dba_account: linked } : {} } });

const link = (sub = 'user_new', extra) => as('POST', '/api/v1/account/clerk-link', { body: { session_token: session(sub, extra) } });

describe('linking a password sign-in to an account made without Clerk (B9, phase A6)', () => {
  it('lets the linked Clerk user open the account', async () => {
    expect((await as('GET', '/api/v1/account')).body).toMatchObject({ created_via: 'signup', clerk_linked: false });
    expect((await link()).body).toMatchObject({ linked: true });
    expect(clerkCalls).toEqual([{ url: 'https://api.clerk.com/v1/users/user_new/metadata', method: 'PATCH', auth: 'Bearer sk_test', body: { public_metadata: { dba_account: account } } }]);
    // Clerk now puts dba_account in that user's session token.
    const clerk = bearer('user_new', { dba_account: account });
    expect((await call(env, 'GET', '/api/v1/whoami', { auth: clerk })).body).toMatchObject({ account });
    expect((await call(env, 'POST', '/api/v1/keys', { auth: clerk, body: { name: 'k', scopes: ['credentials:read'] } })).status).toBe(200);
    expect((await as('GET', '/api/v1/account')).body.clerk_linked).toBe(true);
    expect((await as('GET', '/api/v1/audit')).body.items.map(e => e.type)).toContain('account.clerk_linked');
  });

  it('refuses a sign-in that opens another account, has its own, or comes without a recent sign-in', async () => {
    expect((await link('user_x', { dba_account: 'acct_ANOTHER0000000000000000000' })).body.code).toBe('clerk_user_linked');
    await rpc(env.ACCOUNTS, 'user_old', 'init', { account: 'user_old' });
    await rpc(env.ACCOUNTS, 'user_old', 'deposit', { id: 'd1', amount: 1_000_000 });
    expect((await link('user_old')).body.code).toBe('clerk_user_has_account');
    // An empty account Clerk's webhook made for the new user is fine.
    await rpc(env.ACCOUNTS, 'user_fresh', 'init', { account: 'user_fresh', email: 'fresh@example.com' });
    expect((await link('user_fresh')).body.linked).toBe(true);
    expect((await link('user_other')).body.code).toBe('already_linked');
    expect(clerkCalls).toHaveLength(1);
    t += 11 * MINUTE;
    expect((await link('user_fresh')).body.code).toBe('reverification_required');
  });

  it('can be linked again after Clerk failed to take the change', async () => {
    clerkAnswer = () => new Response('{}', { status: 500 });
    expect((await link()).body.code).toBe('clerk_unavailable');
    clerkAnswer = () => new Response('{}', { status: 200 });
    expect((await link()).body.linked).toBe(true);
  });

  it('refuses a dba_account claim the account does not name back, and creates nothing', async () => {
    expect((await call(env, 'GET', '/api/v1/whoami', { auth: bearer('user_evil', { dba_account: account }) })).body.code).toBe('invalid_auth');
    const ghost = 'acct_GHOST0000000000000000000000';
    expect((await call(env, 'GET', '/api/v1/whoami', { auth: bearer('user_evil', { dba_account: ghost }) })).body.code).toBe('invalid_auth');
    expect(env.ACCOUNTS.get(ghost).storage.rows.size).toBe(0);
    // Without the claim a Clerk user opens only their own account.
    expect((await call(env, 'GET', '/api/v1/whoami', { auth: bearer('user_evil') })).body.account).toBe('user_evil');
  });

  it('unlinks only when another way in remains', async () => {
    await link();
    const clerk = bearer('user_new', { dba_account: account });
    const devices = (await call(env, 'GET', '/api/v1/devices', { auth: clerk })).body.items;
    await call(env, 'POST', `/api/v1/devices/${devices[0].id}/revoke`, { auth: clerk });
    expect((await call(env, 'DELETE', '/api/v1/account/clerk-link', { auth: clerk })).body.code).toBe('no_other_way_in');
    expect((await call(env, 'POST', '/api/v1/settings/recovery-codes', { auth: clerk })).status).toBe(200);
    expect((await call(env, 'DELETE', '/api/v1/account/clerk-link', { auth: clerk })).body).toMatchObject({ linked: false });
    expect(clerkCalls.at(-1)).toMatchObject({ url: 'https://api.clerk.com/v1/users/user_new/metadata', body: { public_metadata: { dba_account: null } } });
    expect((await call(env, 'GET', '/api/v1/whoami', { auth: clerk })).body.code).toBe('invalid_auth');
  });

  it('lets an unlinked sign-in be linked to another account', async () => {
    await link();
    expect((await as('POST', '/api/v1/settings/recovery-codes')).status).toBe(200);
    expect((await as('DELETE', '/api/v1/account/clerk-link')).body).toMatchObject({ linked: false });
    const other = await newDevice();
    const signed = await signUp(env, stripe, other);
    const asOther = asDevice(env, other, signed.credential);
    expect((await asOther('POST', '/api/v1/account/clerk-link', { body: { session_token: session('user_new') } })).body).toMatchObject({ linked: true });
    expect((await call(env, 'GET', '/api/v1/whoami', { auth: bearer('user_new', { dba_account: signed.account }) })).body.account).toBe(signed.account);
    // The first account no longer opens with it.
    expect((await call(env, 'GET', '/api/v1/whoami', { auth: bearer('user_new', { dba_account: account }) })).body.code).toBe('invalid_auth');
  });
});

describe('Clerk webhooks and linked or Clerk-free accounts', () => {
  it('sends the linked user\'s address to the linked account, and forgets it when Clerk deletes the user', async () => {
    await link();
    expect((await webhook(userEvent('user.updated', 'user_new', { email: 'new@example.com', linked: account }))).body).toMatchObject({ received: true });
    expect((await as('GET', '/api/v1/account')).body).toMatchObject({ security_email_address: 'new@example.com', security_email_source: 'clerk' });
    expect((await webhook(userEvent('user.deleted', 'user_new'))).status).toBe(200);
    const after = (await as('GET', '/api/v1/account')).body;
    expect(after).toMatchObject({ account, security_email_address: null, clerk_linked: false });
    expect(after.balance_microdollars).toBeGreaterThan(0);
    expect((await call(env, 'GET', '/api/v1/whoami', { auth: bearer('user_new', { dba_account: account }) })).body.code).toBe('invalid_auth');
    expect((await as('GET', '/api/v1/audit')).body.items.map(e => e.type)).toContain('account.clerk_removed');
  });

  it('ignores a link the account no longer names back, and refuses an unsigned event', async () => {
    expect((await webhook(userEvent('user.updated', 'user_stale', { email: 'x@example.com', linked: account }))).body).toMatchObject({ received: true, ignored: 'stale link' });
    expect((await as('GET', '/api/v1/account')).body.security_email_address).toBeNull();
    expect((await webhook(userEvent('user.created', 'user_y'), { secret: new Uint8Array(24).fill(1) })).body.code).toBe('invalid_signature');
  });

  it('keeps a Clerk account working with only its devices after its Clerk user is deleted', async () => {
    await webhook(userEvent('user.created', 'user_c', { email: 'c@example.com' }));
    await rpc(env.ACCOUNTS, 'user_c', 'deposit', { id: 'd1', amount: 1_000_000 });
    const phone = await newDevice();
    const credential = (await enroll(env, bearer('user_c'), phone, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }] })).approve.body.credential;
    await webhook(userEvent('user.deleted', 'user_c'));
    const asPhone = asDevice(env, phone, credential);
    expect((await asPhone('GET', '/api/v1/account')).body).toMatchObject({ account: 'user_c', security_email_address: null });
    expect((await asPhone('GET', '/api/v1/account')).body.balance_microdollars).toBeGreaterThan(0);
  });
});
