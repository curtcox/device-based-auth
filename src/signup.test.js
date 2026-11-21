import { describe, it, expect, beforeEach } from 'vitest';
import Stripe from 'stripe';
import { testEnv, call, newDevice, ORIGIN } from '../test-utils/env.js';
import { createProof, inspectCredential } from '../packages/verify/src/index.js';
import { grossUp } from './utils/cost-policy.js';
import { price } from './utils/pricing.js';

// Paid accounts without Clerk, phase A1 (todo/clerk_free_accounts.md §3.2, STATUS B9): a device
// pays the first deposit, the signed Stripe webhook creates the account, and the device completes
// its sign-up to get a dashboard credential. Everything here runs as production with every
// CLERK_* variable unset; Stripe's API is faked through env.STRIPE_FETCH and its webhooks are
// really signed.

const WEBHOOK_SECRET = 'whsec_test_dba';
const signer = new Stripe('sk_test_signer');

function fakeStripe() {
  const sessions = [];
  const fetch = async (url, init) => {
    const form = new URLSearchParams(init.body);
    const id = `cs_test_${sessions.length + 1}`;
    sessions.push({ id, url: String(url), form, idempotencyKey: Object.entries(init.headers || {}).find(([k]) => k.toLowerCase() === 'idempotency-key')?.[1] });
    return new Response(JSON.stringify({ id, object: 'checkout.session', url: `https://checkout.stripe.com/c/pay/${id}` }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  return { sessions, fetch };
}

/** What Stripe sends when the Checkout session `opened` (as the fake recorded it) is paid. */
function paidEvent(opened, overrides = {}) {
  const metadata = {};
  for (const [key, value] of opened.form) { const m = key.match(/^metadata\[(.+)\]$/); if (m) metadata[m[1]] = value; }
  const credit = Number(metadata.credit_cents);
  return { id: `evt_${opened.id}`, object: 'event', type: 'checkout.session.completed', data: { object: { id: opened.id, object: 'checkout.session', mode: 'payment', currency: 'usd', payment_status: 'paid', client_reference_id: opened.form.get('client_reference_id'), amount_total: grossUp(credit), metadata, ...overrides } } };
}

function sendWebhook(env, event) {
  const payload = JSON.stringify(event);
  return call(env, 'POST', '/webhooks/stripe', { body: payload, headers: { 'stripe-signature': signer.webhooks.generateTestHeaderString({ payload, secret: WEBHOOK_SECRET }) } });
}

let env; let stripe;
beforeEach(async () => {
  stripe = fakeStripe();
  env = await testEnv({ ENVIRONMENT: 'production', COST_SAFETY_FAIL_OPEN: 'true', LAUNCH_APPROVED: 'true', STRIPE_SECRET_KEY: 'sk_test_dba', STRIPE_WEBHOOK_SECRET: WEBHOOK_SECRET, STRIPE_FETCH: stripe.fetch });
  expect(Object.keys(env).filter(name => name.startsWith('CLERK_'))).toEqual([]);
});

/** A device starts a sign-up. */
async function start(device, { credit = 2000, payload = {}, accept = true } = {}) {
  return call(env, 'POST', '/api/v1/signup', { body: { request: await device.enrollRequest({ device: { name: 'Laptop browser', kind: 'browser' }, ...payload }), credit_cents: credit, accept_terms: accept } });
}

/** The device asks to complete, proving its key with a DPoP proof bound to the ticket. */
async function complete(device, ticket, { key = device } = {}) {
  const path = '/api/v1/signup/complete';
  const proof = await createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method: 'POST', url: `${ORIGIN}${path}`, credential: ticket });
  return call(env, 'POST', path, { body: { ticket }, headers: { DPoP: proof } });
}

const asDevice = (device, credential) => async (method, path, options = {}) => call(env, method, path, { ...options, headers: { ...(options.headers || {}), ...(await device.headers(method, path, credential)) } });

describe('sign-up by paying, without Clerk (B9, phase A1)', () => {
  it('creates, funds and signs in an account with only a device and a card', async () => {
    const device = await newDevice();
    const started = await start(device);
    expect(started.status).toBe(200);
    const { account, ticket, url, signup_id: signupId } = started.body;
    expect(account).toMatch(/^acct_[0-9A-Z]{26}$/);
    expect(url).toBe('https://checkout.stripe.com/c/pay/cs_test_1');
    expect(started.body).toMatchObject({ credit_cents: 2000, total_cents: grossUp(2000), interval: 3 });
    // The Checkout session names the new account, the sign-up and the key; nothing is stored yet.
    const [opened] = stripe.sessions;
    expect(opened.form.get('client_reference_id')).toBe(account);
    expect(opened.form.get('metadata[kind]')).toBe('signup');
    expect(opened.form.get('metadata[signup]')).toBe(signupId);
    expect(opened.form.get('metadata[jkt]')).toBe(device.jkt);
    expect(opened.idempotencyKey).toBe(`dba:signup:${signupId}`);
    expect(env.ACCOUNTS.objects.size).toBe(0);

    // Before the payment arrives the device is told to wait, and still nothing is stored.
    expect((await complete(device, ticket)).body).toMatchObject({ status: 'pending', account, interval: 3 });
    expect([...env.ACCOUNTS.objects.values()].map(o => o.storage.rows.size)).toEqual([0]);

    // Stripe's signed webhook creates the account and credits it.
    expect((await sendWebhook(env, paidEvent(opened))).body).toMatchObject({ received: true });
    const done = await complete(device, ticket);
    expect(done.body).toMatchObject({ status: 'complete', account, cost_microdollars: price('issue') });
    const credential = done.body.credential;
    const { payload } = inspectCredential(credential);
    expect(payload).toMatchObject({ acct: account, cnf: { jkt: device.jkt }, grants: [{ actions: ['dba:session'] }], device: { name: 'Laptop browser' } });

    // The device now runs the account: who am I, balance, a credential for another site.
    const as = asDevice(device, credential);
    expect((await as('GET', '/api/v1/whoami')).body).toMatchObject({ account });
    expect((await as('GET', '/api/v1/account')).body).toMatchObject({ account, balance_microdollars: 2000 * 10000 - price('issue') });
    const other = await newDevice();
    const issued = await as('POST', '/api/v1/credentials', { body: { public_jwk: other.publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }] } });
    expect(issued.status).toBe(200);
    expect(inspectCredential(issued.body.credential).payload.acct).toBe(account);
    // And deposits more through Checkout like any other account.
    const more = await as('POST', '/api/v1/payments/checkout', { body: { credit_cents: 1000 }, headers: { 'Idempotency-Key': 'top-up' } });
    expect(more.status).toBe(200);
    expect(stripe.sessions[1].form.get('client_reference_id')).toBe(account);
    expect(stripe.sessions[1].form.get('metadata[kind]')).toBeNull();
    await sendWebhook(env, paidEvent(stripe.sessions[1]));
    expect((await as('GET', '/api/v1/account')).body.balance_microdollars).toBe(3000 * 10000 - 2 * price('issue'));
  });

  it('returns the same credential when asked again, and charges once', async () => {
    const device = await newDevice();
    const { ticket } = (await start(device)).body;
    await sendWebhook(env, paidEvent(stripe.sessions[0]));
    await sendWebhook(env, paidEvent(stripe.sessions[0])); // Stripe retries; nothing changes.
    const first = await complete(device, ticket);
    const again = await complete(device, ticket);
    expect(again.body.credential).toBe(first.body.credential);
    expect(again.body.cost_microdollars).toBe(0);
    const as = asDevice(device, first.body.credential);
    expect((await as('GET', '/api/v1/account')).body.balance_microdollars).toBe(2000 * 10000 - price('issue'));
  });

  it('quotes without a request, and checks the deposit and the terms', async () => {
    const quote = await call(env, 'POST', '/api/v1/signup?dry_run=1', { body: { credit_cents: 500 } });
    expect(quote.body).toMatchObject({ dry_run: true, credit_cents: 500, total_cents: grossUp(500) });
    const device = await newDevice();
    expect((await start(device, { credit: 499 })).body.code).toBe('invalid_deposit');
    expect((await start(device, { credit: 2500 })).body.code).toBe('deposit_cap');
    expect((await start(device, { accept: false })).body.code).toBe('terms_required');
    expect((await call(env, 'POST', '/api/v1/signup', { body: { request: 'not-a-jws', credit_cents: 500, accept_terms: true } })).body.code).toBe('invalid_request');
    delete env.LAUNCH_APPROVED;
    expect((await start(device)).body.code).toBe('launch_pending');
    expect(stripe.sessions).toHaveLength(0);
  });

  it('makes a dashboard device whatever the request asked for', async () => {
    const device = await newDevice();
    const { ticket } = (await start(device, { payload: { aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }] } })).body;
    await sendWebhook(env, paidEvent(stripe.sessions[0]));
    const { payload } = inspectCredential((await complete(device, ticket)).body.credential);
    expect(payload.aud).toEqual(['devicebasedauth.org']);
    expect(payload.grants).toEqual([{ actions: ['dba:session'] }]);
  });

  it('completes only for the key that signed up, with a real ticket', async () => {
    const device = await newDevice();
    const { ticket } = (await start(device)).body;
    await sendWebhook(env, paidEvent(stripe.sessions[0]));
    const thief = await newDevice();
    expect((await complete(device, ticket, { key: thief })).body.code).toBe('key_mismatch');
    expect((await call(env, 'POST', '/api/v1/signup/complete', { body: { ticket } })).body.code).toBe('proof_required');
    expect((await complete(device, `${ticket}x`)).body.code).toBe('invalid_signup');
    // A proof bound to another ticket does not carry over.
    const path = '/api/v1/signup/complete';
    const wrongAth = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url: `${ORIGIN}${path}`, credential: 'another' });
    expect((await call(env, 'POST', path, { body: { ticket }, headers: { DPoP: wrongAth } })).body.code).toBe('invalid_proof');
  });

  it('never attaches a sign-up to an account that already exists, or to a forged event', async () => {
    const device = await newDevice();
    const { ticket, account } = (await start(device)).body;
    const opened = stripe.sessions[0];
    // A sign-up event naming an account that is not a sign-up id is refused.
    const clerkLike = paidEvent(opened, { client_reference_id: 'user_2abc' });
    clerkLike.data.object.metadata.account = 'user_2abc';
    expect((await sendWebhook(env, clerkLike)).body.code).toBe('invalid_payment');
    expect((await sendWebhook(env, paidEvent(opened, { metadata: { ...paidEvent(opened).data.object.metadata, kind: 'gift' } }))).body.code).toBe('invalid_payment');
    // An unsigned event credits nothing and creates nothing.
    expect((await call(env, 'POST', '/webhooks/stripe', { body: JSON.stringify(paidEvent(opened)) })).body.code).toBe('invalid_signature');
    expect((await complete(device, ticket)).body.status).toBe('pending');
    // The account exists from its first paid event; a second sign-up for the same id cannot rebind it.
    await sendWebhook(env, paidEvent(opened));
    const other = await newDevice();
    const forged = paidEvent(opened, { id: 'cs_test_other' });
    forged.data.object.metadata.jkt = other.jkt;
    await sendWebhook(env, forged);
    const status = await env.ACCOUNTS.get(account).fetch(new Request('http://do/', { method: 'POST', body: JSON.stringify({ op: 'signup-status', id: forged.data.object.metadata.signup, jkt: other.jkt }) }));
    expect((await status.json()).paid).toBe(false);
    expect((await complete(device, ticket)).body.status).toBe('complete');
  });
});

describe('local development sign-up', () => {
  it('lets the dev route stand in for Stripe in local mode only', async () => {
    const local = await testEnv({ STRIPE_SECRET_KEY: 'sk_test_dba', STRIPE_FETCH: fakeStripe().fetch });
    const device = await newDevice();
    const started = await call(local, 'POST', '/api/v1/signup', { body: { request: await device.enrollRequest({ device: { name: 'cli' } }), credit_cents: 500, accept_terms: true } });
    expect((await call(local, 'POST', '/api/v1/dev/signup-paid', { body: { ticket: started.body.ticket } })).body).toMatchObject({ status: 'paid', account: started.body.account });
    expect((await call(env, 'POST', '/api/v1/dev/signup-paid', { body: { ticket: started.body.ticket } })).status).toBe(404);
  });
});
