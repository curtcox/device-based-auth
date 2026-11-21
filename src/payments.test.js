import { describe, it, expect, beforeEach } from 'vitest';
import Stripe from 'stripe';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';
import { grossUp } from './utils/cost-policy.js';

// Payments as they work today (todo/clerk_free_accounts.md, phase A0): a dashboard device
// deposits through Stripe and is credited by the signed webhook, with Clerk not configured.
// Creating the account still needs a sign-in (STATUS B9), so LocalDev stands in for that one
// Clerk sign-in; then the environment turns into production with every CLERK_* variable unset.

const WEBHOOK_SECRET = 'whsec_test_dba';
const signer = new Stripe('sk_test_signer');

/** A stand-in for api.stripe.com that records each request and answers like Checkout does. */
function fakeStripe() {
  const requests = [];
  const fetch = async (url, init) => {
    const form = new URLSearchParams(init.body);
    requests.push({ url: String(url), method: init.method, headers: Object.fromEntries(Object.entries(init.headers || {}).map(([k, v]) => [k.toLowerCase(), v])), form });
    const id = `cs_test_${requests.length}`;
    return new Response(JSON.stringify({ id, object: 'checkout.session', url: `https://checkout.stripe.com/c/pay/${id}` }), { status: 200, headers: { 'Content-Type': 'application/json', 'Request-Id': `req_${requests.length}` } });
  };
  return { requests, fetch };
}

/** A paid Checkout session event for `account`, as Stripe would send it. */
function paidEvent({ account, credit, id = 'cs_test_paid', type = 'checkout.session.completed', ...overrides }) {
  return {
    id: `evt_${id}`, object: 'event', type,
    data: { object: { id, object: 'checkout.session', mode: 'payment', currency: 'usd', payment_status: 'paid', client_reference_id: account, amount_total: grossUp(credit), metadata: { account, credit_cents: String(credit), product: 'devicebasedauth' }, ...overrides } }
  };
}

/** Post an event to the webhook, signed with `secret`. */
function sendWebhook(env, event, { secret = WEBHOOK_SECRET } = {}) {
  const payload = JSON.stringify(event);
  return call(env, 'POST', '/webhooks/stripe', { body: payload, headers: { 'stripe-signature': signer.webhooks.generateTestHeaderString({ payload, secret }) } });
}

let env; let stripe; let device; let credential;
const asDevice = async (method, path, options = {}) => call(env, method, path, { ...options, headers: { ...(options.headers || {}), ...(await device.headers(method, path, credential)) } });
const balance = async () => (await asDevice('GET', '/api/v1/account')).body.balance_microdollars;

beforeEach(async () => {
  env = await testEnv();
  // The one sign-in that creating an account needs today, then a dashboard device.
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
  device = await newDevice();
  credential = (await enroll(env, 'alice', device, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }], name: 'Laptop browser' })).approve.body.credential;
  expect(credential).toBeTruthy();
  // From here on: production, payments configured, Clerk not configured at all.
  stripe = fakeStripe();
  Object.assign(env, { ENVIRONMENT: 'production', LAUNCH_APPROVED: 'true', STRIPE_SECRET_KEY: 'sk_test_dba', STRIPE_WEBHOOK_SECRET: WEBHOOK_SECRET, STRIPE_FETCH: stripe.fetch });
  expect(Object.keys(env).filter(name => name.startsWith('CLERK_'))).toEqual([]);
});

describe('payments without Clerk (B9, phase A0)', () => {
  it('runs in production, where only Clerk could sign a person in', async () => {
    expect((await call(env, 'GET', '/api/v1/whoami', { auth: 'alice' })).body.code).toBe('invalid_auth');
    expect((await call(env, 'GET', '/api/v1/whoami', { auth: 'Bearer some-session-token' })).body).toMatchObject({ code: 'invalid_auth', error: 'Session sign-in is not configured' });
    expect((await asDevice('GET', '/api/v1/whoami')).body).toMatchObject({ account: 'alice' });
  });

  it('lets a dashboard device quote and open a Checkout session', async () => {
    const quote = await asDevice('POST', '/api/v1/payments/checkout?dry_run=1', { body: { credit_cents: 2000 } });
    expect(quote.status).toBe(200);
    expect(quote.body).toMatchObject({ credit_cents: 2000, total_cents: grossUp(2000), card_cost_cents: grossUp(2000) - 2000 });
    expect(stripe.requests).toHaveLength(0);

    const opened = await asDevice('POST', '/api/v1/payments/checkout', { body: { credit_cents: 2000 }, headers: { 'Idempotency-Key': 'deposit-1' } });
    expect(opened.status).toBe(200);
    expect(opened.body).toMatchObject({ url: 'https://checkout.stripe.com/c/pay/cs_test_1', credit_cents: 2000, total_cents: grossUp(2000) });
    expect(stripe.requests).toHaveLength(1);
    const [sent] = stripe.requests;
    expect(sent.url).toBe('https://api.stripe.com/v1/checkout/sessions');
    expect(sent.method).toBe('POST');
    expect(sent.headers.authorization).toBe('Bearer sk_test_dba');
    expect(sent.headers['idempotency-key']).toBe('dba:alice:deposit-1');
    expect(sent.form.get('client_reference_id')).toBe('alice');
    expect(sent.form.get('metadata[account]')).toBe('alice');
    expect(sent.form.get('metadata[credit_cents]')).toBe('2000');
    expect(sent.form.get('metadata[product]')).toBe('devicebasedauth');
    expect(Number(sent.form.get('line_items[0][price_data][unit_amount]')) + Number(sent.form.get('line_items[1][price_data][unit_amount]'))).toBe(grossUp(2000));
  });

  it('credits the device\'s account once, from the signed webhook only', async () => {
    const before = await balance();
    const event = paidEvent({ account: 'alice', credit: 2000 });
    expect((await sendWebhook(env, event)).body).toMatchObject({ received: true });
    expect(await balance()).toBe(before + 2000 * 10000);
    // Stripe retries deliveries; a replay credits nothing more.
    expect((await sendWebhook(env, event)).status).toBe(200);
    expect(await balance()).toBe(before + 2000 * 10000);
    // A delayed payment method that succeeds later is credited the same way, once per session.
    await sendWebhook(env, paidEvent({ account: 'alice', credit: 500, id: 'cs_test_async', type: 'checkout.session.async_payment_succeeded' }));
    expect(await balance()).toBe(before + 2500 * 10000);
    const transactions = (await asDevice('GET', '/api/v1/transactions')).body;
    expect(JSON.stringify(transactions)).toContain('cs_test_paid');
  });

  it('credits nothing for unsigned, mismatched, unpaid or foreign events', async () => {
    const before = await balance();
    expect((await sendWebhook(env, paidEvent({ account: 'alice', credit: 2000 }), { secret: 'whsec_wrong' })).body.code).toBe('invalid_signature');
    expect((await call(env, 'POST', '/webhooks/stripe', { body: JSON.stringify(paidEvent({ account: 'alice', credit: 2000 })) })).body.code).toBe('invalid_signature');
    expect((await sendWebhook(env, paidEvent({ account: 'alice', credit: 2000, id: 'cs_1', amount_total: 2000 }))).body.code).toBe('invalid_payment');
    expect((await sendWebhook(env, paidEvent({ account: 'alice', credit: 2000, id: 'cs_2', client_reference_id: 'mallory' }))).body.code).toBe('invalid_payment');
    expect((await sendWebhook(env, paidEvent({ account: 'alice', credit: 2000, id: 'cs_3', currency: 'eur' }))).body.code).toBe('invalid_payment');
    expect((await sendWebhook(env, paidEvent({ account: 'alice', credit: 2000, id: 'cs_4', payment_status: 'unpaid' }))).body).toMatchObject({ received: true });
    expect((await sendWebhook(env, paidEvent({ account: 'alice', credit: 2000, id: 'cs_5', metadata: { account: 'alice', credit_cents: '2000', product: 'cronly' } }))).body).toMatchObject({ received: true });
    expect((await sendWebhook(env, paidEvent({ account: 'alice', credit: 2000, id: 'cs_6', type: 'checkout.session.expired' }))).body).toMatchObject({ received: true });
    expect(await balance()).toBe(before);
  });

  it('keeps the deposit limits and launch switches', async () => {
    const open = (credit, key) => asDevice('POST', '/api/v1/payments/checkout', { body: { credit_cents: credit }, headers: { 'Idempotency-Key': key } });
    expect((await open(499, 'a')).body.code).toBe('invalid_deposit');
    expect((await open(2001, 'b')).body.code).toBe('deposit_cap');
    delete env.LAUNCH_APPROVED;
    expect((await open(500, 'c')).body).toMatchObject({ code: 'launch_pending' });
    env.LAUNCH_APPROVED = 'true'; delete env.STRIPE_SECRET_KEY;
    expect((await open(500, 'd')).body).toMatchObject({ code: 'payments_unavailable' });
    expect((await sendWebhook(env, paidEvent({ account: 'alice', credit: 500 }))).body.code).toBe('payments_unavailable');
    expect(stripe.requests).toHaveLength(0);
  });
});
