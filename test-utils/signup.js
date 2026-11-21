/**
 * Helpers for tests of paid accounts without Clerk (STATUS B9): a stand-in for Stripe's API
 * (env.STRIPE_FETCH), Stripe webhook events signed for real, and a whole sign-up.
 */
import { expect } from 'vitest';
import Stripe from 'stripe';
import { testEnv, call, ORIGIN } from './env.js';
import { createProof } from '../packages/verify/src/index.js';
import { grossUp } from '../src/utils/cost-policy.js';

export const WEBHOOK_SECRET = 'whsec_test_dba';
const signer = new Stripe('sk_test_signer');

/** A stand-in for api.stripe.com that records each Checkout session it opens. */
export function fakeStripe() {
  const sessions = [];
  const fetch = async (url, init) => {
    const id = `cs_test_${sessions.length + 1}`;
    sessions.push({ id, url: String(url), form: new URLSearchParams(init.body), idempotencyKey: Object.entries(init.headers || {}).find(([k]) => k.toLowerCase() === 'idempotency-key')?.[1] });
    return new Response(JSON.stringify({ id, object: 'checkout.session', url: `https://checkout.stripe.com/c/pay/${id}` }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  return { sessions, fetch };
}

/** Production with payments configured and every CLERK_* variable unset. */
export async function clerkFreeEnv(overrides = {}) {
  const stripe = fakeStripe();
  const env = await testEnv({ ENVIRONMENT: 'production', COST_SAFETY_FAIL_OPEN: 'true', LAUNCH_APPROVED: 'true', STRIPE_SECRET_KEY: 'sk_test_dba', STRIPE_WEBHOOK_SECRET: WEBHOOK_SECRET, STRIPE_FETCH: stripe.fetch, ...overrides });
  expect(Object.keys(env).filter(name => name.startsWith('CLERK_'))).toEqual([]);
  return { env, stripe };
}

/** What Stripe sends when the Checkout session `opened` (as the fake recorded it) is paid. */
export function paidEvent(opened, overrides = {}) {
  const metadata = {};
  for (const [key, value] of opened.form) { const m = key.match(/^metadata\[(.+)\]$/); if (m) metadata[m[1]] = value; }
  return { id: `evt_${opened.id}`, object: 'event', type: 'checkout.session.completed', data: { object: { id: opened.id, object: 'checkout.session', mode: 'payment', currency: 'usd', payment_status: 'paid', client_reference_id: opened.form.get('client_reference_id'), amount_total: grossUp(Number(metadata.credit_cents)), metadata, ...overrides } } };
}

/** Post an event to the Stripe webhook, signed with `secret`. */
export function sendWebhook(env, event, { secret = WEBHOOK_SECRET } = {}) {
  const payload = JSON.stringify(event);
  return call(env, 'POST', '/webhooks/stripe', { body: payload, headers: { 'stripe-signature': signer.webhooks.generateTestHeaderString({ payload, secret }) } });
}

/** Start a sign-up for `device`. */
export async function startSignup(env, device, { credit = 2000, payload = {}, accept = true } = {}) {
  return call(env, 'POST', '/api/v1/signup', { body: { request: await device.enrollRequest({ device: { name: 'Laptop browser', kind: 'browser' }, ...payload }), credit_cents: credit, accept_terms: accept } });
}

/** Ask to complete a sign-up, proving `key` (normally the signing-up device) with a DPoP proof bound to the ticket. */
export async function completeSignup(env, key, ticket) {
  const path = '/api/v1/signup/complete';
  const proof = await createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method: 'POST', url: `${ORIGIN}${path}`, credential: ticket });
  return call(env, 'POST', path, { body: { ticket }, headers: { DPoP: proof } });
}

/** A whole sign-up: start, Stripe's paid webhook, complete. Returns { account, credential }. */
export async function signUp(env, stripe, device, options) {
  const started = await startSignup(env, device, options);
  expect(started.status, JSON.stringify(started.body)).toBe(200);
  await sendWebhook(env, paidEvent(stripe.sessions.at(-1)));
  const done = await completeSignup(env, device, started.body.ticket);
  expect(done.body.status, JSON.stringify(done.body)).toBe('complete');
  return { account: done.body.account, credential: done.body.credential };
}

/** Call the Worker as `device` holding `credential`. */
export const asDevice = (env, device, credential) => async (method, path, options = {}) => call(env, method, path, { ...options, headers: { ...(options.headers || {}), ...(await device.headers(method, path, credential)) } });
