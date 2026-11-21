import Stripe from 'stripe';
import { assert, readJson, readText } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { grossUp, COST_POLICY } from '../utils/cost-policy.js';
import { MINIMUM_DEPOSIT_CENTS, MAXIMUM_DEPOSIT_CENTS } from '../utils/pricing.js';

const PRODUCT = 'devicebasedauth';
const WEEK_MS = 7 * 86400000;

/** Ids of accounts made by paying (api/signup.js); Clerk accounts keep Clerk's user ids. */
export const SIGNUP_ACCOUNT = /^acct_[0-9A-Z]{26}$/;

/**
 * A Stripe client. A function in env.STRIPE_FETCH replaces Stripe's HTTP transport in tests only
 * (a deployed Worker's variables are strings, so it can never be set there).
 */
const stripeClient = env => new Stripe(env.STRIPE_SECRET_KEY, { httpClient: Stripe.createFetchHttpClient(typeof env.STRIPE_FETCH === 'function' ? env.STRIPE_FETCH : undefined) });

/**
 * Check a deposit amount and quote it. An account in its first week (or one that does not exist
 * yet) may deposit at most newAccountDepositCapCents per payment.
 */
export function quoteDeposit(credit, { newAccount }) {
  assert(Number.isSafeInteger(credit) && credit >= MINIMUM_DEPOSIT_CENTS && credit <= MAXIMUM_DEPOSIT_CENTS, 'invalid_deposit', 'Deposit must be $5–$1,000');
  if (newAccount) assert(credit <= COST_POLICY.newAccountDepositCapCents, 'deposit_cap', 'New accounts may deposit at most $20 per payment in their first week');
  const total = grossUp(credit);
  return { credit_cents: credit, card_cost_cents: total - credit, total_cents: total };
}

/**
 * Open an itemized Stripe Checkout (ported from cronly) that credits `account`. `metadata` adds to
 * what the webhook checks; nothing is credited here.
 */
export async function openCheckout(env, { account, credit, metadata = {}, returnPath, idempotencyKey }) {
  const quote = quoteDeposit(credit, { newAccount: false });
  assert(env.ENVIRONMENT !== 'production' || env.LAUNCH_APPROVED === 'true', 'launch_pending', 'Payments open after owner and legal launch approval', 503);
  assert(env.STRIPE_SECRET_KEY, 'payments_unavailable', 'Payments are not configured', 503);
  const products = [env.STRIPE_CREDIT_PRODUCT_ID, env.STRIPE_CARD_COST_PRODUCT_ID];
  const product = (id, name) => id ? { product: id } : { product_data: { name } };
  const session = await stripeClient(env).checkout.sessions.create({
    mode: 'payment', payment_method_types: ['card'], client_reference_id: account,
    metadata: { ...metadata, account, credit_cents: String(credit), product: PRODUCT },
    line_items: [
      { price_data: { currency: 'usd', unit_amount: credit, ...product(products[0], 'devicebasedauth.org prepaid credit') }, quantity: 1 },
      { price_data: { currency: 'usd', unit_amount: quote.card_cost_cents, ...product(products[1], 'Card payment cost (non-refundable)') }, quantity: 1 }
    ],
    success_url: `${env.APP_ORIGIN}${returnPath}`, cancel_url: `${env.APP_ORIGIN}${returnPath}`
  }, { idempotencyKey });
  return { url: session.url, ...quote };
}

/** A deposit into the caller's account. Credit is granted only by the signed webhook. */
export async function checkout(request, env, auth, dryRun) {
  const body = await readJson(request); const credit = body.credit_cents;
  const account = await rpc(env.ACCOUNTS, auth.account, 'account');
  const quote = quoteDeposit(credit, { newAccount: Date.now() - account.created_at < WEEK_MS });
  if (dryRun) return quote;
  return openCheckout(env, { account: auth.account, credit, returnPath: '/app.html#account', idempotencyKey: `dba:${auth.account}:${request.headers.get('Idempotency-Key') || crypto.randomUUID()}` });
}

/**
 * What the signed webhook does for a paid sign-up (api/signup.js), shared with the local-only
 * dev route: create the account bound to the signing-up key, then credit it (once per id).
 */
export async function creditSignup(env, { account, signup, jkt, deposit, amount, kind }) {
  await rpc(env.ACCOUNTS, account, 'init', { account, signup: { id: signup, jkt } });
  await rpc(env.ACCOUNTS, account, 'deposit', { id: deposit, amount, ...(kind ? { kind } : {}) });
}

/** Credit only signed, paid Checkout events, once per Checkout session. */
export async function stripeWebhook(request, env) {
  assert(env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET, 'payments_unavailable', 'Payments are not configured', 503);
  const stripe = stripeClient(env);
  let event; const payload = await readText(request);
  try { event = await stripe.webhooks.constructEventAsync(payload, request.headers.get('stripe-signature'), env.STRIPE_WEBHOOK_SECRET, undefined, Stripe.createSubtleCryptoProvider()); }
  catch { assert(false, 'invalid_signature', 'Invalid webhook signature', 400); }
  if (!['checkout.session.completed', 'checkout.session.async_payment_succeeded'].includes(event.type)) return { received: true };
  const session = event.data.object; const metadata = session.metadata || {};
  if (metadata.product !== PRODUCT || session.payment_status !== 'paid') return { received: true };
  const credit = Number(metadata.credit_cents);
  assert(session.mode === 'payment' && session.currency === 'usd' && session.client_reference_id === metadata.account && Number.isSafeInteger(credit) && credit >= MINIMUM_DEPOSIT_CENTS && credit <= MAXIMUM_DEPOSIT_CENTS && session.amount_total === grossUp(credit), 'invalid_payment', 'Payment does not match credited amount');
  const account = session.client_reference_id;
  if (metadata.kind === 'signup') {
    // Only POST /api/v1/signup makes these (with a fresh account id), and Stripe signed them.
    assert(SIGNUP_ACCOUNT.test(account) && /^sup_[0-9A-Z]{16}$/.test(metadata.signup || '') && /^[A-Za-z0-9_-]{43}$/.test(metadata.jkt || ''), 'invalid_payment', 'Sign-up payment is malformed');
    await creditSignup(env, { account, signup: metadata.signup, jkt: metadata.jkt, deposit: session.id, amount: credit * 10000 });
    return { received: true };
  }
  assert(metadata.kind === undefined, 'invalid_payment', 'Unknown payment kind');
  await rpc(env.ACCOUNTS, account, 'init', { account });
  await rpc(env.ACCOUNTS, account, 'deposit', { id: session.id, amount: credit * 10000 });
  return { received: true };
}
