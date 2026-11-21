import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { randomId } from '../utils/ids.js';
import { signToken, verifyToken } from '../auth/tokens.js';
import { jwkThumbprint } from '../../packages/verify/src/jose.js';
import { verifyProof, VerificationError } from '../../packages/verify/src/credential.js';
import { cleanDevice, issueCredential } from '../services/credentials.js';
import { appAudience } from '../services/issuer.js';
import { readEnrollRequest } from './enrollments.js';
import { quoteDeposit, openCheckout, creditSignup } from './payments.js';

// Paid accounts without Clerk (todo/clerk_free_accounts.md §3.2, STATUS B9): a device pays the
// first deposit and the signed Stripe webhook creates the account, bound to that device's key.
// Starting writes nothing (the request travels in a signed ticket, as anonymous enrollment
// starts do); storage is written only when money arrives.

const TICKET_PREFIX = 'sup_';
const TICKET_DAYS = 30;
const POLL_INTERVAL = 3;
/** A sign-up always makes a dashboard device, whatever audience and grants the request named. */
export const DASHBOARD_GRANTS = Object.freeze([{ actions: ['dba:session'] }]);

/**
 * Start a sign-up: body { request (a dba-enroll+jwt signed by the new key; aud and grants may be
 * left out), credit_cents, accept_terms: true }. Opens a Stripe Checkout for a new account and
 * returns its URL with a signed ticket the device keeps to complete. ?dry_run=1 only quotes.
 */
export async function startSignup(request, env, dryRun) {
  const body = await readJson(request, 32768);
  const quote = quoteDeposit(body.credit_cents, { newAccount: true });
  if (dryRun) return { dry_run: true, ...quote };
  assert(body.accept_terms === true, 'terms_required', 'Accept the terms of service and privacy policy (accept_terms: true) to create an account');
  const { jwk, payload, lifetime, attestation } = await readEnrollRequest(body.request, { env, defaults: { aud: [appAudience(env)], grants: DASHBOARD_GRANTS } });
  const account = randomId('acct', 26); const id = randomId('sup');
  const jkt = await jwkThumbprint(jwk);
  const opened = await openCheckout(env, { account, credit: quote.credit_cents, metadata: { kind: 'signup', signup: id, jkt, terms_accepted: 'true' }, returnPath: '/app.html#signup', idempotencyKey: `dba:signup:${id}` });
  const exp = Math.floor(Date.now() / 1000) + TICKET_DAYS * 86400;
  const ticket = await signToken(TICKET_PREFIX, { id, account, jwk, jkt, device: cleanDevice(payload.device), attestation, lifetime, credit_cents: quote.credit_cents, exp }, env.TOKEN_SIGNING_KEY);
  return { account, signup_id: id, ...opened, ticket, complete_url: `${env.APP_ORIGIN}/api/v1/signup/complete`, interval: POLL_INTERVAL, expires_at: exp };
}

async function readTicket(env, ticket) {
  const data = await verifyToken(ticket || '', TICKET_PREFIX, env.TOKEN_SIGNING_KEY);
  assert(data, 'invalid_signup', 'Sign-up ticket is invalid or expired', 400);
  return data;
}

/**
 * Complete a sign-up: body { ticket }, with a DPoP proof made by the ticket's key whose `ath` is
 * the ticket's hash. Until the payment arrives this answers { status: 'pending' } (poll every
 * `interval` seconds); then it issues the dashboard credential, charging the issue price to the
 * new balance. Asking again returns the same credential (its charge id is the sign-up's).
 */
export async function completeSignup(request, env) {
  const body = await readJson(request, 32768);
  const data = await readTicket(env, body.ticket);
  const proof = request.headers.get('DPoP');
  assert(proof, 'proof_required', 'A DPoP proof made by the signing-up key, with ath over the ticket, is required', 401);
  // A replayed proof can only fetch the same credential again, which is useless without the key.
  try { await verifyProof(proof, { method: request.method, url: request.url, credential: body.ticket, jkt: data.jkt }); }
  catch (error) { if (error instanceof VerificationError) assert(false, error.code, error.message, 401); throw error; }
  const state = await rpc(env.ACCOUNTS, data.account, 'signup-status', { id: data.id, jkt: data.jkt });
  if (!state.paid) return { status: 'pending', account: data.account, interval: POLL_INTERVAL };
  const issued = await issueCredential(env, data.account, { public_jwk: data.jwk, device: data.device, aud: [appAudience(env)], grants: DASHBOARD_GRANTS, lifetime_seconds: data.lifetime }, { source: 'signup', chargeId: `signup-${data.id}`, attestation: data.attestation });
  return { status: 'complete', account: data.account, credential: issued.credential, cid: issued.cid, device_id: issued.device_id, cost_microdollars: issued.charged };
}

/** Local development only: do what the Stripe webhook does when a sign-up is paid. */
export async function devSignupPaid(request, env) {
  assert(env.ENVIRONMENT === 'local', 'not_found', 'Not found', 404);
  const data = await readTicket(env, (await readJson(request, 32768)).ticket);
  await creditSignup(env, { account: data.account, signup: data.id, jkt: data.jkt, deposit: `dev-${data.id}`, amount: data.credit_cents * 10000, kind: 'development credit' });
  return { status: 'paid', account: data.account };
}
