/**
 * Creating an account by paying, and getting back into one after losing every device, from the
 * command line (STATUS B9, done/clerk_free_accounts.md §3.8). These functions do the network part
 * and take the client, the key and a clock, so they are tested against the real Worker in memory;
 * commands/account.js does the files and the printing.
 */
import { UsageError, ApiError } from './errors.js';
import { enrollmentPayload, signEnrollmentRequest } from './enrollment.js';

/** Recovery methods `dba recover` knows. */
export const RECOVERY_VIA = ['code', 'gate', 'email'];

/** A deposit in dollars ("5", "12.50") as cents. */
export function depositCents(value = '5') {
  const text = String(value).trim().replace(/^\$/, '');
  if (!/^\d{1,4}(\.\d{1,2})?$/.test(text)) throw new UsageError('--deposit is an amount in dollars, like 5 or 12.50');
  return Math.round(Number(text) * 100);
}

/** Which way `dba recover` goes: --via, else a code means "code", an email "email", else "gate". */
export function recoveryVia({ via, code, email, account }) {
  const chosen = via ?? (code ? 'code' : email ? 'email' : 'gate');
  if (!RECOVERY_VIA.includes(chosen)) throw new UsageError(`--via must be one of ${RECOVERY_VIA.join(', ')}`);
  if (chosen === 'code' && !code) throw new UsageError('--via code needs --code (one from your recovery sheet)');
  if (chosen === 'email' && !email) throw new UsageError('--via email needs --email (the address your account verified)');
  if (chosen !== 'email' && !account) throw new UsageError('--account is the account id on your recovery sheet and the Account page');
  return chosen;
}

/** A sign-up or recovery request: an enrollment request with no audience or grants. */
const signedRequest = (key, { name, kind, keyProtection, attestation }) => signEnrollmentRequest(key, enrollmentPayload({ name, kind, keyProtection, attestation }));

/** POST /api/v1/signup for `key`. Resolves with { url, account, ticket, local_payment?, … }. */
export async function startSignup(client, key, { credit, device }) {
  return client.request('POST', '/api/v1/signup', { body: { request: await signedRequest(key, device), credit_cents: credit, accept_terms: true } });
}

/** POST /api/v1/recover for `key`: { status: 'recovered', credential } at once, or a ticket to wait on. */
export async function startRecovery(client, key, { via, account, code, email, device }) {
  return client.request('POST', '/api/v1/recover', { body: { via, request: await signedRequest(key, device), ...(account ? { account } : {}), ...(code ? { code } : {}), ...(email ? { email } : {}) } });
}

/**
 * Ask `path` (…/signup/complete or …/recover/complete) with the ticket, proving the key, until it
 * hands over a credential or `waitSeconds` pass. Network errors are retried; a refusal throws.
 * Returns the answer with the credential, or { status: 'timeout', last } with the last "not yet".
 */
export async function pollTicket(client, key, path, ticket, { waitSeconds = 900, onPending, sleep = ms => new Promise(r => setTimeout(r, ms)), clock = () => Date.now() } = {}) {
  const deadline = clock() + waitSeconds * 1000;
  let last = null;
  for (;;) {
    try {
      last = await client.request('POST', path, { body: { ticket }, device: { key, credential: ticket } });
      if (last.credential) return last;
      onPending?.(last);
    } catch (error) {
      if (error.code !== 'network_error') throw error;
    }
    if (clock() >= deadline) return { status: 'timeout', last };
    await sleep(Math.min((last?.interval || 3) * 1000, Math.max(0, deadline - clock())));
  }
}

/** The error to raise when a wait ended without a credential. */
export function stillWaiting(what, last) {
  const when = last?.ready_at ? ` (it can finish after ${new Date(last.ready_at).toISOString()})` : '';
  return new ApiError(`Still waiting for the ${what}${when}. Run the same command with --resume later.`, 'still_waiting');
}
