import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { jwkThumbprint } from '../../packages/verify/src/jose.js';
import { verifyProof, VerificationError } from '../../packages/verify/src/credential.js';
import { signToken, verifyToken } from '../auth/tokens.js';
import { randomId } from '../utils/ids.js';
import { cleanEmailAddress } from '../services/email.js';
import { EMAIL_LINK_MS, EMAIL_RECOVERY_WAIT_MS } from '../durable-objects/account/email-address.js';
import { emailHash } from './email-address.js';
import { cleanDevice, issueCredential } from '../services/credentials.js';
import { appAudience } from '../services/issuer.js';
import { readEnrollRequest } from './enrollments.js';
import { DASHBOARD_GRANTS } from './signup.js';

// Getting back in after losing every device (done/clerk_free_accounts.md §3.5, STATUS B9). Works
// the same for Clerk accounts and accounts made by paying; nobody needs to be signed in.

const TICKET_PREFIX = 'rcv_';
const POLL_INTERVAL = 3;
// An email recovery waits hours: its device polls once a minute.
const EMAIL_POLL_INTERVAL = 60;

/** The new device's credential: a dashboard device, free, and it may bring back a revoked device. */
const recoveredCredential = (env, account, { jwk, device, lifetime, attestation }, chargeId) =>
  issueCredential(env, account, { public_jwk: jwk, device, aud: [appAudience(env)], grants: DASHBOARD_GRANTS, lifetime_seconds: lifetime }, { source: 'recovery', chargeId, attestation, reinstate: true, free: true });

/**
 * POST /api/v1/recover: body { account, via, request, code? }. `request` is a dba-enroll+jwt
 * signed by the new device's key within the last 10 minutes (as for POST /api/v1/enrollments; aud
 * and grants may be left out), which proves the key.
 * - via 'code' (the default): uses up the recovery code and issues the new device a dashboard
 *   credential at once (a used code cannot be replayed).
 * - via 'gate': asks the account's passkey, security-key and device gates; returns the number the
 *   new device shows (approvers type it), the approval page link for passkeys, and a ticket for
 *   POST /api/v1/recover/complete.
 * - via 'email': if `email` is an account's verified address, emails it a link; once the link is
 *   used, the device gets in after EMAIL_RECOVERY_WAIT_MS unless a signed-in device cancels. The
 *   answer is the same whether or not the address belongs to an account.
 * Every way the credential is free (an empty balance must not lock the owner out) and counts as
 * a recent sign-in for ten minutes, so the owner can revoke the lost devices and make new codes.
 */
export async function recoverAccount(request, env) {
  const body = await readJson(request, 32768);
  // By email the address finds the account; otherwise the owner names it (recovery sheet, Account page).
  assert(body.via === 'email' || (typeof body.account === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(body.account)), 'invalid_account', 'account is the account id shown on your recovery sheet and Account page');
  const via = body.via ?? 'code';
  assert(['code', 'gate', 'email'].includes(via), 'invalid_recovery', 'via must be "code", "gate" or "email"');
  const address = via === 'email' ? cleanEmailAddress(body.email) : null;
  if (via === 'email') assert(address, 'invalid_email', 'email must be the address your account verified');
  if (via === 'code') assert(typeof body.code === 'string' && body.code.length > 0 && body.code.length <= 40, 'invalid_recovery_code', 'code is one of your recovery codes');
  const { jwk, payload, lifetime, attestation } = await readEnrollRequest(body.request, { env, defaults: { aud: [appAudience(env)], grants: DASHBOARD_GRANTS } });
  const device = cleanDevice(payload.device);
  const jkt = await jwkThumbprint(jwk);
  if (via === 'email') {
    const hash = await emailHash(address); const id = randomId('erc');
    const { account } = await rpc(env.REGISTRY, 'global', 'email-get', { hash });
    if (account) await rpc(env.ACCOUNTS, account, 'email-recovery-start', { id, jkt, device_name: device.name ?? null, account });
    const exp = Math.ceil((Date.now() + EMAIL_LINK_MS + EMAIL_RECOVERY_WAIT_MS + 7 * 86400000) / 1000);
    const ticket = await signToken(TICKET_PREFIX, { via: 'email', h: hash, id, jwk, jkt, device, lifetime, attestation, exp }, env.TOKEN_SIGNING_KEY);
    return { status: 'pending', stage: 'waiting_for_link', message: 'If this address belongs to an account, a recovery link was emailed to it', wait_hours: EMAIL_RECOVERY_WAIT_MS / 3600000, ticket, complete_url: `${env.APP_ORIGIN}/api/v1/recover/complete`, interval: EMAIL_POLL_INTERVAL };
  }
  if (via === 'gate') {
    const asked = await rpc(env.ACCOUNTS, body.account, 'recover-gate-start', { jkt, device_name: device.name ?? null, account: body.account });
    const ticket = await signToken(TICKET_PREFIX, { account: body.account, id: asked.id, jwk, jkt, device, lifetime, attestation, exp: Math.ceil(asked.expires_at / 1000) + 600 }, env.TOKEN_SIGNING_KEY);
    return { status: 'pending', account: body.account, number: asked.number, ...(asked.approve_url ? { approve_url: asked.approve_url } : {}), ticket, complete_url: `${env.APP_ORIGIN}/api/v1/recover/complete`, interval: Math.max(POLL_INTERVAL, asked.retry_after), expires_at: asked.expires_at };
  }
  const used = await rpc(env.ACCOUNTS, body.account, 'recover-with-code', { code: body.code, jkt, device_name: device.name ?? null });
  const issued = await recoveredCredential(env, body.account, { jwk, device, lifetime, attestation }, `recover-${used.id}`);
  return { status: 'recovered', account: body.account, credential: issued.credential, cid: issued.cid, device_id: issued.device_id, recovery_codes_left: used.left };
}

/**
 * POST /api/v1/recover/complete: body { ticket } from a recovery by gate, with a DPoP proof by the
 * new key whose `ath` is the ticket's hash. Answers pending until a gate approves (poll every
 * `interval` seconds), then the new device's credential; asking again returns the same one.
 */
export async function completeRecovery(request, env) {
  const body = await readJson(request, 32768);
  const data = await verifyToken(body.ticket || '', TICKET_PREFIX, env.TOKEN_SIGNING_KEY);
  assert(data, 'invalid_recovery', 'Recovery ticket is invalid or expired', 400);
  const proof = request.headers.get('DPoP');
  assert(proof, 'proof_required', 'A DPoP proof made by the new device\'s key, with ath over the ticket, is required', 401);
  try { await verifyProof(proof, { method: request.method, url: request.url, credential: body.ticket, jkt: data.jkt }); }
  catch (error) { if (error instanceof VerificationError) assert(false, error.code, error.message, 401); throw error; }
  if (data.via === 'email') {
    // Looked up again rather than carried in the ticket, so the ticket never tells its holder
    // which account an address belongs to.
    const { account } = await rpc(env.REGISTRY, 'global', 'email-get', { hash: data.h });
    const state = account ? await rpc(env.ACCOUNTS, account, 'email-recovery-status', { id: data.id, jkt: data.jkt }) : { status: 'pending', stage: 'waiting_for_link' };
    assert(state.status !== 'denied', 'recovery_denied', 'This recovery was cancelled from a signed-in device', 403);
    if (state.status === 'pending') return { status: 'pending', stage: state.stage, ...(state.ready_at ? { ready_at: state.ready_at } : {}), interval: EMAIL_POLL_INTERVAL };
    const issued = await recoveredCredential(env, account, data, `recover-${data.id}`);
    return { status: 'recovered', account, credential: issued.credential, cid: issued.cid, device_id: issued.device_id };
  }
  const state = await rpc(env.ACCOUNTS, data.account, 'recover-gate-status', { id: data.id, jkt: data.jkt });
  assert(state.status !== 'denied', 'recovery_denied', 'A gate refused this recovery, or nobody answered in time', 403);
  if (state.status === 'pending') return { status: 'pending', account: data.account, interval: Math.max(POLL_INTERVAL, state.retry_after) };
  const issued = await recoveredCredential(env, data.account, data, `recover-${data.id}`);
  return { status: 'recovered', account: data.account, credential: issued.credential, cid: issued.cid, device_id: issued.device_id };
}

/**
 * POST /api/v1/recover/email-link { token } (from the emailed link, on /email-link.html): starts
 * the wait; the owner's browsers and email are told, and any dashboard sign-in can cancel.
 */
export async function confirmEmailRecovery(request, env) {
  const body = await readJson(request, 4096);
  const data = await verifyToken(body.token || '', 'erl_', env.TOKEN_SIGNING_KEY);
  assert(data, 'invalid_link', 'This recovery link is not valid any more', 410);
  return rpc(env.ACCOUNTS, data.a, 'email-recovery-confirm', { id: data.i });
}

/**
 * GET /api/v1/account/recovery: how the owner could get back in after losing every device, and
 * email recoveries waiting. POST { acknowledge_no_recovery: true }: they accept losing the account
 * instead (the dashboard keeps warning until one or the other); POST { cancel_email_recovery: id }:
 * stop an email recovery (any dashboard sign-in, no recent sign-in needed: it only protects).
 */
export async function accountRecovery(request, env, auth) {
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'recovery-status');
  const body = await readJson(request, 1024);
  if (body.cancel_email_recovery !== undefined) {
    assert(typeof body.cancel_email_recovery === 'string' && body.cancel_email_recovery.length <= 64, 'invalid_request', 'cancel_email_recovery is the id of a waiting email recovery');
    return rpc(env.ACCOUNTS, auth.account, 'email-recovery-cancel', { id: body.cancel_email_recovery });
  }
  assert(body.acknowledge_no_recovery === true, 'invalid_request', 'Send { "acknowledge_no_recovery": true } to accept that losing every device loses this account, or { "cancel_email_recovery": id }');
  return rpc(env.ACCOUNTS, auth.account, 'acknowledge-no-recovery', {});
}
