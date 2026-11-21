import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { jwkThumbprint } from '../../packages/verify/src/jose.js';
import { verifyProof, VerificationError } from '../../packages/verify/src/credential.js';
import { signToken, verifyToken } from '../auth/tokens.js';
import { cleanDevice, issueCredential } from '../services/credentials.js';
import { appAudience } from '../services/issuer.js';
import { readEnrollRequest } from './enrollments.js';
import { DASHBOARD_GRANTS } from './signup.js';

// Getting back in after losing every device (todo/clerk_free_accounts.md §3.5, STATUS B9). Works
// the same for Clerk accounts and accounts made by paying; nobody needs to be signed in.

const TICKET_PREFIX = 'rcv_';
const POLL_INTERVAL = 3;

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
 * Either way the credential is free (an empty balance must not lock the owner out) and counts as
 * a recent sign-in for ten minutes, so the owner can revoke the lost devices and make new codes.
 */
export async function recoverAccount(request, env) {
  const body = await readJson(request, 32768);
  assert(typeof body.account === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(body.account), 'invalid_account', 'account is the account id shown on your recovery sheet and Account page');
  const via = body.via ?? 'code';
  assert(via === 'code' || via === 'gate', 'invalid_recovery', 'via must be "code" or "gate"');
  if (via === 'code') assert(typeof body.code === 'string' && body.code.length > 0 && body.code.length <= 40, 'invalid_recovery_code', 'code is one of your recovery codes');
  const { jwk, payload, lifetime, attestation } = await readEnrollRequest(body.request, { env, defaults: { aud: [appAudience(env)], grants: DASHBOARD_GRANTS } });
  const device = cleanDevice(payload.device);
  const jkt = await jwkThumbprint(jwk);
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
  const state = await rpc(env.ACCOUNTS, data.account, 'recover-gate-status', { id: data.id, jkt: data.jkt });
  assert(state.status !== 'denied', 'recovery_denied', 'A gate refused this recovery, or nobody answered in time', 403);
  if (state.status === 'pending') return { status: 'pending', account: data.account, interval: Math.max(POLL_INTERVAL, state.retry_after) };
  const issued = await recoveredCredential(env, data.account, data, `recover-${data.id}`);
  return { status: 'recovered', account: data.account, credential: issued.credential, cid: issued.cid, device_id: issued.device_id };
}

/**
 * GET /api/v1/account/recovery: how the owner could get back in after losing every device.
 * POST with { acknowledge_no_recovery: true }: they accept losing the account instead (the
 * dashboard keeps warning until one or the other).
 */
export async function accountRecovery(request, env, auth) {
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'recovery-status');
  const body = await readJson(request, 1024);
  assert(body.acknowledge_no_recovery === true, 'invalid_request', 'Send { "acknowledge_no_recovery": true } to accept that losing every device loses this account');
  return rpc(env.ACCOUNTS, auth.account, 'acknowledge-no-recovery', {});
}
