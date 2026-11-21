import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { jwkThumbprint } from '../../packages/verify/src/jose.js';
import { cleanDevice, issueCredential } from '../services/credentials.js';
import { appAudience } from '../services/issuer.js';
import { readEnrollRequest } from './enrollments.js';
import { DASHBOARD_GRANTS } from './signup.js';

// Getting back in after losing every device (todo/clerk_free_accounts.md §3.5, STATUS B9). Works
// the same for Clerk accounts and accounts made by paying; nobody needs to be signed in.

/**
 * POST /api/v1/recover: body { account, via: 'code', code, request }. `request` is a
 * dba-enroll+jwt signed by the new device's key within the last 10 minutes (as for
 * POST /api/v1/enrollments; aud and grants may be left out), which proves the key; a used code
 * cannot be replayed. Uses up the code and issues the new device a dashboard credential, free (an
 * empty balance must not lock the owner out). That credential counts as a recent sign-in for ten
 * minutes, so the owner can revoke the lost devices and make new codes.
 */
export async function recoverAccount(request, env) {
  const body = await readJson(request, 32768);
  assert(typeof body.account === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(body.account), 'invalid_account', 'account is the account id shown on your recovery sheet and Account page');
  assert(body.via === undefined || body.via === 'code', 'invalid_recovery', 'via must be "code"');
  assert(typeof body.code === 'string' && body.code.length > 0 && body.code.length <= 40, 'invalid_recovery_code', 'code is one of your recovery codes');
  const { jwk, payload, lifetime, attestation } = await readEnrollRequest(body.request, { env, defaults: { aud: [appAudience(env)], grants: DASHBOARD_GRANTS } });
  const device = cleanDevice(payload.device);
  const used = await rpc(env.ACCOUNTS, body.account, 'recover-with-code', { code: body.code, jkt: await jwkThumbprint(jwk), device_name: device.name ?? null });
  // A person who just proved they own the account may bring back a device revoked before.
  const issued = await issueCredential(env, body.account, { public_jwk: jwk, device, aud: [appAudience(env)], grants: DASHBOARD_GRANTS, lifetime_seconds: lifetime }, { source: 'recovery', chargeId: `recover-${used.id}`, attestation, reinstate: true, free: true });
  return { status: 'recovered', account: body.account, credential: issued.credential, cid: issued.cid, device_id: issued.device_id, recovery_codes_left: used.left };
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
