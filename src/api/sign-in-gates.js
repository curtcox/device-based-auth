import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { requireRecentSignIn } from '../auth/reverify.js';
import { validateGrant, grantGates } from '../../packages/verify/src/grants.js';
import { AUDIENCE_NAME } from '../durable-objects/registry-do.js';

/**
 * Gate entries for sign-in (done/additional_gates.md §3.3): the same shape as require.gates.
 * The owner gate cannot gate a sign-in: the owner is the one signing in.
 */
export function cleanSignInEntries(entries, path) {
  if (entries === null) return null;
  const problems = validateGrant({ actions: ['x:y'], require: { gates: entries } }, path).map(p => p.replace(`${path}.require.gates`, path));
  assert(!problems.length, 'invalid_gates', problems.join('; '));
  assert(!entries.some(e => e.any.includes('owner')), 'invalid_gates', `${path}: the owner gate cannot gate a sign-in (the owner is who signs in); use a device, an authenticator app, a security key or a webhook`);
  return grantGates({ require: { gates: entries } });
}

/**
 * GET/PUT /api/v1/settings/sign-in-gates: { default, audiences: { <client>: entries }, dashboard }.
 * Changing them needs a recent sign-in and is announced (plan §3.3, §8).
 */
export async function signInGates(route, request, env, auth) {
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'get-sign-in-gates');
  // A person's own setting: never an API key or an app (they could switch sign-in gates off
  // without anyone signing in), nor a device; and a recent sign-in.
  assert(auth.session === true, 'session_required', 'Sign-in gates are changed from the dashboard by the signed-in owner, not with an API key or a device', 403);
  requireRecentSignIn(auth, 'change your sign-in gates');
  const body = await readJson(request, 16384);
  for (const key of Object.keys(body)) assert(['default', 'audiences', 'dashboard'].includes(key), 'invalid_gates', `${key} is not a sign-in gate setting (default, audiences, dashboard)`);
  const settings = {};
  if (body.default !== undefined) settings.default = cleanSignInEntries(body.default, 'default');
  if (body.dashboard !== undefined) settings.dashboard = cleanSignInEntries(body.dashboard, 'dashboard');
  if (body.audiences !== undefined) {
    assert(body.audiences && typeof body.audiences === 'object' && !Array.isArray(body.audiences) && Object.keys(body.audiences).length <= 50, 'invalid_gates', 'audiences maps up to 50 site names to gate entries');
    settings.audiences = {};
    for (const [name, entries] of Object.entries(body.audiences)) {
      assert(AUDIENCE_NAME.test(name), 'invalid_gates', `audiences: ${name.slice(0, 80)} is not a site name`);
      settings.audiences[name] = cleanSignInEntries(entries, `audiences["${name}"]`);
    }
  }
  const result = await rpc(env.ACCOUNTS, auth.account, 'put-sign-in-gates', { settings, account: auth.account });
  // Loosening waits for the current gates (202, send the same change again after retry_after);
  // a refusal is 403. Anything else is the saved settings.
  if (result.status === 'pending') return Response.json({ ...result, error: 'This change loosens your sign-in gates, so their current gates must approve it first; send it again once they have', code: 'gate_pending' }, { status: 202 });
  assert(result.status !== 'denied', result.code, 'Your current sign-in gates refused this change', 403);
  return result;
}

/**
 * The dashboard's own sign-in gate (done/additional_gates.md §5.2). GET /api/v1/session says
 * whether this session is confirmed; POST …/confirm opens (or reads) its gate request, and may
 * carry this page's own answer ({ entry, gate, totp | webauthn }); POST …/recover uses a
 * recovery code. A recent sign-in does not bypass the gate.
 */
export async function dashboardSession(route, request, env, auth) {
  assert(auth.session_key, 'insufficient_scope', 'Only a dashboard sign-in has a session to confirm', 403);
  const path = new URL(request.url).pathname;
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'dashboard-status', { session: auth.session_key });
  const body = await readJson(request, 32768);
  if (path.endsWith('/recover')) {
    assert(typeof body.code === 'string' && body.code.length <= 40, 'invalid_recovery_code', 'code is required');
    return rpc(env.ACCOUNTS, auth.account, 'dashboard-recover', { session: auth.session_key, code: body.code });
  }
  return rpc(env.ACCOUNTS, auth.account, 'dashboard-confirm', { account: auth.account, session: auth.session_key, device_id: auth.device?.payload.sub ?? null, device_name: auth.device?.payload.device?.name ?? null, answer: factorAnswer(body) });
}

/** A page's own factor answer ({ entry?, gate, totp | webauthn }) from a request body, or null. */
function factorAnswer(body) {
  if (body.gate === undefined) return null;
  assert(typeof body.gate === 'string' && (body.entry === undefined || (Number.isSafeInteger(body.entry) && body.entry >= 0 && body.entry < 3)), 'invalid_answer', 'gate (and optionally entry) name the gate this page answers for');
  const proof = {};
  if (body.totp) proof.totp = { code: String(body.totp.code ?? '').slice(0, 12) };
  if (body.webauthn) proof.webauthn = Object.fromEntries(['credential_id', 'clientDataJSON', 'authenticatorData', 'signature'].map(k => [k, String(body.webauthn[k] ?? '').slice(0, 8192)]));
  return { entry: body.entry, gate: body.gate, proof };
}

/**
 * POST /api/v1/session/reverify: a dashboard device confirms it is the owner through one of the
 * owner's gates (todo/clerk_free_accounts.md §3.4), which then counts as a recent sign-in for
 * REVERIFY_MINUTES. Send it again (with this device's own TOTP or security-key answer, or after
 * another device approved, typing the number shown) until it answers `reverified`. Browser
 * sessions sign in again with their sign-in provider instead.
 */
export async function sessionReverify(request, env, auth) {
  assert(auth.kind === 'device' && auth.device?.dba, 'device_only', 'Only a dashboard device re-verifies through gates; a browser session signs in again', 400);
  const body = await readJson(request, 32768);
  const { payload } = auth.device;
  return rpc(env.ACCOUNTS, auth.account, 'session-reverify', { account: auth.account, cid: payload.cid, device_id: payload.sub, device_name: payload.device?.name ?? null, answer: factorAnswer(body) });
}

/** POST /api/v1/settings/recovery-codes: 10 new one-time codes, shown once (recent sign-in). */
export async function recoveryCodes(request, env, auth) {
  requireRecentSignIn(auth, 'make recovery codes');
  // The account id goes on the recovery sheet: recovering onto a new device needs both.
  return { account: auth.account, ...await rpc(env.ACCOUNTS, auth.account, 'recovery-codes', {}) };
}
