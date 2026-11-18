import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { describeGrant } from '../../packages/verify/src/grants.js';
import { issueCredential, renewCredential, exchangeToken } from '../services/credentials.js';
import { canAccess, SESSION } from '../auth/scopes.js';
import { requireRecentSignIn, hasDbaAction, reinstatingIssue } from '../auth/reverify.js';

/** Issue by API (fleets, CI, agents provisioned by a trusted device). */
export async function createCredential(request, env, auth) {
  const body = await readJson(request, 65536);
  // A device signed in to the dashboard (dba:session) acts as its owner; any other device
  // delegates, so it can only issue grants narrower than its own and never past its own expiry.
  const parent = auth.device && !canAccess({ ...auth, session: false }, SESSION) ? auth.device.payload : null;
  // A delegating device is bounded by its own grants; anyone acting as the owner must have signed in recently.
  if (!parent && hasDbaAction(body.grants)) requireRecentSignIn(auth, 'issue a credential with permissions on devicebasedauth.org itself (dba:*)');
  const key = request.headers.get('Idempotency-Key');
  assert(key === null || /^[\x21-\x7e]{1,128}$/.test(key), 'invalid_idempotency_key', 'Idempotency-Key must be 1–128 printable ASCII characters');
  const issued = await reinstatingIssue(auth, reinstate => issueCredential(env, auth.account, body, {
    source: parent ? 'delegation' : auth.key_id ? 'api' : 'dashboard',
    chargeId: key ? `issue-${auth.account}-${key}` : undefined,
    // A device may only delegate grants narrower than its own, and never past its own expiry.
    parentGrants: parent?.grants, maxExp: parent?.exp, parentCid: parent?.cid, reinstate
  }), { person: !parent });
  return { credential: issued.credential, cid: issued.cid, device_id: issued.device_id, payload: issued.payload, cost_microdollars: issued.charged, balance_microdollars: issued.balance_microdollars, ...(issued.replay ? { idempotent_replay: true } : {}) };
}

export async function listCredentials(request, env, auth) {
  const q = new URL(request.url).searchParams;
  return rpc(env.ACCOUNTS, auth.account, 'list-credentials', { status: q.get('status') || undefined, audience: q.get('audience') || undefined, device_id: q.get('device') || undefined, cursor: q.get('cursor') || undefined });
}

export async function getCredential(route, env, auth) {
  const cred = await rpc(env.ACCOUNTS, auth.account, 'get-credential', { cid: route.params.cid });
  const state = cred.revoked_at ? 'revoked' : cred.exp * 1000 <= Date.now() ? 'expired' : 'active';
  return { ...cred, state, descriptions: cred.grants.map(describeGrant) };
}

export async function credentialDecisions(route, env, auth) {
  await rpc(env.ACCOUNTS, auth.account, 'get-credential', { cid: route.params.cid });
  return rpc(env.ACCOUNTS, auth.account, 'decisions', { cid: route.params.cid });
}

export async function revoke(route, request, env, auth) {
  const body = request.method === 'POST' ? await readJson(request) : {};
  const reason = typeof body.reason === 'string' ? body.reason.slice(0, 200) : undefined;
  if (route.handler === 'revoke-credential') return rpc(env.ACCOUNTS, auth.account, 'revoke', { cid: route.params.cid, reason });
  if (route.handler === 'revoke-device') return rpc(env.ACCOUNTS, auth.account, 'revoke', { device_id: route.params.id, reason });
  assert(body.confirm === 'revoke-all', 'confirm_required', 'Send {"confirm":"revoke-all"} to revoke every credential');
  return rpc(env.ACCOUNTS, auth.account, 'revoke', { all: true, audience: body.audience, reason: reason || 'revoke all' });
}

/** A device revokes its own credential (lost trust in itself, uninstall, logout). */
export async function revokeSelf(env, auth) {
  return rpc(env.ACCOUNTS, auth.account, 'revoke', { cid: auth.device.payload.cid, reason: 'revoked by the device' });
}

export async function renew(route, request, env, auth) {
  assert(route.params.cid === auth.device.payload.cid, 'forbidden', 'A device can only renew the credential it presents', 403);
  const body = await readJson(request, 16384);
  const result = await renewCredential(env, auth.device, body);
  return { ...result, cost_microdollars: result.charged };
}

export async function token(request, env, auth) {
  return exchangeToken(env, auth.device, await readJson(request));
}

export async function whoami(env, auth) {
  if (!auth.device) return { account: auth.account, kind: auth.kind, scopes: auth.scopes ?? null };
  const p = auth.device.payload;
  return { account: auth.account, kind: 'device', device_id: p.sub, cid: p.cid, jti: p.jti, aud: p.aud, exp: p.exp, grants: p.grants, descriptions: p.grants.map(describeGrant) };
}
