import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { describeGrant } from '../../packages/verify/src/grants.js';
import { issueCredential, renewCredential, exchangeToken } from '../services/credentials.js';

/** Issue by API (fleets, CI, agents provisioned by a trusted device). */
export async function createCredential(request, env, auth) {
  const body = await readJson(request, 65536);
  const parent = auth.device?.payload;
  const issued = await issueCredential(env, auth.account, body, {
    source: parent ? 'delegation' : auth.key_id ? 'api' : 'dashboard',
    chargeId: request.headers.get('Idempotency-Key') ? `issue-${auth.account}-${request.headers.get('Idempotency-Key')}` : undefined,
    // A device may only delegate grants narrower than its own, and never past its own expiry.
    parentGrants: parent?.grants, maxExp: parent?.exp
  });
  return { credential: issued.credential, cid: issued.cid, device_id: issued.device_id, payload: issued.payload, cost_microdollars: issued.charged };
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
