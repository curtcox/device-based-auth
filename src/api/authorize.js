import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { price } from '../utils/pricing.js';
import { verifyCredential, verifyProof, VerificationError } from '../../packages/verify/src/credential.js';
import { evaluateGrants, actionNamespace } from '../../packages/verify/src/grants.js';
import { jwks, issuerName } from '../services/issuer.js';

// Per environment (a Worker has one; tests make many), so a cached record never crosses registries.
const audienceCaches = new WeakMap();
async function audience(env, name) {
  let audienceCache = audienceCaches.get(env);
  if (!audienceCache) { audienceCache = new Map(); audienceCaches.set(env, audienceCache); }
  const cached = audienceCache.get(name);
  if (cached && cached.expires > Date.now()) return cached.value;
  const value = await rpc(env.REGISTRY, 'global', 'get', { name });
  audienceCache.set(name, { value, expires: Date.now() + 60000 });
  return value;
}

/**
 * The only location kept in the decision log: an ISO country code, from the network the caller
 * observed or else the one the device reported (master plan §10). Coordinates, regions and IPs
 * are evaluated and then forgotten.
 * @param {{ network?: object, device?: object }} location
 * @returns {string|null}
 */
export function coarseCountry(location) {
  for (const source of [location.network, location.device]) {
    const country = source?.country;
    if (typeof country === 'string' && /^[A-Za-z]{2}$/.test(country)) return country.toUpperCase();
  }
  return null;
}

/**
 * Online authorization (metered, billed to the audience's owner). Adds what offline verification
 * cannot do: instant revocation, usage counters, step-up approval and a decision log.
 * Every decision is billed, including denials.
 */
export async function authorize(request, env, auth) {
  const body = await readJson(request, 65536);
  assert(typeof body.audience === 'string', 'invalid_request', 'audience is required');
  assert(typeof body.action === 'string' && body.action.length <= 300, 'invalid_request', 'action is required');
  assert(body.resource === undefined || (typeof body.resource === 'string' && body.resource.length <= 1024), 'invalid_request', 'resource must be a string');
  const registered = await audience(env, body.audience);
  assert(registered.owner === auth.account, 'forbidden', 'You can only ask for decisions for audiences you own', 403);
  assert(actionNamespace(body.action) === registered.namespace, 'invalid_request', `Actions for ${body.audience} start with "${registered.namespace}:"`);
  const charged = await rpc(env.ACCOUNTS, auth.account, 'charge', { kind: 'decision', amount: price('decision'), aggregate: true, detail: { audience: body.audience } });
  const deny = (code, message) => ({ allow: false, code, message, reasons: [], cost_microdollars: charged.charged, balance_microdollars: charged.balance_microdollars });
  const now = Math.floor(Date.now() / 1000);
  let payload; let proof = null;
  try {
    ({ payload } = await verifyCredential(body.credential, { jwks: jwks(env), issuer: issuerName(env), audience: body.audience, typ: 'any', now }));
    // An audience that turned access tokens off refuses the ones issued before it did.
    if (!payload.cnf && registered.accept_access_tokens === false) return deny('access_tokens_refused', `${body.audience} does not accept access tokens`);
    if (payload.cnf) {
      assert(typeof body.proof === 'string' && body.request?.method && body.request?.url, 'proof_required', 'A device credential needs proof, request.method and request.url');
      proof = await verifyProof(body.proof, { method: body.request.method, url: body.request.url, credential: body.credential, jkt: payload.cnf.jkt, now });
    }
  } catch (error) {
    if (error instanceof VerificationError || error.code === 'proof_required') return deny(error.code, error.message);
    throw error;
  }
  const location = { network: body.context?.network, device: proof?.loc };
  // The audience's gate policy: fail_open is applied by the evaluator (to entries, through the
  // candidates); whether the grant's gates are of accepted kinds is checked in the account, which
  // knows its gates (spec/evaluation.md §3.8).
  const policy = registered.catalog?.find(c => c.action === body.action)?.gates ?? null;
  // A credential with confirm is checked against the account's record of its last confirmation
  // (in the account, below); the evaluator gets a stand-in so it checks everything else.
  const confirmation = payload.confirm ? { iat: now, exp: now + 120, by_timeout: false } : undefined;
  const evaluation = evaluateGrants(payload.grants, { now, action: body.action, resource: body.resource, location, online: true, attestation: payload.device?.attestation, confirmation, policy: policy?.fail_open === false ? { gates: { fail_open: false } } : undefined });
  // Gates (step-up is the owner gate) are decided by the account's gate engine.
  const candidates = evaluation.results.map((r, index) => ({ index, ok: r.ok, uses: r.online.uses, step_up: r.online.step_up, gates: r.online.gates, gates_reuse_s: r.online.gates_reuse_s, fail_open: policy?.fail_open === false ? false : r.online.fail_open, confirmation: payload.grants[index]?.require?.confirmation === true })).filter(c => c.ok).map(({ ok: _ok, ...c }) => c);
  const decision = await rpc(env.ACCOUNTS, payload.acct, 'authorize', { account: payload.acct, cid: payload.cid, jti: payload.jti, status_list: payload.status.status_list, proof_jti: proof ? `${proof.jkt}:${proof.jti}` : null, proof_exp: now + 180, candidates, action: body.action, resource: body.resource, audience: body.audience, caller: auth.account, country: coarseCountry(location), token_namespace: payload.cnf ? null : registered.namespace, gate_policy: policy?.require ? { require: true, kinds: policy.kinds ?? null } : null });
  const grant = decision.allow ? payload.grants[decision.grant_index] : null;
  return {
    allow: decision.allow, code: decision.code, grant_index: decision.grant_index ?? null, reasons: decision.allow ? [] : (decision.reasons.length ? decision.reasons : evaluation.reasons.flat()),
    per_grant_reasons: evaluation.reasons, caveats: grant?.limits?.spend_usd_per_month !== undefined ? { spend_usd_per_month: grant.limits.spend_usd_per_month } : {},
    step_up: decision.step_up ? { ...decision.step_up, approve_url: `${env.APP_ORIGIN}/app.html#approvals` } : undefined,
    gate_request: decision.gate_request, gates: decision.gates, by_timeout: decision.by_timeout || undefined,
    device_id: payload.sub, account: payload.acct, cid: payload.cid,
    // Callers may cache an allow briefly unless counters or gates were involved.
    expires_in: decision.allow && !grant?.limits?.uses && !grant?.require?.step_up && !grant?.require?.gates ? 30 : 0,
    cost_microdollars: charged.charged, balance_microdollars: charged.balance_microdollars
  };
}
