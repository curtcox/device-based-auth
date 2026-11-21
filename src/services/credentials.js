import { assert } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { randomId, derivedId } from '../utils/ids.js';
import { price } from '../utils/pricing.js';
import { validateGrants, actionNamespace, grantsNarrow, isNarrowing } from '../../packages/verify/src/grants.js';
import { jwkThumbprint, publicJwk, verifyJws, decodeJws, sha256b64u } from '../../packages/verify/src/jose.js';
import { signCredential, signAccessToken } from '../../packages/verify/src/issuer.js';
import { CREDENTIAL_TYP, inspectCredential } from '../../packages/verify/src/credential.js';
import { activeSigner, issuerName, statusUri } from './issuer.js';

export const DEVICE_KINDS = ['browser', 'phone', 'desktop', 'server', 'cli', 'agent', 'iot', 'other'];
export const KEY_PROTECTION = ['webcrypto-nonextractable', 'secure-enclave', 'android-keystore', 'tpm', 'os-keychain', 'software'];
export const LIFETIME = Object.freeze({ min: 300, max: 400 * 86400, default: 30 * 86400 });
export const ACCESS_TOKEN_SECONDS = 600;
const SHARDS = env => Math.max(1, Number(env.STATUS_SHARDS) || 16);

/** Clean device metadata for display. Names are plain text; control characters are removed. */
export function cleanDevice(device = {}) {
  const name = String(device.name ?? 'Unnamed device').replace(/[\p{Cc}\p{Cf}]/gu, '').trim().slice(0, 100) || 'Unnamed device';
  const kind = DEVICE_KINDS.includes(device.kind) ? device.kind : 'other';
  const key_protection = KEY_PROTECTION.includes(device.key_protection) ? device.key_protection : 'software';
  return { name, kind, key_protection };
}

const ATTESTED_KEY_PROTECTION = { 'android-key': 'android-keystore', 'apple-appattest': 'secure-enclave', tpm: 'tpm' };

/** The device claim with a verified attestation (which also settles key_protection). */
export function withAttestation(device, attestation, at) {
  if (!attestation) return device;
  return { ...device, key_protection: ATTESTED_KEY_PROTECTION[attestation.format] ?? device.key_protection, attestation: { ...attestation, verified_at: at } };
}

/** The device claim without attestation, for a credential moved to a key nobody attested. */
export function withoutAttestation(device) {
  if (!device?.attestation) return device;
  const { attestation: _attestation, ...rest } = device;
  return rest;
}

/** Validate a P-256 public key. */
export function cleanJwk(jwk) {
  try { return publicJwk(jwk); } catch { assert(false, 'invalid_key', 'public_jwk must be a P-256 public JWK'); }
}

/**
 * Validate audiences, grants and lifetime against the registry. Every action must belong to the
 * namespace of one of the credential's audiences, and must be in that audience's catalog
 * (or be a wildcard within the namespace).
 */
/**
 * A credential's confirm block (spec/credential.md §3, §9): it authenticates only while its device
 * holds a confirmation from these gates no older than every_s seconds.
 */
export function cleanConfirm(confirm) {
  if (confirm === undefined || confirm === null) return null;
  assert(confirm && typeof confirm === 'object' && !Array.isArray(confirm) && Object.keys(confirm).every(k => ['gates', 'every_s'].includes(k)), 'invalid_confirm', 'confirm must be { gates, every_s }');
  assert(Number.isSafeInteger(confirm.every_s) && confirm.every_s >= 300 && confirm.every_s <= 604800, 'invalid_confirm', 'confirm.every_s must be an integer from 300 to 604,800 seconds');
  const problems = validateGrants([{ actions: ['x:y'], require: { gates: confirm.gates } }]).map(p => p.replace('grants[0].require.gates', 'confirm.gates'));
  assert(!problems.length, 'invalid_confirm', problems.join('; '));
  return { gates: confirm.gates.map(e => ({ any: [...e.any], ...(e.timeout_s !== undefined ? { timeout_s: e.timeout_s } : {}), ...(e.on_timeout !== undefined ? { on_timeout: e.on_timeout } : {}) })), every_s: confirm.every_s };
}

export async function validateIssue(env, { aud, grants, lifetime_seconds, confirm: request_confirm }) {
  assert(Array.isArray(aud) && aud.length >= 1 && aud.length <= 8 && aud.every(a => typeof a === 'string'), 'invalid_audience', 'aud must list 1–8 audience names');
  const audiences = await rpc(env.REGISTRY, 'global', 'get-many', { names: [...new Set(aud)] });
  const problems = validateGrants(grants);
  assert(!problems.length, 'invalid_grants', problems.join('; '));
  // require.confirmation is set by issuance from the credential's confirm block, never by hand.
  for (const [i, grant] of grants.entries()) {
    assert(grant.require?.confirmation === undefined, 'invalid_grants', `grants[${i}]: require.confirmation is set from the credential's confirm block; send confirm: { gates, every_s } instead`);
  }
  // devicebasedauth.org checks dba:* grants itself, per request, with no counters or approvals.
  for (const [i, grant] of grants.entries()) {
    const dba = grant.actions.some(a => a === '*' || a.startsWith('dba:'));
    assert(!dba || (grant.limits?.uses === undefined && !grant.require?.step_up && !grant.require?.gates), 'invalid_grants', `grants[${i}]: dba:* actions cannot have limits.uses, require.step_up or require.gates; put them in a grant of their own without these`);
    assert(!dba || !request_confirm, 'invalid_confirm', `grants[${i}]: a credential with dba:* actions cannot need confirmation (devicebasedauth.org checks those per request); issue it separately`);
  }
  const namespaces = new Map(Object.values(audiences).map(a => [a.namespace, a]));
  for (const [i, grant] of grants.entries()) for (const action of grant.actions) {
    const audience = namespaces.get(actionNamespace(action));
    assert(audience, 'invalid_grants', `grants[${i}]: "${action}" is not in the namespace of any listed audience (${[...namespaces.keys()].join(', ')})`);
    const known = action.endsWith(':*') || audience.catalog.some(c => c.action === action);
    assert(known, 'invalid_grants', `grants[${i}]: "${action}" is not in ${audience.name}'s action catalog`);
  }
  // Audience gate policies (spec/evaluation.md §3.8): a grant naming an action whose catalog entry
  // requires gates must have them. The kinds of its gates are checked in the account, which holds
  // them (AccountDO store-credential). Wildcard grants are not refused here; /authorize answers
  // gate_required for the gated actions they cover.
  const gatePolicies = [];
  for (const [i, grant] of grants.entries()) for (const action of grant.actions) {
    const policy = namespaces.get(actionNamespace(action))?.catalog.find(c => c.action === action)?.gates;
    if (!policy?.require) continue;
    assert(grant.require?.gates || grant.require?.step_up, 'gate_required', `grants[${i}]: ${action} requires gates${policy.kinds ? ` of kind ${policy.kinds.join(' or ')}` : ''} (${actionNamespace(action)}'s policy); add require.gates`, 400, { grant_index: i, action, policy });
    gatePolicies.push({ grant_index: i, action, kinds: policy.kinds ?? null });
  }
  const lifetime = lifetime_seconds ?? LIFETIME.default;
  assert(Number.isSafeInteger(lifetime) && lifetime >= LIFETIME.min && lifetime <= LIFETIME.max, 'invalid_lifetime', `lifetime_seconds must be ${LIFETIME.min}–${LIFETIME.max}`);
  return { aud: [...new Set(aud)], grants, lifetime, audiences, gatePolicies, confirm: cleanConfirm(request_confirm) };
}

// Shards this isolate has seen full. A shard never empties (indexes are not reused), so once full
// it is skipped for good instead of costing every later issuance an extra DO request.
const fullShards = new Set();

async function allocate(env) {
  const shards = SHARDS(env); const first = Math.floor(Math.random() * shards);
  for (let i = 0; i < shards; i++) {
    const shard = (first + i) % shards;
    const name = `${env.STATUS_ORIGIN ?? ''}#${shard}`;
    if (fullShards.has(name)) continue;
    try { return { ...(await rpc(env.STATUS, `shard-${shard}`, 'allocate', { shard })), uri: statusUri(env, shard) }; }
    catch (error) { if (error.code !== 'shard_full') throw error; fullShards.add(name); }
  }
  assert(false, 'capacity', 'All status list shards are full; raise STATUS_SHARDS', 503);
}

/**
 * For each grant of a delegated credential, the index of the parent grant whose usage counter it
 * must share, or null for its own. A delegated grant has to copy its parent's `limits.uses`
 * (isNarrowing), and with a counter of its own every delegate would get the whole limit again.
 * A grant that also narrows a parent grant without a use limit keeps its own counter: the parent
 * could do as much itself. Returns undefined when no grant needs to share.
 * @param {object[]} grants the delegated credential's grants
 * @param {object[]} parentGrants the delegating credential's grants
 * @returns {(number|null)[]|undefined}
 */
export function sharedUsage(grants, parentGrants) {
  const from = grants.map(grant => {
    if (!grant.limits?.uses) return null;
    const covering = parentGrants.map((parent, i) => isNarrowing(grant, parent) ? i : -1).filter(i => i >= 0);
    if (covering.some(i => !parentGrants[i].limits?.uses)) return null;
    return covering.length ? covering[0] : null;
  });
  return from.some(i => i !== null) ? from : undefined;
}

/** Refuse early (before allocating or signing) when the balance cannot cover the price. */
export async function requireFunds(env, account, amount) {
  const state = await rpc(env.ACCOUNTS, account, 'account', { funds_check: true });
  assert(state.balance_microdollars >= amount, 'insufficient_balance', 'Insufficient balance', 402, { needed_microdollars: amount - state.balance_microdollars, price_microdollars: amount });
}

/**
 * Issue a credential: validate, check funds, allocate a status index, sign, then charge and store
 * atomically in the account. Returns { credential, cid, payload, charged }.
 */
export async function issueCredential(env, account, request, { source, chargeId, parentGrants, parentAud, maxExp, parentCid, enrollmentToken, attestation, reinstate = false, free = false, now = Date.now() }) {
  const jwk = cleanJwk(request.public_jwk);
  // `attestation` comes only from a verified key attestation (services/attestation.js), never
  // from a request body: cleanDevice drops anything else the caller put in device.
  const device = withAttestation(cleanDevice(request.device), attestation, Math.floor(now / 1000));
  const validated = await validateIssue(env, request);
  const { aud, lifetime, gatePolicies, confirm } = validated;
  // A confirm block makes every grant need a current confirmation, so verifiers that do not know
  // confirmations deny the credential instead of ignoring the block (spec/credential.md §3).
  const grants = confirm ? validated.grants.map(g => ({ ...g, require: { ...g.require, confirmation: true } })) : validated.grants;
  // Audiences bound a credential as much as grants do: a site may accept any credential naming it
  // to identify the account, so a delegate cannot name a site its delegator could not.
  if (parentAud) assert(aud.every(a => parentAud.includes(a)), 'not_narrower', `aud must be within the delegating credential's audiences (${parentAud.join(', ')})`, 403);
  if (parentGrants) assert(grantsNarrow(grants, parentGrants), 'not_narrower', 'A device can only issue credentials whose grants are narrower than its own (same constraints, covered actions and resources)', 403);
  // `free`: a recovery onto a new device (api/recovery.js), so an empty balance never locks anyone out.
  const amount = free ? 0 : price('issue');
  if (amount) await requireFunds(env, account, amount);
  const status = await allocate(env);
  const jkt = await jwkThumbprint(jwk);
  const cid = randomId('crd'); const deviceId = await derivedId('dev', account, jkt);
  const iat = Math.floor(now / 1000);
  const exp = Math.min(iat + lifetime, maxExp ?? Infinity);
  assert(exp > iat + 60, 'parent_expiring', 'The delegating credential expires too soon to issue from', 409);
  const payload = { iss: issuerName(env), sub: deviceId, acct: account, aud, cid, jti: `${cid}.1`, iat, nbf: iat, exp, cnf: { jkt }, device, grants, status: { status_list: { idx: status.idx, uri: status.uri } }, ver: 1, ...(confirm ? { confirm } : {}) };
  const credential = await signCredential(payload, await activeSigner(env));
  const usageFrom = parentGrants ? sharedUsage(grants, parentGrants) : undefined;
  const record = { cid, jti: payload.jti, version: 1, device_id: deviceId, jkt, aud, grants, lifetime, device, iat, exp, status, jws: credential, source, ...(confirm ? { confirm, confirmed_until: null } : {}), ...(maxExp ? { max_exp: maxExp } : {}), ...(parentCid ? { parent_cid: parentCid } : {}), ...(usageFrom ? { usage_from: usageFrom } : {}) };
  // With a caller's charge id (Idempotency-Key, an enrollment's id) a retry gets the first
  // credential back; the fingerprint tells a retry from a different request reusing the key.
  const fingerprint = chargeId ? await sha256b64u(JSON.stringify({ jkt, aud, grants, lifetime, device: cleanDevice(request.device), parentCid: parentCid ?? null })) : undefined;
  const stored = await rpc(env.ACCOUNTS, account, 'store-credential', { record, extra_gates: confirm ? confirm.gates.flatMap(e => e.any) : [], gate_policies: gatePolicies, device: { id: deviceId, jkt, public_jwk: jwk, ...device }, price: amount, charge_id: chargeId || `issue-${cid}`, fingerprint, reinstate, source, ...(enrollmentToken ? { enrollment_token: enrollmentToken } : {}), now });
  if (stored.duplicate) return { credential: stored.jws, cid: stored.cid, device_id: stored.device_id, payload: inspectCredential(stored.jws).payload, charged: 0, balance_microdollars: stored.balance_microdollars, replay: true };
  return { credential, cid, device_id: deviceId, payload, charged: stored.charged, balance_microdollars: stored.balance_microdollars };
}

/**
 * Renew the presenting device's credential, optionally rotating to a new key.
 * Rotation needs a JWS (typ dba-rotate+jwt) over { cid, iat } signed by the NEW key with its JWK
 * in the header, in addition to the DPoP proof from the old key that authenticated the request.
 */
export async function renewCredential(env, device, body, now = Date.now()) {
  const { payload } = device;
  const account = payload.acct;
  const record = await rpc(env.ACCOUNTS, account, 'credential-status', { cid: payload.cid, with_jws: !!device.recovery });
  assert(record.exists && !record.revoked, 'revoked', 'Credential has been revoked', 403);
  assert(record.jti === payload.jti, 'superseded', 'Present the current version of the credential to renew it', 409);
  // Recovery renewal (credential signed by a withdrawn issuer key): whoever leaked the key can sign
  // anything, so only the exact credential DBA issued and stored is renewed. Byte equality, not
  // claims: a forgery reusing a real cid and jti with wider grants is refused.
  if (device.recovery) assert(record.jws === device.credential, 'unknown_credential', 'This credential is not the one devicebasedauth.org issued; enroll the device again', 403);
  // A credential that needs confirmation renews (or rotates) only while it holds one (plan §3.4).
  assert(!record.confirm || record.confirmed_until > now, 'confirmation_required', `Confirm this credential first (POST /api/v1/credentials/${payload.cid}/confirm)`, 403);
  let rotation = null; let jkt = record.jkt; let status = record.status; let deviceId = record.device_id;
  if (body.new_key_proof) {
    let decoded;
    try { decoded = decodeJws(body.new_key_proof); } catch { assert(false, 'invalid_key_proof', 'new_key_proof is not a JWS'); }
    assert(decoded.header.typ === 'dba-rotate+jwt' && decoded.header.jwk, 'invalid_key_proof', 'new_key_proof must have typ dba-rotate+jwt and the new jwk');
    const newJwk = cleanJwk(decoded.header.jwk);
    assert(await verifyJws(body.new_key_proof, newJwk), 'invalid_key_proof', 'new_key_proof signature does not verify');
    assert(decoded.payload.cid === payload.cid && Math.abs(decoded.payload.iat - now / 1000) <= 120, 'invalid_key_proof', 'new_key_proof must name this credential and be fresh');
    jkt = await jwkThumbprint(newJwk);
    assert(jkt !== record.jkt, 'invalid_key_proof', 'The new key must differ from the current key');
    deviceId = await derivedId('dev', account, jkt);
    status = await allocate(env);
    // The attestation vouched for the old key only.
    rotation = { device: { ...withoutAttestation(record.device), id: deviceId, jkt, public_jwk: newJwk } };
  }
  const amount = price(rotation ? 'issue' : 'renew');
  // A recovery renewal without rotation is free (AccountDO.op_renew); do not refuse it for funds.
  if (!device.recovery || rotation) await requireFunds(env, account, amount);
  const iat = Math.floor(now / 1000);
  const version = Number(payload.jti.split('.').at(-1)) + 1;
  // Delegated credentials never outlive the credential that issued them.
  const exp = Math.min(iat + record.lifetime, record.max_exp ?? Infinity);
  assert(exp > iat + 60, 'parent_expiring', 'This credential cannot be renewed past the expiry of the credential that delegated it', 409);
  const next = { ...payload, ...(rotation && payload.device ? { device: withoutAttestation(payload.device) } : {}), sub: deviceId, jti: `${payload.cid}.${version}`, iat, nbf: iat, exp, cnf: { jkt }, status: { status_list: { idx: status.idx, uri: status.uri } } };
  const credential = await signCredential(next, await activeSigner(env));
  const update = { jti: next.jti, version, iat, exp: next.exp, jws: credential, ...(rotation ? { jkt, device_id: deviceId, status } : {}) };
  const result = await rpc(env.ACCOUNTS, account, 'renew', { cid: payload.cid, from_jti: payload.jti, update, price: amount, charge_id: `renew-${next.jti}`, rotation, ...(device.recovery ? { recovery: true } : {}), now });
  return { credential, cid: payload.cid, jti: next.jti, exp: next.exp, rotated: !!rotation, ...(device.recovery ? { recovered: true } : {}), charged: result.charged, balance_microdollars: result.balance_microdollars };
}

/**
 * Exchange a device credential (already authenticated with its proof) for a short-lived bearer
 * access token for one audience, carrying only the grants in that audience's namespace.
 */
export async function exchangeToken(env, device, { audience }, now = Date.now()) {
  const { payload } = device;
  assert(typeof audience === 'string' && payload.aud.includes(audience), 'invalid_audience', 'audience must be one of the credential\'s audiences');
  const registered = await rpc(env.REGISTRY, 'global', 'get', { name: audience });
  assert(registered.accept_access_tokens !== false, 'access_tokens_refused', `${audience} does not accept access tokens`, 403);
  // A token never outlives the confirmation its credential holds, so it carries no confirmation
  // requirement of its own (it has no device key to bind a confirmation to).
  const confirmedUntil = confirmationUntil(device, now);
  const grants = payload.grants.map(g => {
    const out = { ...g, actions: g.actions.filter(a => actionNamespace(a) === registered.namespace) };
    if (g.require?.confirmation) { const require = withoutConfirmation(g.require); if (require) out.require = require; else delete out.require; }
    return out;
  }).filter(g => g.actions.length);
  assert(grants.length, 'no_grants', `The credential has no grants for ${audience}`);
  const paid = await rpc(env.ACCOUNTS, payload.acct, 'charge', { kind: 'token', amount: price('token'), aggregate: true, now });
  const iat = Math.floor(now / 1000);
  const exp = Math.min(iat + ACCESS_TOKEN_SECONDS, payload.exp, Math.floor(confirmedUntil / 1000));
  const token = { iss: payload.iss, sub: payload.sub, acct: payload.acct, aud: [audience], cid: payload.cid, jti: randomId('tok'), iat, nbf: iat, exp, device: payload.device, grants, status: payload.status, ver: payload.ver };
  return { access_token: await signAccessToken(token, await activeSigner(env)), token_type: 'Bearer', expires_in: exp - iat, audience, cost_microdollars: paid.charged, balance_microdollars: paid.balance_microdollars };
}

/** require without its confirmation member (undefined when nothing is left). */
function withoutConfirmation(require) {
  const { confirmation: _c, ...rest } = require;
  return Object.keys(rest).length ? rest : undefined;
}

/**
 * Until when a presenting device's credential is confirmed (ms; Infinity when it needs no
 * confirmation). Throws 403 confirmation_required when it needs one and holds none.
 */
export function confirmationUntil(device, now = Date.now()) {
  if (!device.confirmation?.required) return Infinity;
  assert(device.confirmation.until > now + 60000, 'confirmation_required', `This credential needs a current confirmation (POST /api/v1/credentials/${device.payload.cid}/confirm)`, 403);
  return device.confirmation.until;
}

export { CREDENTIAL_TYP };
