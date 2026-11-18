import { assert } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { randomId, derivedId } from '../utils/ids.js';
import { price } from '../utils/pricing.js';
import { validateGrants, actionNamespace, grantsNarrow } from '../../packages/verify/src/grants.js';
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
export async function validateIssue(env, { aud, grants, lifetime_seconds }) {
  assert(Array.isArray(aud) && aud.length >= 1 && aud.length <= 8 && aud.every(a => typeof a === 'string'), 'invalid_audience', 'aud must list 1–8 audience names');
  const audiences = await rpc(env.REGISTRY, 'global', 'get-many', { names: [...new Set(aud)] });
  const problems = validateGrants(grants);
  assert(!problems.length, 'invalid_grants', problems.join('; '));
  const namespaces = new Map(Object.values(audiences).map(a => [a.namespace, a]));
  for (const [i, grant] of grants.entries()) for (const action of grant.actions) {
    const audience = namespaces.get(actionNamespace(action));
    assert(audience, 'invalid_grants', `grants[${i}]: "${action}" is not in the namespace of any listed audience (${[...namespaces.keys()].join(', ')})`);
    const known = action.endsWith(':*') || audience.catalog.some(c => c.action === action);
    assert(known, 'invalid_grants', `grants[${i}]: "${action}" is not in ${audience.name}'s action catalog`);
  }
  const lifetime = lifetime_seconds ?? LIFETIME.default;
  assert(Number.isSafeInteger(lifetime) && lifetime >= LIFETIME.min && lifetime <= LIFETIME.max, 'invalid_lifetime', `lifetime_seconds must be ${LIFETIME.min}–${LIFETIME.max}`);
  return { aud: [...new Set(aud)], grants, lifetime, audiences };
}

async function allocate(env) {
  const shards = SHARDS(env); const first = Math.floor(Math.random() * shards);
  for (let i = 0; i < shards; i++) {
    const shard = (first + i) % shards;
    try { return { ...(await rpc(env.STATUS, `shard-${shard}`, 'allocate', { shard })), uri: statusUri(env, shard) }; }
    catch (error) { if (error.code !== 'shard_full') throw error; }
  }
  assert(false, 'capacity', 'All status list shards are full; raise STATUS_SHARDS', 503);
}

/** Refuse early (before allocating or signing) when the balance cannot cover the price. */
export async function requireFunds(env, account, amount) {
  const state = await rpc(env.ACCOUNTS, account, 'account');
  assert(state.balance_microdollars >= amount, 'insufficient_balance', 'Insufficient balance', 402, { needed_microdollars: amount - state.balance_microdollars, price_microdollars: amount });
}

/**
 * Issue a credential: validate, check funds, allocate a status index, sign, then charge and store
 * atomically in the account. Returns { credential, cid, payload, charged }.
 */
export async function issueCredential(env, account, request, { source, chargeId, parentGrants, maxExp, parentCid, enrollmentToken, attestation, reinstate = false, now = Date.now() }) {
  const jwk = cleanJwk(request.public_jwk);
  // `attestation` comes only from a verified key attestation (services/attestation.js), never
  // from a request body: cleanDevice drops anything else the caller put in device.
  const device = withAttestation(cleanDevice(request.device), attestation, Math.floor(now / 1000));
  const { aud, grants, lifetime } = await validateIssue(env, request);
  if (parentGrants) assert(grantsNarrow(grants, parentGrants), 'not_narrower', 'A device can only issue credentials whose grants are narrower than its own (same constraints, covered actions and resources)', 403);
  const amount = price('issue');
  await requireFunds(env, account, amount);
  const status = await allocate(env);
  const jkt = await jwkThumbprint(jwk);
  const cid = randomId('crd'); const deviceId = await derivedId('dev', account, jkt);
  const iat = Math.floor(now / 1000);
  const exp = Math.min(iat + lifetime, maxExp ?? Infinity);
  assert(exp > iat + 60, 'parent_expiring', 'The delegating credential expires too soon to issue from', 409);
  const payload = { iss: issuerName(env), sub: deviceId, acct: account, aud, cid, jti: `${cid}.1`, iat, nbf: iat, exp, cnf: { jkt }, device, grants, status: { status_list: { idx: status.idx, uri: status.uri } }, ver: 1 };
  const credential = await signCredential(payload, await activeSigner(env));
  const record = { cid, jti: payload.jti, version: 1, device_id: deviceId, jkt, aud, grants, lifetime, device, iat, exp, status, jws: credential, source, ...(maxExp ? { max_exp: maxExp } : {}), ...(parentCid ? { parent_cid: parentCid } : {}) };
  // With a caller's charge id (Idempotency-Key, an enrollment's id) a retry gets the first
  // credential back; the fingerprint tells a retry from a different request reusing the key.
  const fingerprint = chargeId ? await sha256b64u(JSON.stringify({ jkt, aud, grants, lifetime, device: cleanDevice(request.device), parentCid: parentCid ?? null })) : undefined;
  const stored = await rpc(env.ACCOUNTS, account, 'store-credential', { record, device: { id: deviceId, jkt, public_jwk: jwk, ...device }, price: amount, charge_id: chargeId || `issue-${cid}`, fingerprint, reinstate, source, ...(enrollmentToken ? { enrollment_token: enrollmentToken } : {}), now });
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
  const grants = payload.grants.map(g => ({ ...g, actions: g.actions.filter(a => actionNamespace(a) === registered.namespace) })).filter(g => g.actions.length);
  assert(grants.length, 'no_grants', `The credential has no grants for ${audience}`);
  const paid = await rpc(env.ACCOUNTS, payload.acct, 'charge', { kind: 'token', amount: price('token'), aggregate: true, now });
  const iat = Math.floor(now / 1000);
  const exp = Math.min(iat + ACCESS_TOKEN_SECONDS, payload.exp);
  const token = { iss: payload.iss, sub: payload.sub, acct: payload.acct, aud: [audience], cid: payload.cid, jti: randomId('tok'), iat, nbf: iat, exp, device: payload.device, grants, status: payload.status, ver: payload.ver };
  return { access_token: await signAccessToken(token, await activeSigner(env)), token_type: 'Bearer', expires_in: exp - iat, audience, cost_microdollars: paid.charged, balance_microdollars: paid.balance_microdollars };
}

export { CREDENTIAL_TYP };
