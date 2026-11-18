import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { randomId } from '../utils/ids.js';
import { price } from '../utils/pricing.js';
import { signToken, verifyToken } from '../auth/tokens.js';
import { decodeJws, verifyJws, jwkThumbprint } from '../../packages/verify/src/jose.js';
import { describeGrant, validateGrants } from '../../packages/verify/src/grants.js';
import { cleanDevice, cleanJwk, issueCredential, withAttestation, LIFETIME } from '../services/credentials.js';
import { verifyAttestation, createChallenge, checkChallenge, tpmEkAnchorsFor } from '../services/attestation.js';
import { startTpmActivation, tpmActivationResponse, ACTIVATION_PREFIX } from '../services/tpm-activation.js';
import { requireRecentSignIn, hasDbaAction } from '../auth/reverify.js';

export const ENROLL_TYP = 'dba-enroll+jwt';
const ENROLLMENT_SECONDS = 900;
const POLL_INTERVAL = 3;

/**
 * Check a device's enrollment request: a JWS (typ dba-enroll+jwt) signed by the new key, whose
 * public JWK is in the header. Returns { jwk, payload, lifetime, returnOrigin, lifetimeRequested }.
 */
export async function readEnrollRequest(jws, { defaults, env } = {}) {
  let decoded;
  try { decoded = decodeJws(jws); } catch { assert(false, 'invalid_request', 'request must be a compact JWS signed by the device key'); }
  const { header } = decoded;
  // With an enrollment token the template supplies aud and grants the request leaves out.
  const payload = { ...decoded.payload, aud: decoded.payload.aud ?? defaults?.aud, grants: decoded.payload.grants ?? defaults?.grants };
  assert(header.typ === ENROLL_TYP && header.alg === 'ES256', 'invalid_request', `request must have typ ${ENROLL_TYP} and alg ES256`);
  const jwk = cleanJwk(header.jwk);
  assert(await verifyJws(jws, jwk), 'invalid_request', 'request signature does not verify with its jwk');
  const now = Math.floor(Date.now() / 1000);
  assert(Number.isSafeInteger(payload.iat) && Math.abs(payload.iat - now) <= 600, 'invalid_request', 'request iat must be within 10 minutes');
  assert(Array.isArray(payload.aud) && payload.aud.length >= 1 && payload.aud.length <= 8 && payload.aud.every(a => typeof a === 'string' && a.length <= 253), 'invalid_audience', 'aud must list 1–8 audiences');
  const problems = validateGrants(payload.grants);
  assert(!problems.length, 'invalid_grants', problems.join('; '));
  const lifetime = payload.lifetime_seconds ?? LIFETIME.default;
  assert(Number.isSafeInteger(lifetime) && lifetime >= LIFETIME.min && lifetime <= LIFETIME.max, 'invalid_lifetime', 'lifetime_seconds out of range');
  let returnOrigin = null;
  if (payload.return_origin !== undefined) {
    try { const u = new URL(payload.return_origin); assert(u.origin === payload.return_origin && (u.protocol === 'https:' || u.hostname === 'localhost'), 'x', 'x'); returnOrigin = u.origin; }
    catch { assert(false, 'invalid_return_origin', 'return_origin must be an https origin'); }
  }
  // Key attestation (optional): verified here so the result can travel in the signed ticket.
  const attestation = payload.attestation === undefined ? null : await verifyAttestation(payload.attestation, jwk, env);
  return { jwk, payload, lifetime, returnOrigin, attestation, lifetimeRequested: payload.lifetime_seconds !== undefined };
}

/**
 * Start an enrollment. The device sends a JWS (typ dba-enroll+jwt) signed with its new key, the
 * public key in the header, asking for audiences and grants. Nothing is stored: the request
 * travels in a signed token inside the approval URL, so anonymous starts cost no storage.
 */
export async function startEnrollment(request, env) {
  const body = await readJson(request, 32768);
  const { jwk, payload, lifetime, returnOrigin, attestation } = await readEnrollRequest(body.request, { env });
  const now = Math.floor(Date.now() / 1000);
  const id = randomId('enr');
  const exp = now + ENROLLMENT_SECONDS;
  const ticket = await signToken('enr_', { id, jwk, jkt: await jwkThumbprint(jwk), aud: payload.aud, grants: payload.grants, device: cleanDevice(payload.device), attestation, lifetime, return_origin: returnOrigin, exp }, env.TOKEN_SIGNING_KEY);
  const poll = await signToken('enp_', { id, exp: exp + 3600 }, env.TOKEN_SIGNING_KEY);
  return { enrollment_id: id, approval_url: `${env.APP_ORIGIN}/approve.html#${ticket}`, request: ticket, poll_url: `${env.APP_ORIGIN}/api/v1/enrollments/${id}?poll_token=${encodeURIComponent(poll)}`, poll_token: poll, interval: POLL_INTERVAL, expires_in: ENROLLMENT_SECONDS };
}

async function readTicket(env, ticket) {
  const data = await verifyToken(ticket, 'enr_', env.TOKEN_SIGNING_KEY);
  assert(data, 'invalid_enrollment', 'Enrollment request is invalid or expired', 400);
  return data;
}

/**
 * A challenge for Android Key Attestation: the device passes its ASCII bytes to
 * setAttestationChallenge, then sends { format: 'android-key', challenge, x5c } as the
 * enrollment request's `attestation`. Stateless, so anonymous calls cost no storage.
 */
export function attestationChallenge(env) { return createChallenge(env.TOKEN_SIGNING_KEY); }

/**
 * Step 1 of TPM attestation by EK credential activation (services/tpm-activation.js), for TPMs
 * without a Microsoft-certified attestation key: checks the EK certificate, the attestation key and
 * its certify of the device key, and answers with a secret wrapped for that TPM plus a signed
 * activation token. The device unwraps the secret with TPM2_ActivateCredential and enrolls with
 * { format: 'tpm-ek', challenge, activation, secret }. Stateless, like the challenge.
 */
export async function tpmActivation(request, env) {
  const body = await readJson(request, 32768);
  await checkChallenge(body.challenge, env.TOKEN_SIGNING_KEY);
  const result = await startTpmActivation({ ekCertificate: body.ek_certificate, ekChain: body.ek_chain ?? [], akPubArea: body.ak_pub_area, pubArea: body.pub_area, certInfo: body.cert_info, sig: body.sig, anchors: tpmEkAnchorsFor(env) });
  return tpmActivationResponse(result, { challenge: body.challenge, sign: payload => signToken(ACTIVATION_PREFIX, payload, env.TOKEN_SIGNING_KEY) });
}

/** Describe a pending enrollment for the approval page (no storage). */
export async function describeEnrollment(request, env) {
  const body = await readJson(request, 32768);
  const data = await readTicket(env, body.request);
  const audiences = await rpc(env.REGISTRY, 'global', 'get-many', { names: data.aud }).catch(error => ({ error }));
  const known = audiences.error ? null : Object.values(audiences).map(a => ({ name: a.name, description: a.description, first_party: !!a.first_party, actions: a.catalog }));
  const decision = await rpc(env.ENROLLMENTS, data.id, 'get');
  return {
    enrollment_id: data.id, device: withAttestation(data.device, data.attestation, Math.floor(Date.now() / 1000)), jkt: data.jkt, aud: data.aud, audiences: known, unknown_audiences: audiences.error ? audiences.error.message : null,
    grants: data.grants, descriptions: data.grants.map(describeGrant), lifetime_seconds: data.lifetime, return_origin: data.return_origin, expires_at: data.exp,
    status: decision.status, price_microdollars: price('issue')
  };
}

/** The account owner approves (optionally narrowing). Session only: a person must approve. */
export async function approveEnrollment(request, env, auth) {
  const body = await readJson(request, 65536);
  const data = await readTicket(env, body.request);
  const prior = await rpc(env.ENROLLMENTS, data.id, 'get');
  assert(prior.status === 'pending', 'already_decided', `This enrollment was already ${prior.status}`, 409);
  if (hasDbaAction(body.grants ?? data.grants)) requireRecentSignIn(auth, 'approve a device with permissions on devicebasedauth.org itself (dba:*)');
  const issued = await issueCredential(env, auth.account, {
    public_jwk: data.jwk, device: { ...data.device, ...(body.device_name ? { name: body.device_name } : {}) },
    aud: body.aud ?? data.aud, grants: body.grants ?? data.grants, lifetime_seconds: body.lifetime_seconds ?? data.lifetime
  }, { source: 'enrollment', chargeId: `enroll-${data.id}`, attestation: data.attestation });
  await rpc(env.ENROLLMENTS, data.id, 'put', { result: { status: 'approved', credential: issued.credential, cid: issued.cid, device_id: issued.device_id, account: auth.account } });
  return { status: 'approved', credential: issued.credential, cid: issued.cid, device_id: issued.device_id, return_origin: data.return_origin, enrollment_id: data.id, cost_microdollars: issued.charged, balance_microdollars: issued.balance_microdollars };
}

export async function denyEnrollment(request, env) {
  const body = await readJson(request, 65536);
  const data = await readTicket(env, body.request);
  await rpc(env.ENROLLMENTS, data.id, 'put', { result: { status: 'denied' } });
  return { status: 'denied', enrollment_id: data.id, return_origin: data.return_origin };
}

/** Device polls with its poll token until the owner approves or denies. */
export async function pollEnrollment(route, request, env) {
  const token = new URL(request.url).searchParams.get('poll_token');
  const data = await verifyToken(token || '', 'enp_', env.TOKEN_SIGNING_KEY);
  assert(data && data.id === route.params.id, 'invalid_poll_token', 'Invalid or expired poll token', 401);
  const result = await rpc(env.ENROLLMENTS, data.id, 'get');
  if (result.status === 'pending' && data.exp - 3600 < Math.floor(Date.now() / 1000)) return { status: 'expired', interval: POLL_INTERVAL };
  const { account: _account, ...visible } = result;
  return { ...visible, interval: POLL_INTERVAL };
}

export { randomId };
