import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { randomId } from '../utils/ids.js';
import { signToken, verifyToken, digest } from '../auth/tokens.js';
import { canAccess, SESSION } from '../auth/scopes.js';
import { grantsNarrow } from '../../packages/verify/src/grants.js';
import { cleanDevice, issueCredential, validateIssue } from '../services/credentials.js';
import { readEnrollRequest } from './enrollments.js';
import { requireRecentSignIn, hasDbaAction } from '../auth/reverify.js';

export const ENROLLMENT_TOKEN_PREFIX = 'dbae_';
const MAX_USES = 10000;
const MAX_DAYS = 90;

/**
 * Enrollment tokens (STATUS B2): the owner pre-approves a template once (audiences, grants,
 * lifetime, how many devices, until when) and hands the token to a fleet. Each device still makes
 * its own key and signs its own request; the token replaces only the per-device approval click.
 * The secret is shown once; the account stores only its digest.
 */
export async function enrollmentTokens(route, request, env, auth) {
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'list-enrollment-tokens');
  if (request.method === 'DELETE') return rpc(env.ACCOUNTS, auth.account, 'revoke-enrollment-token', { id: route.params.id });
  // A delegating device could otherwise mint a token wider than its own grants.
  assert(!auth.device || canAccess({ ...auth, session: false }, SESSION), 'forbidden', 'Only the account owner or an API key can create enrollment tokens', 403);
  const body = await readJson(request, 65536);
  const { aud, grants, lifetime } = await validateIssue(env, body);
  if (hasDbaAction(grants)) requireRecentSignIn(auth, 'create an enrollment token with permissions on devicebasedauth.org itself (dba:*)');
  const maxUses = body.max_uses ?? 1;
  assert(Number.isSafeInteger(maxUses) && maxUses >= 1 && maxUses <= MAX_USES, 'invalid_max_uses', `max_uses must be 1–${MAX_USES}`);
  const days = body.expires_in_days ?? 7;
  assert(Number.isFinite(days) && days > 0 && days <= MAX_DAYS, 'invalid_expiry', `expires_in_days must be more than 0 and at most ${MAX_DAYS}`);
  const name = String(body.name ?? 'Enrollment token').replace(/[\p{Cc}\p{Cf}]/gu, '').trim().slice(0, 64) || 'Enrollment token';
  const id = randomId('etk', 12);
  const expiresAt = Date.now() + Math.round(days * 86400000);
  // Rounded up so the signed token never lapses before the stored token: the account's
  // "expired" state, not a generic invalid-token error, is what the device sees.
  const secret = await signToken(ENROLLMENT_TOKEN_PREFIX, { account: auth.account, id, exp: Math.ceil(expiresAt / 1000) }, env.TOKEN_SIGNING_KEY);
  const token = await rpc(env.ACCOUNTS, auth.account, 'create-enrollment-token', { id, name, hash: await digest(secret), template: { aud, grants, lifetime }, max_uses: maxUses, expires_at: expiresAt });
  return { ...token, token: secret };
}

/**
 * A device redeems a token: POST { request, enrollment_token }. The request is the same
 * dba-enroll+jwt as an ordinary enrollment. Its aud and grants may narrow the template's (never
 * widen them); left out, the template's apply. Charges the issue price to the token's
 * account, like an approval would.
 */
export async function redeemEnrollmentToken(request, env) {
  const body = await readJson(request, 32768);
  const data = await verifyToken(body.enrollment_token, ENROLLMENT_TOKEN_PREFIX, env.TOKEN_SIGNING_KEY);
  assert(data?.account && data.id, 'invalid_enrollment_token', 'Enrollment token is invalid or expired', 401);
  const hash = await digest(body.enrollment_token);
  const { template } = await rpc(env.ACCOUNTS, data.account, 'check-enrollment-token', { id: data.id, hash });
  const { jwk, payload, lifetime, lifetimeRequested, attestation } = await readEnrollRequest(body.request, { defaults: template, env });
  assert(payload.aud.every(a => template.aud.includes(a)), 'not_narrower', `aud must be within the token's audiences (${template.aud.join(', ')})`, 403);
  assert(grantsNarrow(payload.grants, template.grants), 'not_narrower', "grants must be the token's grants or narrower", 403);
  const issued = await issueCredential(env, data.account, {
    public_jwk: jwk, device: cleanDevice(payload.device), aud: payload.aud, grants: payload.grants,
    lifetime_seconds: lifetimeRequested ? Math.min(lifetime, template.lifetime) : template.lifetime
  }, { source: 'enrollment-token', enrollmentToken: { id: data.id, hash }, attestation });
  return { status: 'approved', credential: issued.credential, cid: issued.cid, device_id: issued.device_id, cost_microdollars: issued.charged };
}
