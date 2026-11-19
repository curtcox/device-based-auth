import { verifyToken as verifyClerkToken } from '@clerk/backend';
import { assert } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { digest, verifyToken } from './tokens.js';
import { verifyCredential, verifyProof, VerificationError, ACCESS_TYP, PROOF_MAX_AGE, CLOCK_SKEW } from '../../packages/verify/src/credential.js';
import { networkLocation } from '../../packages/verify/src/verifier.js';
import { jwks, withdrawnJwks, issuerName, appAudience } from '../services/issuer.js';
import { factorAgeMinutes } from './reverify.js';
import { isMcpAccessToken, authenticateMcpToken } from '../api/mcp-oauth.js';
import { sameStatusEntry } from '../durable-objects/account-do.js';

export const API_KEY_PREFIX = 'dbak_';

// Per-caller request limits per minute. The check runs inside the account's authentication call,
// so it costs no Durable Object request of its own.
const SESSION_RATE = 300; const RATE = 120;

/**
 * Authenticate: LocalDev (local only), Clerk session JWTs, API keys (dbak_…), and
 * devicebasedauth.org's own device credentials ("Authorization: DBA" + DPoP) — DBA is its own
 * first relying party. Returns { account, session, scopes?, key_id?, device? }.
 */
export async function authenticate(request, env, { anyAudience = false, recovery = false } = {}) {
  const header = request.headers.get('Authorization') || '';
  if (header.startsWith('LocalDev ')) {
    // "LocalDev <account>" or "LocalDev <account> <session>": local sessions may name themselves,
    // so the dashboard gate can tell one browser from another in development.
    const [account, sessionName = 'default', extra] = header.slice(9).trim().split(/\s+/);
    assert(env.ENVIRONMENT === 'local', 'invalid_auth', 'Local authentication is disabled', 401);
    assert(/^[a-zA-Z0-9_-]{1,128}$/.test(account) && /^[a-zA-Z0-9_-]{1,64}$/.test(sessionName) && extra === undefined, 'invalid_auth', 'Invalid local user', 401);
    const session_key = `local:${sessionName}`;
    const init = await rpc(env.ACCOUNTS, account, 'init', { account, rate: { id: 'session', limit: SESSION_RATE }, session: session_key });
    return { account, session: true, kind: 'local', rated: true, session_key, dashboard: init.dashboard };
  }
  if (header.startsWith('DBA ')) return authenticateDevice(request, env, header.slice(4).trim(), { anyAudience, recovery });
  if (header.startsWith('Bearer ')) {
    const token = header.slice(7).trim();
    // An app connected through the MCP OAuth flow: acts like an API key with the approved scopes.
    if (isMcpAccessToken(token)) return authenticateMcpToken(token, env);
    assert(env.CLERK_SECRET_KEY, 'invalid_auth', 'Session sign-in is not configured', 401);
    let claims;
    // env.CLERK_VERIFY_TOKEN replaces Clerk's verifier in tests only.
    const verify = env.CLERK_VERIFY_TOKEN || verifyClerkToken;
    try { claims = await verify(token, { secretKey: env.CLERK_SECRET_KEY, authorizedParties: [env.APP_ORIGIN] }); } catch { claims = null; }
    assert(claims?.sub && claims.sid, 'invalid_auth', 'Invalid session', 401);
    const session_key = `sid:${claims.sid}`;
    const init = await rpc(env.ACCOUNTS, claims.sub, 'init', { account: claims.sub, rate: { id: 'session', limit: SESSION_RATE }, session: session_key });
    return { account: claims.sub, session: true, kind: 'clerk', factor_age_minutes: factorAgeMinutes(claims), rated: true, session_key, dashboard: init.dashboard };
  }
  if (header.startsWith('ApiKey ')) {
    const token = header.slice(7).trim();
    const payload = await verifyToken(token, API_KEY_PREFIX, env.TOKEN_SIGNING_KEY, 2048);
    assert(payload && typeof payload.account === 'string' && typeof payload.id === 'string', 'invalid_auth', 'Invalid API key', 401);
    const key = await rpc(env.ACCOUNTS, payload.account, 'authenticate-key', { id: payload.id, hash: await digest(token), rate: { id: payload.id, limit: RATE } });
    return { account: payload.account, key_id: payload.id, scopes: key.scopes, session: false, kind: 'key', rated: true };
  }
  assert(false, 'auth_required', 'Authentication required', 401);
}

/**
 * A credential signed by a withdrawn issuer key, checked against that key. Only the renew route
 * accepts it (`recovery`), and renewCredential then requires the account's registry to hold this
 * exact credential, so a credential forged with the leaked key is refused. Elsewhere the device
 * is told to renew (code reissue_required) instead of getting a bare unknown_kid.
 */
async function verifyWithdrawn(credential, env, recovery) {
  const withdrawn = withdrawnJwks(env);
  if (!withdrawn.keys.length) return null;
  try {
    const result = await verifyCredential(credential, { jwks: withdrawn, issuer: issuerName(env), typ: 'device' });
    assert(recovery, 'reissue_required', `This credential was signed by a withdrawn issuer key; renew it at POST /api/v1/credentials/${result.payload.cid}/renew`, 401, { cid: result.payload.cid });
    return result;
  } catch (error) {
    if (error instanceof VerificationError && error.code === 'unknown_kid') return null;
    throw error;
  }
}

async function authenticateDevice(request, env, credential, { anyAudience, recovery }) {
  let payload; let recovered = false;
  try {
    try {
      ({ payload } = await verifyCredential(credential, { jwks: jwks(env), issuer: issuerName(env), typ: 'device' }));
    } catch (error) {
      if (!(error instanceof VerificationError && error.code === 'unknown_kid')) throw error;
      const result = await verifyWithdrawn(credential, env, recovery);
      if (!result) throw error;
      ({ payload } = result); recovered = true;
    }
    const proof = request.headers.get('DPoP');
    assert(proof, 'proof_required', 'A DPoP proof is required with a DBA credential', 401);
    const verifiedProof = await verifyProof(proof, { method: request.method, url: request.url, credential, jkt: payload.cnf.jkt });
    const now = Math.floor(Date.now() / 1000);
    const dba = payload.aud.includes(appAudience(env));
    const status = await rpc(env.ACCOUNTS, payload.acct, 'credential-status', { cid: payload.cid, rate: { id: payload.cid, limit: RATE }, proof_key: `${verifiedProof.jkt}:${verifiedProof.jti}`, proof_exp: now + PROOF_MAX_AGE + 2 * CLOCK_SKEW, ...(dba ? { session: `cid:${payload.cid}` } : {}) });
    assert(!status.replayed, 'replayed_proof', 'DPoP proof was already used; make a new proof for each request', 401);
    // The account's own record is authoritative and instant; a rotated credential has a new entry.
    assert(status.exists && !status.revoked && sameStatusEntry(status.status, payload.status.status_list), 'revoked', 'Credential has been revoked', 401);
    assert(dba || anyAudience, 'wrong_audience', `Credential is not valid for ${appAudience(env)}`, 401);
    return { account: payload.acct, session: false, kind: 'device', rated: true, ...(dba ? { session_key: `cid:${payload.cid}`, dashboard: status.dashboard } : {}), device: { payload, credential, proof: verifiedProof, dba, confirmation: { required: !!status.confirm, until: status.confirmed_until ?? 0 }, ...(recovered ? { recovery: true } : {}), ...(status.parent_cid ? { delegated_by: status.parent_cid } : {}), location: { network: networkLocation(request), device: verifiedProof.loc } } };
  } catch (error) {
    if (error instanceof VerificationError) assert(false, error.code, error.message, 401);
    throw error;
  }
}

/** Does this bearer token look like a DBA access token (rather than a Clerk session)? */
export function isAccessToken(token) {
  try { return JSON.parse(atob(token.split('.')[0].replaceAll('-', '+').replaceAll('_', '/'))).typ === ACCESS_TYP; } catch { return false; }
}
