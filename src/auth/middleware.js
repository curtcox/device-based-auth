import { verifyToken as verifyClerkToken } from '@clerk/backend';
import { assert } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { digest, verifyToken } from './tokens.js';
import { verifyCredential, verifyProof, VerificationError, ACCESS_TYP } from '../../packages/verify/src/credential.js';
import { networkLocation } from '../../packages/verify/src/verifier.js';
import { jwks, withdrawnJwks, issuerName, appAudience } from '../services/issuer.js';
import { factorAgeMinutes } from './reverify.js';
import { isMcpAccessToken, authenticateMcpToken } from '../api/mcp-oauth.js';
import { sameStatusEntry } from '../durable-objects/account-do.js';

export const API_KEY_PREFIX = 'dbak_';

/**
 * Authenticate: LocalDev (local only), Clerk session JWTs, API keys (dbak_…), and
 * devicebasedauth.org's own device credentials ("Authorization: DBA" + DPoP) — DBA is its own
 * first relying party. Returns { account, session, scopes?, key_id?, device? }.
 */
export async function authenticate(request, env, { anyAudience = false, recovery = false } = {}) {
  const header = request.headers.get('Authorization') || '';
  if (header.startsWith('LocalDev ')) {
    const account = header.slice(9).trim();
    assert(env.ENVIRONMENT === 'local', 'invalid_auth', 'Local authentication is disabled', 401);
    assert(/^[a-zA-Z0-9_-]{1,128}$/.test(account), 'invalid_auth', 'Invalid local user', 401);
    await rpc(env.ACCOUNTS, account, 'init', { account });
    return { account, session: true, kind: 'local' };
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
    await rpc(env.ACCOUNTS, claims.sub, 'init', { account: claims.sub });
    return { account: claims.sub, session: true, kind: 'clerk', factor_age_minutes: factorAgeMinutes(claims) };
  }
  if (header.startsWith('ApiKey ')) {
    const token = header.slice(7).trim();
    const payload = await verifyToken(token, API_KEY_PREFIX, env.TOKEN_SIGNING_KEY, 2048);
    assert(payload && typeof payload.account === 'string' && typeof payload.id === 'string', 'invalid_auth', 'Invalid API key', 401);
    const key = await rpc(env.ACCOUNTS, payload.account, 'authenticate-key', { id: payload.id, hash: await digest(token) });
    return { account: payload.account, key_id: payload.id, scopes: key.scopes, session: false, kind: 'key' };
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
    const status = await rpc(env.ACCOUNTS, payload.acct, 'credential-status', { cid: payload.cid });
    // The account's own record is authoritative and instant; a rotated credential has a new entry.
    assert(status.exists && !status.revoked && sameStatusEntry(status.status, payload.status.status_list), 'revoked', 'Credential has been revoked', 401);
    const dba = payload.aud.includes(appAudience(env));
    assert(dba || anyAudience, 'wrong_audience', `Credential is not valid for ${appAudience(env)}`, 401);
    return { account: payload.acct, session: false, kind: 'device', device: { payload, credential, proof: verifiedProof, dba, ...(recovered ? { recovery: true } : {}), location: { network: networkLocation(request), device: verifiedProof.loc } } };
  } catch (error) {
    if (error instanceof VerificationError) assert(false, error.code, error.message, 401);
    throw error;
  }
}

/** Does this bearer token look like a DBA access token (rather than a Clerk session)? */
export function isAccessToken(token) {
  try { return JSON.parse(atob(token.split('.')[0].replaceAll('-', '+').replaceAll('_', '/'))).typ === ACCESS_TYP; } catch { return false; }
}
