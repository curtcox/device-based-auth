import { verifyToken as verifyClerkToken } from '@clerk/backend';
import { assert } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { digest, verifyToken } from './tokens.js';
import { verifyCredential, verifyProof, VerificationError, ACCESS_TYP } from '../../packages/verify/src/credential.js';
import { networkLocation } from '../../packages/verify/src/verifier.js';
import { jwks, issuerName, appAudience } from '../services/issuer.js';

export const API_KEY_PREFIX = 'dbak_';

/**
 * Authenticate: LocalDev (local only), Clerk session JWTs, API keys (dbak_…), and
 * devicebasedauth.org's own device credentials ("Authorization: DBA" + DPoP) — DBA is its own
 * first relying party. Returns { account, session, scopes?, key_id?, device? }.
 */
export async function authenticate(request, env, { anyAudience = false } = {}) {
  const header = request.headers.get('Authorization') || '';
  if (header.startsWith('LocalDev ')) {
    const account = header.slice(9).trim();
    assert(env.ENVIRONMENT === 'local', 'invalid_auth', 'Local authentication is disabled', 401);
    assert(/^[a-zA-Z0-9_-]{1,128}$/.test(account), 'invalid_auth', 'Invalid local user', 401);
    await rpc(env.ACCOUNTS, account, 'init', { account });
    return { account, session: true, kind: 'local' };
  }
  if (header.startsWith('DBA ')) return authenticateDevice(request, env, header.slice(4).trim(), { anyAudience });
  if (header.startsWith('Bearer ')) {
    const token = header.slice(7).trim();
    assert(env.CLERK_SECRET_KEY, 'invalid_auth', 'Session sign-in is not configured', 401);
    let claims;
    try { claims = await verifyClerkToken(token, { secretKey: env.CLERK_SECRET_KEY, authorizedParties: [env.APP_ORIGIN] }); } catch { claims = null; }
    assert(claims?.sub && claims.sid, 'invalid_auth', 'Invalid session', 401);
    await rpc(env.ACCOUNTS, claims.sub, 'init', { account: claims.sub });
    return { account: claims.sub, session: true, kind: 'clerk' };
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

async function authenticateDevice(request, env, credential, { anyAudience }) {
  let payload;
  try {
    ({ payload } = await verifyCredential(credential, { jwks: jwks(env), issuer: issuerName(env), typ: 'device' }));
    const proof = request.headers.get('DPoP');
    assert(proof, 'proof_required', 'A DPoP proof is required with a DBA credential', 401);
    const verifiedProof = await verifyProof(proof, { method: request.method, url: request.url, credential, jkt: payload.cnf.jkt });
    const status = await rpc(env.ACCOUNTS, payload.acct, 'credential-status', { cid: payload.cid });
    // The account's own record is authoritative and instant; a rotated credential has a new index.
    assert(status.exists && !status.revoked && status.status?.idx === payload.status.status_list.idx, 'revoked', 'Credential has been revoked', 401);
    const dba = payload.aud.includes(appAudience(env));
    assert(dba || anyAudience, 'wrong_audience', `Credential is not valid for ${appAudience(env)}`, 401);
    return { account: payload.acct, session: false, kind: 'device', device: { payload, credential, proof: verifiedProof, dba, location: { network: networkLocation(request), device: verifiedProof.loc } } };
  } catch (error) {
    if (error instanceof VerificationError) assert(false, error.code, error.message, 401);
    throw error;
  }
}

/** Does this bearer token look like a DBA access token (rather than a Clerk session)? */
export function isAccessToken(token) {
  try { return JSON.parse(atob(token.split('.')[0].replaceAll('-', '+').replaceAll('_', '/'))).typ === ACCESS_TYP; } catch { return false; }
}
