import { assert, readJson, readText, ApiError } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { randomId } from '../utils/ids.js';
import { price } from '../utils/pricing.js';
import { signToken, verifyToken } from '../auth/tokens.js';
import { sha256b64u, signJws, decodeJws, verifyJws } from '../../packages/verify/src/jose.js';
import { activeSigner, issuerName, jwks } from '../services/issuer.js';

const CODE_SECONDS = 60;
const TOKEN_SECONDS = 600;
const SCOPES = ['openid', 'profile', 'device'];

/** OpenID Connect discovery. Clients are registered audiences; client_id is the audience name. */
export function oidcConfiguration(env) {
  return new Response(JSON.stringify({
    issuer: issuerName(env), authorization_endpoint: `${env.APP_ORIGIN}/oauth/authorize`, token_endpoint: `${env.APP_ORIGIN}/oauth/token`,
    userinfo_endpoint: `${env.APP_ORIGIN}/oauth/userinfo`, jwks_uri: `${env.APP_ORIGIN}/.well-known/jwks.json`,
    response_types_supported: ['code'], response_modes_supported: ['query'], grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['ES256'], code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'], scopes_supported: SCOPES,
    claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'amr', 'acct', 'dev', 'cid', 'device_name']
  }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600', 'Access-Control-Allow-Origin': '*' } });
}

/** Local development lets first-party sites (hashbin, cronly) run their callbacks on localhost. */
function localRedirect(env, audience, redirectUri) {
  if (env.ENVIRONMENT !== 'local' || !audience.first_party) return false;
  try { const u = new URL(redirectUri); return u.protocol === 'http:' && u.hostname === 'localhost' && !u.hash; } catch { return false; }
}

async function client(env, clientId, redirectUri) {
  const audience = await rpc(env.REGISTRY, 'global', 'get', { name: String(clientId || '') }).catch(() => null);
  assert(audience, 'invalid_client', 'Unknown client_id (register the site as an audience first)', 400);
  assert(audience.redirect_uris?.includes(redirectUri) || localRedirect(env, audience, redirectUri), 'invalid_redirect_uri', 'redirect_uri is not registered for this client', 400);
  return audience;
}

/**
 * The signed-in user approves a sign-in for a client (the consent page posts here).
 * Returns the URL to send the browser to.
 */
export async function oidcAuthorize(request, env, auth) {
  const body = await readJson(request);
  const audience = await client(env, body.client_id, body.redirect_uri);
  const redirect = new URL(body.redirect_uri);
  if (body.state !== undefined) redirect.searchParams.set('state', String(body.state));
  if (!body.approve) { redirect.searchParams.set('error', 'access_denied'); return { redirect: redirect.toString() }; }
  assert(body.response_type === 'code', 'unsupported_response_type', 'response_type must be code');
  assert(body.code_challenge_method === 'S256' && /^[A-Za-z0-9_-]{43}$/.test(body.code_challenge || ''), 'invalid_request', 'PKCE with S256 is required');
  const scopes = String(body.scope || 'openid').split(' ').filter(Boolean);
  assert(scopes.includes('openid') && scopes.every(s => SCOPES.includes(s)), 'invalid_scope', `scope must include openid and only ${SCOPES.join(', ')}`);
  const id = randomId('code', 12);
  const now = Date.now();
  const device = auth.device ? { dev: auth.device.payload.sub, cid: auth.device.payload.cid, device_name: auth.device.payload.device?.name } : {};
  await rpc(env.ACCOUNTS, auth.account, 'put-code', { id, code: { client_id: audience.name, redirect_uri: body.redirect_uri, code_challenge: body.code_challenge, nonce: body.nonce ? String(body.nonce).slice(0, 256) : undefined, scope: scopes.join(' '), auth_time: Math.floor(now / 1000), amr: auth.device ? ['dba_device'] : ['session'], ...device, expires_at: now + CODE_SECONDS * 1000 } });
  const code = await signToken('dbac_', { account: auth.account, id, exp: Math.floor(now / 1000) + CODE_SECONDS }, env.TOKEN_SIGNING_KEY);
  redirect.searchParams.set('code', code);
  redirect.searchParams.set('iss', issuerName(env));
  return { redirect: redirect.toString() };
}

function oauthError(error, description, status = 400) {
  return new Response(JSON.stringify({ error, error_description: description }), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' } });
}

/** Exchange a code (with PKCE) for an ID token and an access token. Billed to the client's owner. */
export async function oidcToken(request, env) {
  const type = request.headers.get('Content-Type') || '';
  const params = type.includes('application/json') ? await readJson(request) : Object.fromEntries(new URLSearchParams(await readText(request, 16384)));
  if (params.grant_type !== 'authorization_code') return oauthError('unsupported_grant_type', 'Only authorization_code is supported');
  const codeData = await verifyToken(params.code || '', 'dbac_', env.TOKEN_SIGNING_KEY);
  if (!codeData) return oauthError('invalid_grant', 'Code is invalid or expired');
  let code;
  try { code = await rpc(env.ACCOUNTS, codeData.account, 'take-code', { id: codeData.id }); } catch { return oauthError('invalid_grant', 'Code is invalid, used or expired'); }
  if (code.client_id !== params.client_id || code.redirect_uri !== params.redirect_uri) return oauthError('invalid_grant', 'client_id or redirect_uri does not match');
  if (typeof params.code_verifier !== 'string' || await sha256b64u(params.code_verifier) !== code.code_challenge) return oauthError('invalid_grant', 'PKCE verification failed');
  const audience = await rpc(env.REGISTRY, 'global', 'get', { name: code.client_id });
  try { await rpc(env.ACCOUNTS, audience.owner, 'charge', { kind: 'login', amount: price('login'), aggregate: true, detail: { audience: code.client_id } }); }
  catch (error) { if (error instanceof ApiError && error.status === 402) return oauthError('temporarily_unavailable', 'The site\'s devicebasedauth.org balance is empty', 503); throw error; }
  const signer = await activeSigner(env); const now = Math.floor(Date.now() / 1000);
  const identity = { acct: codeData.account, ...(code.dev ? { dev: code.dev, cid: code.cid, device_name: code.device_name } : {}) };
  const idToken = await signJws({ typ: 'JWT', kid: signer.kid }, { iss: issuerName(env), sub: codeData.account, aud: code.client_id, iat: now, exp: now + TOKEN_SECONDS, auth_time: code.auth_time, amr: code.amr, ...(code.nonce ? { nonce: code.nonce } : {}), ...identity }, signer.key);
  const accessToken = await signJws({ typ: 'at+jwt', kid: signer.kid }, { iss: issuerName(env), sub: codeData.account, aud: code.client_id, client_id: code.client_id, scope: code.scope, iat: now, exp: now + TOKEN_SECONDS, jti: randomId('at'), ...identity }, signer.key);
  return new Response(JSON.stringify({ access_token: accessToken, token_type: 'Bearer', expires_in: TOKEN_SECONDS, id_token: idToken, scope: code.scope }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' } });
}

export async function oidcUserinfo(request, env) {
  const header = request.headers.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  let decoded = null;
  try { const { header: h } = decodeJws(token); const key = jwks(env).keys.find(k => k.kid === h.kid); if (h.typ === 'at+jwt' && key) decoded = await verifyJws(token, key); } catch { decoded = null; }
  if (!decoded || decoded.payload.iss !== issuerName(env) || decoded.payload.exp < Math.floor(Date.now() / 1000)) return oauthError('invalid_token', 'Access token is invalid or expired', 401);
  const { sub, acct, dev, cid, device_name } = decoded.payload;
  return new Response(JSON.stringify({ sub, acct, ...(dev ? { dev, cid, device_name } : {}) }), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
}
