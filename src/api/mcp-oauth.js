/**
 * OAuth for the MCP server (master plan §7.4: "remote, OAuth-protected"), following the MCP
 * authorization spec: protected-resource metadata (RFC 9728), dynamic client registration
 * (RFC 7591), authorization code + PKCE with a `resource` indicator (RFC 8707), and rotating
 * refresh tokens.
 *
 * Registration is stateless, like anonymous enrollment starts (§5.1): the client_id is an
 * HMAC-signed record of the client's name and redirect URIs, so a flood of registrations writes
 * nothing. Storage is written once, when the signed-in owner approves: the connection becomes an
 * API key record (kind "oauth") with the approved scopes, listed and revocable with the account's
 * other API keys. Access tokens are short ES256 JWTs naming that record; every use checks it, so
 * revoking the key cuts the app off at once.
 */
import { assert, ApiError } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { randomId } from '../utils/ids.js';
import { signToken, verifyToken, digest } from '../auth/tokens.js';
import { USER_SCOPES } from '../auth/scopes.js';
import { DBA_SCOPES } from '../services/first-party.js';
import { signJws, decodeJws, verifyJws } from '../../packages/verify/src/jose.js';
import { activeSigner, issuerName, jwks } from '../services/issuer.js';

export const MCP_CLIENT_PREFIX = 'dbamcp_';
export const REFRESH_PREFIX = 'dbar_';
export const MCP_ACCESS_SECONDS = 3600;
/** Read-only scopes, granted when a client asks for none. */
export const MCP_DEFAULT_SCOPES = Object.freeze(['account:read', 'credentials:read', 'transactions:read']);
const MAX_REDIRECTS = 5;

/** The protected resource: the MCP endpoint's own URL. */
export const mcpResource = env => `${env.APP_ORIGIN}/mcp`;
export const resourceMetadataUrl = env => `${env.APP_ORIGIN}/.well-known/oauth-protected-resource/mcp`;

/** RFC 9728 protected-resource metadata for /mcp. */
export function protectedResourceMetadata(env) {
  return new Response(JSON.stringify({
    resource: mcpResource(env), authorization_servers: [issuerName(env)], scopes_supported: USER_SCOPES,
    bearer_methods_supported: ['header'], resource_name: 'devicebasedauth.org MCP server', resource_documentation: `${env.APP_ORIGIN}/docs/#agents`
  }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600', 'Access-Control-Allow-Origin': '*' } });
}

/**
 * Redirect URIs a public client may register: https without a fragment, or http on a loopback
 * address for native apps (RFC 8252 §7.3).
 */
export function cleanRedirectUri(value) {
  let url;
  try { url = new URL(String(value)); } catch { assert(false, 'invalid_redirect_uri', 'Each redirect_uri must be an absolute URL'); }
  assert(!url.hash && !url.username && !url.password, 'invalid_redirect_uri', 'redirect_uris may not carry a fragment or credentials');
  const loopback = url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  assert(url.protocol === 'https:' || loopback, 'invalid_redirect_uri', 'redirect_uris must use https, or http on localhost / 127.0.0.1 / [::1]');
  assert(url.href.length <= 512, 'invalid_redirect_uri', 'redirect_uris must be at most 512 characters');
  return url.href;
}

function registrationError(error, description) {
  return new Response(JSON.stringify({ error, error_description: description }), { status: 400, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' } });
}

/** POST /oauth/register (RFC 7591). Public clients only; nothing is stored. */
export async function registerClient(request, env) {
  let body;
  try { body = await request.json(); } catch { return registrationError('invalid_client_metadata', 'Body must be JSON'); }
  try {
    assert(Array.isArray(body?.redirect_uris) && body.redirect_uris.length >= 1 && body.redirect_uris.length <= MAX_REDIRECTS, 'invalid_redirect_uri', `redirect_uris must list 1–${MAX_REDIRECTS} URLs`);
    const redirects = [...new Set(body.redirect_uris.map(cleanRedirectUri))];
    const method = body.token_endpoint_auth_method ?? 'none';
    assert(method === 'none', 'invalid_client_metadata', 'Only public clients (token_endpoint_auth_method "none", with PKCE) are supported');
    const grants = body.grant_types ?? ['authorization_code', 'refresh_token'];
    assert(Array.isArray(grants) && grants.includes('authorization_code') && grants.every(g => ['authorization_code', 'refresh_token'].includes(g)), 'invalid_client_metadata', 'grant_types may be authorization_code and refresh_token');
    assert(body.response_types === undefined || (Array.isArray(body.response_types) && body.response_types.every(t => t === 'code')), 'invalid_client_metadata', 'response_types may only be code');
    const name = String(body.client_name ?? 'Unnamed app').replace(/[\p{Cc}\p{Cf}]/gu, '').trim().slice(0, 80) || 'Unnamed app';
    const iat = Math.floor(Date.now() / 1000);
    const clientId = await signToken(MCP_CLIENT_PREFIX, { n: name, r: redirects, iat }, env.TOKEN_SIGNING_KEY);
    return new Response(JSON.stringify({
      client_id: clientId, client_id_issued_at: iat, client_name: name, redirect_uris: redirects,
      token_endpoint_auth_method: 'none', grant_types: grants, response_types: ['code']
    }), { status: 201, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' } });
  } catch (error) {
    if (error instanceof ApiError) return registrationError(error.code === 'invalid_redirect_uri' ? 'invalid_redirect_uri' : 'invalid_client_metadata', error.message);
    throw error;
  }
}

/** Decode a registered MCP client id; null when it is not one or the signature fails. */
export async function mcpClient(env, clientId) {
  if (typeof clientId !== 'string' || !clientId.startsWith(MCP_CLIENT_PREFIX)) return null;
  const data = await verifyToken(clientId, MCP_CLIENT_PREFIX, env.TOKEN_SIGNING_KEY, 8192);
  if (!data || typeof data.n !== 'string' || !Array.isArray(data.r)) return null;
  return { client_id: clientId, client_name: data.n, redirect_uris: data.r };
}

/** GET /oauth/client?client_id=… — what the consent page shows about an MCP client. Free. */
export async function describeClient(request, env) {
  const client = await mcpClient(env, new URL(request.url).searchParams.get('client_id'));
  assert(client, 'invalid_client', 'Unknown or invalid client_id', 404);
  return { kind: 'mcp', client_name: client.client_name, redirect_uris: client.redirect_uris, resource: mcpResource(env), scopes: Object.fromEntries(USER_SCOPES.map(s => [s, DBA_SCOPES[s]])), default_scopes: MCP_DEFAULT_SCOPES };
}

/** The scopes an MCP authorization asks for: DBA scopes only; none means read-only defaults. */
export function mcpScopes(scope) {
  const asked = String(scope ?? '').split(' ').filter(s => s && s !== 'openid' && s !== 'offline_access');
  if (!asked.length) return [...MCP_DEFAULT_SCOPES];
  assert(asked.every(s => USER_SCOPES.includes(s)), 'invalid_scope', `scope may only list ${USER_SCOPES.join(', ')}`);
  return [...new Set(asked)];
}

const clientDigest = clientId => digest(clientId);

/**
 * The code was redeemed: store the connection as an API key record and return its first tokens.
 * code: { client_id, client_name, scope, resource }.
 */
export async function issueMcpTokens(env, account, code) {
  const id = randomId('key', 12);
  const refresh = await signToken(REFRESH_PREFIX, { account, id, n: randomId('r', 12) }, env.TOKEN_SIGNING_KEY);
  const scopes = code.scope.split(' ');
  await rpc(env.ACCOUNTS, account, 'create-key', { id, name: `${code.client_name} (MCP)`, scopes, hash: await digest(refresh), oauth: { client: await clientDigest(code.client_id), resource: code.resource } });
  return tokenResponse(env, { account, id, scopes, clientId: code.client_id, refresh });
}

/** grant_type=refresh_token: rotate the refresh token; a reused one revokes the connection. */
export async function refreshMcpTokens(env, params) {
  const data = await verifyToken(params.refresh_token || '', REFRESH_PREFIX, env.TOKEN_SIGNING_KEY, 4096);
  if (!data?.account || !data.id) return null;
  const refresh = await signToken(REFRESH_PREFIX, { account: data.account, id: data.id, n: randomId('r', 12) }, env.TOKEN_SIGNING_KEY);
  let key;
  try {
    key = await rpc(env.ACCOUNTS, data.account, 'rotate-oauth-key', { id: data.id, hash: await digest(params.refresh_token), client: await clientDigest(params.client_id || ''), new_hash: await digest(refresh) });
  } catch (error) { if (error instanceof ApiError && error.status < 500) return null; throw error; }
  const scopes = params.scope ? mcpScopes(params.scope) : key.scopes;
  if (!scopes.every(s => key.scopes.includes(s))) return null;
  return tokenResponse(env, { account: data.account, id: data.id, scopes, clientId: params.client_id, refresh });
}

async function tokenResponse(env, { account, id, scopes, clientId, refresh }) {
  const signer = await activeSigner(env); const now = Math.floor(Date.now() / 1000);
  const accessToken = await signJws({ typ: 'at+jwt', kid: signer.kid }, { iss: issuerName(env), sub: account, aud: mcpResource(env), client_id: clientId.slice(0, 64), scope: scopes.join(' '), key_id: id, iat: now, exp: now + MCP_ACCESS_SECONDS, jti: randomId('at') }, signer.key);
  return { access_token: accessToken, token_type: 'Bearer', expires_in: MCP_ACCESS_SECONDS, refresh_token: refresh, scope: scopes.join(' ') };
}

/** Is this bearer token one of ours for the MCP resource (an at+jwt)? Cheap header check only. */
export function isMcpAccessToken(token) {
  try { return decodeJws(token).header.typ === 'at+jwt'; } catch { return false; }
}

/**
 * Authenticate an MCP access token: signature, issuer, audience, expiry, then the key record
 * (not revoked). It then acts like an API key with the token's scopes.
 */
export async function authenticateMcpToken(token, env) {
  let verified = null;
  try {
    const { header } = decodeJws(token);
    const key = jwks(env).keys.find(k => k.kid === header.kid);
    if (key) verified = await verifyJws(token, key);
  } catch { verified = null; }
  const p = verified?.payload;
  assert(p && p.iss === issuerName(env) && p.aud === mcpResource(env) && Number.isSafeInteger(p.exp) && p.exp > Math.floor(Date.now() / 1000) && typeof p.sub === 'string' && typeof p.key_id === 'string', 'invalid_token', 'Access token is invalid or expired', 401);
  const key = await rpc(env.ACCOUNTS, p.sub, 'authenticate-oauth-key', { id: p.key_id, rate: { id: p.key_id, limit: 120 } });
  const scopes = String(p.scope || '').split(' ').filter(s => key.scopes.includes(s));
  return { account: p.sub, key_id: p.key_id, scopes, session: false, kind: 'key', oauth: true, rated: true };
}
