import { describe, it, expect, beforeEach } from 'vitest';
import { testEnv, call, worker, ORIGIN, meter } from '../test-utils/env.js';
import { OPERATIONS } from './utils/cost-policy.js';
import { sha256b64u, decodeJws } from '../packages/verify/src/index.js';
import { price } from './utils/pricing.js';

// Master plan §7.4: the MCP server is OAuth-protected, following the MCP authorization spec, so
// MCP clients connect with discovery, registration, PKCE and refresh tokens instead of a pasted key.

const REDIRECT = 'https://app.example/oauth/callback';
const verifier = 'v'.repeat(50);
let env; let challenge;
beforeEach(async () => {
  env = await testEnv(); challenge = await sha256b64u(verifier);
  // Apps pay for reads like API keys do.
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
});

const form = (params) => worker.fetch(new Request(`${ORIGIN}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params) }), env).then(async r => ({ status: r.status, body: await r.json() }));
const rpcCall = (auth, name, args = {}) => call(env, 'POST', '/mcp', { auth, body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } } });

async function register(body = { client_name: 'Test Agent', redirect_uris: [REDIRECT] }) {
  return call(env, 'POST', '/oauth/register', { body });
}

/** Register, approve as `owner`, exchange the code: the tokens an MCP client would hold. */
async function connect(owner = 'alice', scope) {
  const { client_id } = (await register()).body;
  const approved = await call(env, 'POST', '/oauth/authorize', { auth: owner, body: { client_id, redirect_uri: REDIRECT, response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', state: 's', resource: `${ORIGIN}/mcp`, ...(scope ? { scope } : {}), approve: true } });
  expect(approved.status).toBe(200);
  const code = new URL(approved.body.redirect).searchParams.get('code');
  const tokens = await form({ grant_type: 'authorization_code', code, client_id, redirect_uri: REDIRECT, code_verifier: verifier, resource: `${ORIGIN}/mcp` });
  expect(tokens.status).toBe(200);
  return { client_id, ...tokens.body };
}

describe('MCP OAuth discovery and registration', () => {
  it('points an unauthenticated MCP client at the metadata', async () => {
    const refused = await call(env, 'POST', '/mcp', { body: { jsonrpc: '2.0', id: 1, method: 'tools/list' } });
    expect(refused.status).toBe(401);
    expect(refused.headers.get('WWW-Authenticate')).toBe(`Bearer resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp"`);
    const resource = (await call(env, 'GET', '/.well-known/oauth-protected-resource/mcp')).body;
    expect(resource).toMatchObject({ resource: `${ORIGIN}/mcp`, authorization_servers: [ORIGIN] });
    expect(resource.scopes_supported).toContain('credentials:read');
    const server = (await call(env, 'GET', '/.well-known/oauth-authorization-server')).body;
    expect(server).toMatchObject({ issuer: ORIGIN, registration_endpoint: `${ORIGIN}/oauth/register`, code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'] });
    expect(server.grant_types_supported).toContain('refresh_token');
  });

  it('registers public clients statelessly and refuses unsafe redirect URIs', async () => {
    const ok = await register({ client_name: 'Agent\u0007 X', redirect_uris: [REDIRECT, 'http://127.0.0.1:3334/cb'] });
    expect(ok.status).toBe(201);
    expect(ok.body).toMatchObject({ client_name: 'Agent X', token_endpoint_auth_method: 'none', redirect_uris: [REDIRECT, 'http://127.0.0.1:3334/cb'] });
    expect(ok.body.client_id).toMatch(/^dbamcp_/);
    const described = await call(env, 'GET', `/oauth/client?client_id=${encodeURIComponent(ok.body.client_id)}`);
    expect(described.body).toMatchObject({ kind: 'mcp', client_name: 'Agent X', default_scopes: ['account:read', 'credentials:read', 'transactions:read'] });
    for (const redirect_uris of [['http://app.example/cb'], ['https://app.example/cb#x'], ['javascript:alert(1)'], [], Array(6).fill(REDIRECT)]) {
      const bad = await register({ redirect_uris });
      expect(bad.status, JSON.stringify(redirect_uris)).toBe(400);
      expect(['invalid_redirect_uri', 'invalid_client_metadata']).toContain(bad.body.error);
    }
    expect((await register({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'client_secret_basic' })).body.error).toBe('invalid_client_metadata');
    // A client id cannot be forged or edited.
    const forged = ok.body.client_id.replace(/.$/, c => (c === 'A' ? 'B' : 'A'));
    expect((await call(env, 'GET', `/oauth/client?client_id=${encodeURIComponent(forged)}`)).status).toBe(404);
  });
});

describe('MCP OAuth authorization and tokens', () => {
  it('connects an app that then uses the MCP tools with the approved scopes only', async () => {
    const tokens = await connect('alice', 'credentials:read account:read');
    expect(tokens).toMatchObject({ token_type: 'Bearer', expires_in: 3600, scope: 'credentials:read account:read' });
    expect(tokens.refresh_token).toMatch(/^dbar_/);
    expect(decodeJws(tokens.access_token).payload).toMatchObject({ aud: `${ORIGIN}/mcp`, sub: 'alice' });
    const bearer = `Bearer ${tokens.access_token}`;
    const listed = await rpcCall(bearer, 'list_credentials');
    expect(listed.body.result.isError, listed.body.result.content[0].text).toBe(false);
    expect(JSON.parse(listed.body.result.content[0].text).items).toEqual([]);
    // revoke_credential needs credentials:revoke, which was not approved.
    const refused = await rpcCall(bearer, 'revoke_credential', { cid: 'crd_12345678' });
    expect(JSON.parse(refused.body.result.content[0].text).code).toBe('insufficient_scope');
    // The connection shows up with the account's API keys.
    const keys = await call(env, 'GET', '/api/v1/keys', { auth: 'alice' });
    expect(keys.body.items).toEqual([expect.objectContaining({ name: 'Test Agent (MCP)', kind: 'oauth', scopes: ['credentials:read', 'account:read'], resource: `${ORIGIN}/mcp` })]);
    expect(keys.body.items[0].hash).toBeUndefined();
  });

  it('grants read-only scopes when the app asks for none, and refuses unknown scopes', async () => {
    expect((await connect('alice')).scope).toBe('account:read credentials:read transactions:read');
    const { client_id } = (await register()).body;
    const bad = await call(env, 'POST', '/oauth/authorize', { auth: 'alice', body: { client_id, redirect_uri: REDIRECT, response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', scope: 'credentials:read root', approve: true } });
    expect(bad.body.code).toBe('invalid_scope');
    const wrongResource = await call(env, 'POST', '/oauth/authorize', { auth: 'alice', body: { client_id, redirect_uri: REDIRECT, response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', resource: 'https://evil.example/mcp', approve: true } });
    expect(wrongResource.body.code).toBe('invalid_target');
    const wrongRedirect = await call(env, 'POST', '/oauth/authorize', { auth: 'alice', body: { client_id, redirect_uri: 'https://evil.example/cb', response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', approve: true } });
    expect(wrongRedirect.body.code).toBe('invalid_redirect_uri');
  });

  it('needs a recent sign-in, like creating an API key', async () => {
    const { client_id } = (await register()).body;
    const stale = { ...env, CLERK_SECRET_KEY: 'sk_test', CLERK_VERIFY_TOKEN: async () => ({ sub: 'carol', sid: 's', fva: [30, -1] }) };
    const response = await worker.fetch(new Request(`${ORIGIN}/oauth/authorize`, { method: 'POST', headers: { Authorization: 'Bearer clerk-session', 'Content-Type': 'application/json' }, body: JSON.stringify({ client_id, redirect_uri: REDIRECT, response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', approve: true }) }), stale);
    expect(response.status).toBe(403);
    expect((await response.json()).code).toBe('reverification_required');
  });

  it('rotates refresh tokens, and a reused one revokes the connection', async () => {
    const first = await connect();
    const second = await form({ grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: first.client_id });
    expect(second.status).toBe(200);
    expect(second.body.refresh_token).not.toBe(first.refresh_token);
    expect((await rpcCall(`Bearer ${second.body.access_token}`, 'balance')).body.result.isError).toBe(false);
    // Another client cannot use it.
    const other = (await register({ client_name: 'Other', redirect_uris: [REDIRECT] })).body.client_id;
    expect((await form({ grant_type: 'refresh_token', refresh_token: second.body.refresh_token, client_id: other })).body.error).toBe('invalid_grant');
    // Replaying the first refresh token (a leaked copy) revokes the whole connection.
    expect((await form({ grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: first.client_id })).body.error).toBe('invalid_grant');
    expect((await form({ grant_type: 'refresh_token', refresh_token: second.body.refresh_token, client_id: first.client_id })).body.error).toBe('invalid_grant');
    const cut = await call(env, 'POST', '/mcp', { auth: `Bearer ${second.body.access_token}`, body: { jsonrpc: '2.0', id: 1, method: 'tools/list' } });
    expect(cut.status).toBe(401);
    expect(cut.headers.get('WWW-Authenticate')).toContain('error="invalid_token"');
    const audit = await call(env, 'GET', '/api/v1/audit', { auth: 'alice' });
    expect(audit.body.items.some(e => e.type === 'key.revoked' && e.reason === 'refresh token reused')).toBe(true);
  });

  it('charges each refresh as a token, keeps the refresh token through an empty balance, and shows when it last refreshed', async () => {
    const first = await connect();
    const before = (await call(env, 'GET', '/api/v1/account', { auth: 'alice' })).body.balance_microdollars;
    const second = await form({ grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: first.client_id });
    expect(second.status).toBe(200);
    const after = (await call(env, 'GET', '/api/v1/account', { auth: 'alice' })).body;
    expect(before - after.balance_microdollars).toBe(price('token'));
    expect(after.today.aggregates.token).toEqual({ count: 1, amount: price('token') });
    const keys = (await call(env, 'GET', '/api/v1/keys', { auth: 'alice' })).body.items;
    expect(keys[0].refreshed_at).toBeGreaterThan(0);
    // Empty balance: refused without rotating, so the same refresh token works after a deposit.
    const account = [...env.ACCOUNTS.objects.values()].find(o => o.storage.rows.has('profile') && o.storage.rows.get('profile').account === 'alice');
    const balance = account.storage.rows.get('balance'); const kept = balance.balance_microdollars; balance.balance_microdollars = 0;
    const empty = await form({ grant_type: 'refresh_token', refresh_token: second.body.refresh_token, client_id: first.client_id });
    expect(empty).toMatchObject({ status: 503, body: { error: 'temporarily_unavailable' } });
    account.storage.rows.get('balance').balance_microdollars = kept;
    expect((await form({ grant_type: 'refresh_token', refresh_token: second.body.refresh_token, client_id: first.client_id })).status).toBe(200);
    // Revoking the connection drops its refresh state from the balance row.
    await call(env, 'DELETE', `/api/v1/keys/${keys[0].id}`, { auth: 'alice' });
    expect(account.storage.rows.get('balance').refresh).toEqual({});
  });

  it('a refresh stays within what a token is priced on (cost policy)', async () => {
    const first = await connect();
    const warm = await form({ grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: first.client_id });
    const realNow = Date.now; const t = realNow() + 86400000; Date.now = () => t;
    try {
      const m = meter(env); m.reset();
      expect((await form({ grant_type: 'refresh_token', refresh_token: warm.body.refresh_token, client_id: first.client_id })).status).toBe(200);
      const got = m.read();
      expect(got.doRequests).toBeLessThanOrEqual(OPERATIONS.token.doRequests);
      expect(got.rowWrites).toBeLessThanOrEqual(OPERATIONS.token.rowWrites);
    } finally { Date.now = realNow; }
  });

  it('stops working the moment the owner revokes it in the dashboard', async () => {
    const tokens = await connect();
    const [key] = (await call(env, 'GET', '/api/v1/keys', { auth: 'alice' })).body.items;
    expect((await call(env, 'DELETE', `/api/v1/keys/${key.id}`, { auth: 'alice' })).status).toBe(200);
    expect((await call(env, 'GET', '/api/v1/account', { auth: `Bearer ${tokens.access_token}` })).status).toBe(401);
    expect((await form({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: tokens.client_id })).body.error).toBe('invalid_grant');
  });

  it('keeps refresh tokens out of the API-key path and access tokens for other audiences out of /mcp', async () => {
    const tokens = await connect();
    expect((await call(env, 'GET', '/api/v1/account', { auth: `ApiKey ${tokens.refresh_token}` })).status).toBe(401);
    // A sign-in access token issued to a site (audience) is not an MCP token.
    const forged = tokens.access_token.split('.'); forged[1] = Buffer.from(JSON.stringify({ ...decodeJws(tokens.access_token).payload, aud: 'cronly.org' })).toString('base64url');
    expect((await call(env, 'GET', '/api/v1/account', { auth: `Bearer ${forged.join('.')}` })).status).toBe(401);
  });
});
