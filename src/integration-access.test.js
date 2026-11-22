import { describe, it, expect, beforeEach } from 'vitest';
import { testEnv, call, newDevice, enroll, ORIGIN } from '../test-utils/env.js';
import { inspectCredential, sha256b64u, b64u } from '../packages/verify/src/index.js';
import { price } from './utils/pricing.js';
import { fund } from '../test-utils/integration.js';

// End to end through the Worker: API keys, metered reads and delegation, OpenID Connect sign-in,
// and the public endpoints (JWKS, discovery, quotes, status lists, MCP).

let env;
beforeEach(async () => { env = await testEnv(); });

describe('API keys, metered reads and delegation', () => {
  it('meters API-key reads and keeps session reads free', async () => {
    await fund(env, 'alice');
    const key = await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'ci', scopes: ['credentials:read', 'account:read'] } });
    expect(key.body.secret).toMatch(/^dbak_/);
    const read = await call(env, 'GET', '/api/v1/credentials', { auth: `ApiKey ${key.body.secret}` });
    expect(read.body.cost_microdollars).toBe(price('read'));
    expect((await call(env, 'GET', '/api/v1/credentials', { auth: 'alice' })).body.cost_microdollars).toBe(0);
    expect((await call(env, 'POST', '/api/v1/revoke-all', { auth: `ApiKey ${key.body.secret}`, body: {} })).status).toBe(403);
    await call(env, 'DELETE', `/api/v1/keys/${key.body.id}`, { auth: 'alice' });
    expect((await call(env, 'GET', '/api/v1/credentials', { auth: `ApiKey ${key.body.secret}` })).status).toBe(401);
  });

  it('lets a device with dba:credentials:issue delegate only narrower grants', async () => {
    await fund(env, 'alice');
    const admin = await newDevice();
    const parentGrants = [{ actions: ['dba:credentials:issue'] }, { actions: ['hashbin:content:*'], where: { source: 'network', countries: ['US'] } }];
    const credential = (await enroll(env, 'alice', admin, { aud: ['devicebasedauth.org', 'hashbin.org'], grants: parentGrants })).approve.body.credential;
    const child = await newDevice();
    const issue = async grants => call(env, 'POST', '/api/v1/credentials', { headers: await admin.headers('POST', '/api/v1/credentials', credential), body: { public_jwk: child.publicJwk, aud: ['hashbin.org'], grants, device: { name: 'child', kind: 'agent' } } });
    const ok = await issue([{ actions: ['hashbin:content:write'], where: { source: 'network', countries: ['US'] }, limits: { spend_usd_per_month: 1 } }]);
    expect(ok.status).toBe(200);
    expect(ok.body.payload.exp).toBeLessThanOrEqual(inspectCredential(credential).payload.exp);
    expect((await issue([{ actions: ['hashbin:content:write'] }])).body.code).toBe('not_narrower');
    // Nor may it name an audience its own credential does not (cronly.org could identify the
    // account from such a credential even with no cronly grants in it).
    const wider = await call(env, 'POST', '/api/v1/credentials', { headers: await admin.headers('POST', '/api/v1/credentials', credential), body: { public_jwk: child.publicJwk, aud: ['hashbin.org', 'cronly.org'], grants: [{ actions: ['hashbin:content:write'], where: { source: 'network', countries: ['US'] } }] } });
    expect(wider.status).toBe(403);
    expect(wider.body.code).toBe('not_narrower');
    // One level only (master plan §13): a delegated credential cannot delegate again, even one
    // that was given dba:credentials:issue.
    const middle = await newDevice();
    const delegated = (await call(env, 'POST', '/api/v1/credentials', { headers: await admin.headers('POST', '/api/v1/credentials', credential), body: { public_jwk: middle.publicJwk, aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:credentials:issue'] }] } })).body.credential;
    const deeper = await call(env, 'POST', '/api/v1/credentials', { headers: await middle.headers('POST', '/api/v1/credentials', delegated), body: { public_jwk: (await newDevice()).publicJwk, aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:credentials:issue'] }] } });
    expect(deeper.status).toBe(403);
    expect(deeper.body.code).toBe('delegation_depth');
    // Revoking the delegating credential revokes what it issued.
    const revoked = await call(env, 'DELETE', `/api/v1/credentials/${inspectCredential(credential).payload.cid}`, { auth: 'alice' });
    expect(revoked.body.revoked[0]).toBe(inspectCredential(credential).payload.cid);
    expect(revoked.body.revoked.slice(1).sort()).toEqual([ok.body.cid, inspectCredential(delegated).payload.cid].sort());
  });

  it('lets a dashboard device (dba:session) issue like its owner', async () => {
    await fund(env, 'alice');
    const dashboard = await newDevice();
    const credential = (await enroll(env, 'alice', dashboard, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }] })).approve.body.credential;
    const child = await newDevice();
    const issued = await call(env, 'POST', '/api/v1/credentials', { headers: await dashboard.headers('POST', '/api/v1/credentials', credential), body: { public_jwk: child.publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], lifetime_seconds: 86400 * 90 } });
    expect(issued.status).toBe(200);
    expect(issued.body.payload.exp - issued.body.payload.iat).toBe(86400 * 90);
  });

  it('signs in to its own API with a DBA device credential holding dba:session', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }] })).approve.body.credential;
    const list = await call(env, 'GET', '/api/v1/credentials', { headers: await device.headers('GET', '/api/v1/credentials', credential) });
    expect(list.status).toBe(200);
    expect(list.body.cost_microdollars).toBe(0);
    const narrow = await newDevice();
    const readOnly = (await enroll(env, 'alice', narrow, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:credentials:read'] }] })).approve.body.credential;
    expect((await call(env, 'GET', '/api/v1/credentials', { headers: await narrow.headers('GET', '/api/v1/credentials', readOnly) })).body.cost_microdollars).toBe(price('read'));
    expect((await call(env, 'POST', '/api/v1/revoke-all', { headers: await narrow.headers('POST', '/api/v1/revoke-all', readOnly), body: { confirm: 'revoke-all' } })).status).toBe(403);
  });
});

describe('OpenID Connect', () => {
  it('runs the authorization code flow with PKCE and bills the site', async () => {
    await fund(env, 'operator');
    const verifier = b64u(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = await sha256b64u(verifier);
    const redirect_uri = 'https://cronly.org/auth/dba/callback';
    const approved = await call(env, 'POST', '/oauth/authorize', { auth: 'alice', body: { client_id: 'cronly.org', redirect_uri, response_type: 'code', scope: 'openid profile', state: 's1', nonce: 'n1', code_challenge: challenge, code_challenge_method: 'S256', approve: true } });
    const back = new URL(approved.body.redirect);
    expect(back.searchParams.get('state')).toBe('s1');
    const form = new URLSearchParams({ grant_type: 'authorization_code', code: back.searchParams.get('code'), redirect_uri, client_id: 'cronly.org', code_verifier: verifier });
    const token = await call(env, 'POST', '/oauth/token', { body: form.toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    expect(token.status).toBe(200);
    const id = inspectCredential(token.body.id_token).payload;
    expect(id).toMatchObject({ iss: ORIGIN, sub: 'alice', aud: 'cronly.org', nonce: 'n1', acct: 'alice' });
    const again = await call(env, 'POST', '/oauth/token', { body: form.toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    expect(again.body.error).toBe('invalid_grant');
    const info = await call(env, 'GET', '/oauth/userinfo', { headers: { Authorization: `Bearer ${token.body.access_token}` } });
    expect(info.body).toMatchObject({ sub: 'alice', acct: 'alice' });
    expect((await call(env, 'GET', '/api/v1/account', { auth: 'operator' })).body.today.aggregates.login).toEqual({ count: 1, amount: price('login') });
    expect((await call(env, 'GET', '/api/v1/audiences/cronly.org/usage', { auth: 'operator' })).body.items[0]).toMatchObject({ decisions: 0, logins: 1, spent_microdollars: price('login') });
    const bad = await call(env, 'POST', '/oauth/authorize', { auth: 'alice', body: { client_id: 'cronly.org', redirect_uri: 'https://evil.example/cb', response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', approve: true } });
    expect(bad.body.code).toBe('invalid_redirect_uri');
    const local = await call(env, 'POST', '/oauth/authorize', { auth: 'alice', body: { client_id: 'hashbin.org', redirect_uri: 'http://localhost:8790/auth/dba/callback', response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', approve: true } });
    expect(local.body.redirect).toMatch(/^http:\/\/localhost:8790\/auth\/dba\/callback\?code=/);
  });

  it('refuses redirect URIs that are not web addresses (the consent page navigates to them)', async () => {
    await fund(env, 'operator'); await fund(env, 'mallory');
    for (const uri of ['javascript://localhost/%0Aalert(document.domain)', 'data://localhost/x', 'http://shop.example/cb', 'https://user:pw@shop.example/cb', 'https://shop.example/cb#x']) {
      const patched = await call(env, 'PATCH', '/api/v1/audiences/cronly.org', { auth: 'operator', body: { redirect_uris: [uri] } });
      expect(patched.status, uri).toBe(400);
      expect(patched.body.code).toBe('invalid_redirect_uris');
      const created = await call(env, 'POST', '/api/v1/audiences', { auth: 'mallory', body: { name: 'shop.localhost', namespace: 'shop', catalog: [{ action: 'shop:buy' }], redirect_uris: [uri] } });
      expect(created.body.code, uri).toBe('invalid_redirect_uris');
    }
    expect((await call(env, 'PATCH', '/api/v1/audiences/cronly.org', { auth: 'operator', body: { redirect_uris: ['https://cronly.org/cb', 'http://127.0.0.1:9000/cb'] } })).status).toBe(200);
  });
});

describe('public endpoints', () => {
  it('serves JWKS, discovery, quotes, and the status list', async () => {
    expect((await call(env, 'GET', '/.well-known/jwks.json')).body.keys[0]).toMatchObject({ kid: 'test-1', kty: 'EC', crv: 'P-256' });
    expect((await call(env, 'GET', '/.well-known/jwks.json')).body.keys[0].d).toBeUndefined();
    expect((await call(env, 'GET', '/.well-known/openid-configuration')).body.issuer).toBe(ORIGIN);
    expect((await call(env, 'GET', '/api/v1/quote?op=issue')).body.quote_microdollars).toBe(price('issue'));
    expect((await call(env, 'GET', '/api/v1/audiences?mine=1', { auth: 'operator' })).body.items.map(a => a.name)).toContain('hashbin.org');
    expect((await call(env, 'GET', '/api/v1/audiences?mine=1')).status).toBe(401);
    // The public route checks the scope itself and meters the read like any other.
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'operator', body: { amount_microdollars: 1_000_000 } });
    const narrow = await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'n', scopes: ['authorize'] } });
    expect((await call(env, 'GET', '/api/v1/audiences?mine=1', { auth: `ApiKey ${narrow.body.secret}` })).body.code).toBe('insufficient_scope');
    const reader = await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'r', scopes: ['audiences:read'] } });
    const mine = await call(env, 'GET', '/api/v1/audiences?mine=1', { auth: `ApiKey ${reader.body.secret}` });
    expect(mine.body.items.map(a => a.name)).toContain('hashbin.org');
    expect(mine.body.cost_microdollars).toBe(price('read'));
    expect(mine.headers.get('X-DBA-Cost-Microdollars')).toBe(String(price('read')));
    const list = await call(env, 'GET', '/status/v1/lists/0');
    expect(list.headers.get('Content-Type')).toBe('application/statuslist+jwt');
    expect((await call(env, 'GET', '/status/v1/lists/99')).status).toBe(404);
    expect((await call(env, 'OPTIONS', '/api/v1/enrollments')).headers.get('Access-Control-Allow-Headers')).toMatch(/DPoP/);
  });
  it('answers MCP tools/list and evaluates grants offline', async () => {
    await fund(env, 'alice');
    const key = await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'agent', scopes: ['credentials:read'] } });
    const list = await call(env, 'POST', '/mcp', { auth: `ApiKey ${key.body.secret}`, body: { jsonrpc: '2.0', id: 1, method: 'tools/list' } });
    expect(list.body.result.tools.map(t => t.name)).toContain('evaluate_grants');
    const evaluation = await call(env, 'POST', '/mcp', { auth: `ApiKey ${key.body.secret}`, body: { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'evaluate_grants', arguments: { grants: JSON.stringify([{ actions: ['x:y'] }]), action: 'x:y' } } } });
    expect(JSON.parse(evaluation.body.result.content[0].text)).toMatchObject({ allow: true });
    const creds = await call(env, 'POST', '/mcp', { auth: `ApiKey ${key.body.secret}`, body: { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'list_credentials', arguments: {} } } });
    expect(JSON.parse(creds.body.result.content[0].text).items).toEqual([]);
  });
});
