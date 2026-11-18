import { describe, it, expect, beforeEach } from 'vitest';
import { testEnv, call, newDevice, enroll, runAlarms, worker, ORIGIN } from '../test-utils/env.js';
import { createVerifier, createProof, signJws, inspectCredential, sha256b64u, b64u } from '../packages/verify/src/index.js';

const fund = (env, account, dollars = 1) => call(env, 'POST', '/api/v1/dev/deposit', { auth: account, body: { amount_microdollars: dollars * 1_000_000 } });
const verifierFor = (env, audience = 'hashbin.org', options = {}) => createVerifier({ issuer: ORIGIN, audience, fetch: (url, init) => worker.fetch(new Request(url, init), env), ...options });
const requestWith = async (device, credential, method = 'POST', url = 'https://hashbin.org/api/content') => new Request(url, { method, headers: { Authorization: `DBA ${credential}`, DPoP: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method, url, credential }) } });

let env;
beforeEach(async () => { env = await testEnv(); });

describe('enrollment and offline verification', () => {
  it('enrolls a device, charges the issue price and verifies offline', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const { start, approve } = await enroll(env, 'alice', device);
    expect(start.approval_url).toMatch(/^http:\/\/localhost:8787\/approve\.html#enr_/);
    expect(approve.status).toBe(200);
    expect(approve.body.cost_microdollars).toBe(75);
    const credential = approve.body.credential;
    const { header, payload } = inspectCredential(credential);
    expect(header).toMatchObject({ typ: 'dba-device+jwt', kid: 'test-1' });
    expect(payload).toMatchObject({ iss: ORIGIN, acct: 'alice', aud: ['hashbin.org'], cnf: { jkt: device.jkt }, grants: [{ actions: ['hashbin:content:write'] }] });

    const poll = await call(env, 'GET', `/api/v1/enrollments/${start.enrollment_id}?poll_token=${encodeURIComponent(start.poll_token)}`);
    expect(poll.body).toMatchObject({ status: 'approved', credential });

    const account = await call(env, 'GET', '/api/v1/account', { auth: 'alice' });
    expect(account.body.balance_microdollars).toBe(1_000_000 - 75);

    const verifier = verifierFor(env);
    expect(await verifier.verifyRequest(await requestWith(device, credential), { action: 'hashbin:content:write' })).toMatchObject({ allow: true, account: 'alice' });
    expect(await verifier.verifyRequest(await requestWith(device, credential), { action: 'hashbin:content:delete' })).toMatchObject({ allow: false, code: 'forbidden' });
    const other = await newDevice();
    expect(await verifier.verifyRequest(await requestWith(other, credential), { action: 'hashbin:content:write' })).toMatchObject({ allow: false, code: 'key_mismatch' });
  });

  it('refuses an enrollment request not signed by its key, and double approval', async () => {
    await fund(env, 'alice');
    const device = await newDevice(); const other = await newDevice();
    const forged = await signJws({ typ: 'dba-enroll+jwt', jwk: device.publicJwk }, { iat: Math.floor(Date.now() / 1000), aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }] }, other.privateKey);
    expect((await call(env, 'POST', '/api/v1/enrollments', { body: { request: forged } })).status).toBe(400);
    const { start } = await enroll(env, 'alice', device);
    expect((await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: start.request } })).status).toBe(409);
  });

  it('validates actions against the audience catalog', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const bad = await enroll(env, 'alice', device, { grants: [{ actions: ['cronly:run'] }] });
    expect(bad.approve.body.code).toBe('invalid_grants');
    const unknown = await enroll(env, 'alice', await newDevice(), { grants: [{ actions: ['hashbin:teleport'] }] });
    expect(unknown.approve.body.error).toMatch(/catalog/);
  });

  it('returns 402 without enough balance and stores nothing', async () => {
    const { approve } = await enroll(env, 'bob', await newDevice());
    expect(approve.status).toBe(402);
    expect((await call(env, 'GET', '/api/v1/credentials', { auth: 'bob' })).body.items).toEqual([]);
  });
});

describe('revocation', () => {
  it('revokes instantly online and through the status list after publishing', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device)).approve.body.credential;
    const { cid } = inspectCredential(credential).payload;
    expect((await verifierFor(env).verifyRequest(await requestWith(device, credential), { action: 'hashbin:content:write' })).allow).toBe(true);

    const revoked = await call(env, 'DELETE', `/api/v1/credentials/${cid}`, { auth: 'alice' });
    expect(revoked.body).toMatchObject({ revoked: [cid], count: 1, cost_microdollars: 0 });
    // Before the debounced publish, the shard has the bit but the published list does not.
    await runAlarms(env);
    const fresh = verifierFor(env);
    expect(await fresh.verifyRequest(await requestWith(device, credential), { action: 'hashbin:content:write' })).toMatchObject({ allow: false, code: 'revoked' });
    const detail = await call(env, 'GET', `/api/v1/credentials/${cid}`, { auth: 'alice' });
    expect(detail.body).toMatchObject({ state: 'revoked', revoked_reason: 'revoked by owner' });
    const inspected = await call(env, 'POST', '/api/v1/inspect', { body: { credential } });
    expect(inspected.body).toMatchObject({ signature_valid: true, revoked: true, valid: false });
  });

  it('revokes every credential of a device, and everything with a confirmation', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    await enroll(env, 'alice', device); await enroll(env, 'alice', device);
    const devices = await call(env, 'GET', '/api/v1/devices', { auth: 'alice' });
    expect(devices.body.items).toHaveLength(1);
    expect(devices.body.items[0].credentials).toHaveLength(2);
    const result = await call(env, 'POST', `/api/v1/devices/${devices.body.items[0].id}/revoke`, { auth: 'alice', body: {} });
    expect(result.body.count).toBe(2);
    await enroll(env, 'alice', await newDevice());
    expect((await call(env, 'POST', '/api/v1/revoke-all', { auth: 'alice', body: {} })).status).toBe(400);
    const all = await call(env, 'POST', '/api/v1/revoke-all', { auth: 'alice', body: { confirm: 'revoke-all' } }); expect(all.body.count, JSON.stringify(all.body)).toBe(1);
  });

  it('lets a device revoke itself', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device)).approve.body.credential;
    const result = await call(env, 'POST', '/api/v1/self/revoke', { headers: await device.headers('POST', '/api/v1/self/revoke', credential) });
    expect(result.body.count).toBe(1);
  });
});

describe('renewal, rotation and access tokens', () => {
  it('renews with the same key and status index; the old version stays valid until it expires', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { lifetime_seconds: 3600 })).approve.body.credential;
    const { cid, status } = inspectCredential(credential).payload;
    const path = `/api/v1/credentials/${cid}/renew`;
    const renewed = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: {} });
    expect(renewed.body).toMatchObject({ cid, jti: `${cid}.2`, rotated: false, cost_microdollars: 25 });
    expect(inspectCredential(renewed.body.credential).payload.status).toEqual(status);
    const again = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: {} });
    expect(again.body.code).toBe('superseded');
  });

  it('rotates to a new key, revoking the old index', async () => {
    await fund(env, 'alice');
    const device = await newDevice(); const next = await newDevice();
    const credential = (await enroll(env, 'alice', device)).approve.body.credential;
    const { cid } = inspectCredential(credential).payload;
    const path = `/api/v1/credentials/${cid}/renew`;
    const keyProof = await signJws({ typ: 'dba-rotate+jwt', jwk: next.publicJwk }, { cid, iat: Math.floor(Date.now() / 1000) }, next.privateKey);
    const rotated = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: { new_key_proof: keyProof } });
    expect(rotated.body).toMatchObject({ rotated: true, cost_microdollars: 75 });
    const fresh = inspectCredential(rotated.body.credential).payload;
    expect(fresh.cnf.jkt).toBe(next.jkt);
    await runAlarms(env);
    const verifier = verifierFor(env);
    expect((await verifier.verifyRequest(await requestWith(device, credential), { action: 'hashbin:content:write' })).code).toBe('revoked');
    expect((await verifier.verifyRequest(await requestWith(next, rotated.body.credential), { action: 'hashbin:content:write' })).allow).toBe(true);
  });

  it('exchanges a credential for a short bearer access token with only that audience\'s grants', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { aud: ['hashbin.org', 'cronly.org'], grants: [{ actions: ['hashbin:content:write', 'cronly:run'] }] })).approve.body.credential;
    const result = await call(env, 'POST', '/api/v1/token', { headers: await device.headers('POST', '/api/v1/token', credential), body: { audience: 'cronly.org' } });
    expect(result.body).toMatchObject({ token_type: 'Bearer', expires_in: 600, audience: 'cronly.org', cost_microdollars: 0 });
    const token = inspectCredential(result.body.access_token);
    expect(token.header.typ).toBe('dba-access+jwt');
    expect(token.payload.grants).toEqual([{ actions: ['cronly:run'] }]);
    const verifier = verifierFor(env, 'cronly.org');
    const allowed = await verifier.verifyRequest(new Request('https://cronly.org/api/jobs/x/run', { method: 'POST', headers: { Authorization: `Bearer ${result.body.access_token}` } }), { action: 'cronly:run' });
    expect(allowed.allow).toBe(true);
    expect((await call(env, 'GET', '/api/v1/account', { auth: 'alice' })).body.today.aggregates.token).toEqual({ count: 1, amount: 5 });
  });
});

describe('online authorization', () => {
  async function setup(grants) {
    await fund(env, 'alice'); await fund(env, 'operator');
    const key = await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'hashbin verifier', scopes: ['authorize'] } });
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { grants })).approve.body.credential;
    const ask = async (action = 'hashbin:content:write', extra = {}) => {
      const url = 'https://hashbin.org/api/content';
      const proof = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential });
      return call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key.body.secret}`, body: { credential, proof, request: { method: 'POST', url }, audience: 'hashbin.org', action, ...extra } });
    };
    return { ask, credential, device };
  }

  it('enforces usage limits and bills the audience for every decision', async () => {
    const { ask, credential, device } = await setup([{ actions: ['hashbin:content:write'], limits: { uses: { count: 2, per: 'day' } } }]);
    expect((await ask()).body).toMatchObject({ allow: true, grant_index: 0, cost_microdollars: 10 });
    expect((await ask()).body.allow).toBe(true);
    expect((await ask()).body).toMatchObject({ allow: false, reasons: ['usage_limit_reached'] });
    expect((await call(env, 'GET', '/api/v1/account', { auth: 'operator' })).body.today.aggregates.decision).toEqual({ count: 3, amount: 30 });
    const offline = await verifierFor(env).verifyRequest(await requestWith(device, credential), { action: 'hashbin:content:write' });
    expect(offline).toMatchObject({ allow: false, code: 'online_required', online_required: true });
    const { cid } = inspectCredential(credential).payload;
    const decisions = await call(env, 'GET', `/api/v1/credentials/${cid}/decisions`, { auth: 'alice' });
    expect(decisions.body.items.map(d => d.allow)).toEqual([false, true, true]);
  });

  it('rejects replayed proofs and revoked credentials immediately', async () => {
    const { credential, device } = await setup([{ actions: ['hashbin:content:write'] }]);
    const key = await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'k', scopes: ['authorize'] } });
    const url = 'https://hashbin.org/api/content';
    const proof = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential });
    const body = { credential, proof, request: { method: 'POST', url }, audience: 'hashbin.org', action: 'hashbin:content:write' };
    expect((await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key.body.secret}`, body })).body.allow).toBe(true);
    expect((await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key.body.secret}`, body })).body.code).toBe('replayed_proof');
    await call(env, 'DELETE', `/api/v1/credentials/${inspectCredential(credential).payload.cid}`, { auth: 'alice' });
    const proof2 = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential });
    expect((await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key.body.secret}`, body: { ...body, proof: proof2 } })).body.code).toBe('revoked');
  });

  it('requires owner approval for step-up grants', async () => {
    const { ask } = await setup([{ actions: ['hashbin:content:delete'], require: { step_up: true } }]);
    const first = await ask('hashbin:content:delete');
    expect(first.body).toMatchObject({ allow: false, code: 'step_up_required' });
    const pending = await call(env, 'GET', '/api/v1/step-ups', { auth: 'alice' });
    expect(pending.body.items).toHaveLength(1);
    await call(env, 'POST', `/api/v1/step-ups/${first.body.step_up.id}/approve`, { auth: 'alice', body: {} });
    expect((await ask('hashbin:content:delete')).body.allow).toBe(true);
    expect((await ask('hashbin:content:delete')).body.code).toBe('step_up_required');
  });

  it('only lets an audience owner ask, and needs funds', async () => {
    const { credential } = await setup([{ actions: ['hashbin:content:write'] }]);
    const mallory = await call(env, 'POST', '/api/v1/keys', { auth: 'mallory', body: { name: 'k', scopes: ['authorize'] } });
    const denied = await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${mallory.body.secret}`, body: { credential, audience: 'hashbin.org', action: 'hashbin:content:write' } });
    expect(denied.status).toBe(403);
  });
});

describe('API keys, metered reads and delegation', () => {
  it('meters API-key reads and keeps session reads free', async () => {
    await fund(env, 'alice');
    const key = await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'ci', scopes: ['credentials:read', 'account:read'] } });
    expect(key.body.secret).toMatch(/^dbak_/);
    const read = await call(env, 'GET', '/api/v1/credentials', { auth: `ApiKey ${key.body.secret}` });
    expect(read.body.cost_microdollars).toBe(5);
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
    // Revoking the delegating credential revokes what it issued.
    const revoked = await call(env, 'DELETE', `/api/v1/credentials/${inspectCredential(credential).payload.cid}`, { auth: 'alice' });
    expect(revoked.body.revoked).toEqual([inspectCredential(credential).payload.cid, ok.body.cid]);
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
    expect((await call(env, 'GET', '/api/v1/credentials', { headers: await narrow.headers('GET', '/api/v1/credentials', readOnly) })).body.cost_microdollars).toBe(5);
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
    expect((await call(env, 'GET', '/api/v1/account', { auth: 'operator' })).body.today.aggregates.login).toEqual({ count: 1, amount: 10 });
    const bad = await call(env, 'POST', '/oauth/authorize', { auth: 'alice', body: { client_id: 'cronly.org', redirect_uri: 'https://evil.example/cb', response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', approve: true } });
    expect(bad.body.code).toBe('invalid_redirect_uri');
    const local = await call(env, 'POST', '/oauth/authorize', { auth: 'alice', body: { client_id: 'hashbin.org', redirect_uri: 'http://localhost:8790/auth/dba/callback', response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', approve: true } });
    expect(local.body.redirect).toMatch(/^http:\/\/localhost:8790\/auth\/dba\/callback\?code=/);
  });
});

describe('public endpoints', () => {
  it('serves JWKS, discovery, quotes, and the status list', async () => {
    expect((await call(env, 'GET', '/.well-known/jwks.json')).body.keys[0]).toMatchObject({ kid: 'test-1', kty: 'EC', crv: 'P-256' });
    expect((await call(env, 'GET', '/.well-known/jwks.json')).body.keys[0].d).toBeUndefined();
    expect((await call(env, 'GET', '/.well-known/openid-configuration')).body.issuer).toBe(ORIGIN);
    expect((await call(env, 'GET', '/api/v1/quote?op=issue')).body.quote_microdollars).toBe(75);
    expect((await call(env, 'GET', '/api/v1/audiences?mine=1', { auth: 'operator' })).body.items.map(a => a.name)).toContain('hashbin.org');
    expect((await call(env, 'GET', '/api/v1/audiences?mine=1')).status).toBe(401);
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
