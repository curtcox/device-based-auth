import { describe, it, expect, beforeEach } from 'vitest';
import { price } from './utils/pricing.js';
import { testEnv, call, newDevice, enroll, runAlarms, ORIGIN } from '../test-utils/env.js';
import { signJws, inspectCredential, createProof } from '../packages/verify/src/index.js';
import { fund, verifierFor, requestWith } from '../test-utils/integration.js';

// End to end through the Worker: a credential's life from enrollment and offline verification
// through revocation and renewal, and the account budget guards that limit issuing.

let env;
beforeEach(async () => { env = await testEnv(); });

describe('enrollment and offline verification', () => {
  it('issues vocabulary 2 only for grants with net, and verifiers enforce net.client offline (B10 N1)', async () => {
    await fund(env, 'alice');
    const plain = await enroll(env, 'alice', await newDevice());
    expect(inspectCredential(plain.approve.body.credential).payload.ver).toBe(1);
    const device = await newDevice();
    const grants = [{ actions: ['hashbin:content:write'], net: { client: { addresses: { cidrs: ['203.0.113.0/24'] }, latency: { max_rtt_ms: 40 } } } }];
    const { approve } = await enroll(env, 'alice', device, { grants });
    const { payload } = inspectCredential(approve.body.credential);
    expect(payload).toMatchObject({ ver: 2, grants });
    const verifier = verifierFor(env);
    const at = async (ip, rtt_ms) => {
      const request = await requestWith(device, approve.body.credential);
      return verifier.verifyRequest(request, { action: 'hashbin:content:write', location: { network: { ip, ...(rtt_ms === undefined ? {} : { rtt_ms }) } } });
    };
    expect(await at('203.0.113.7', 12)).toMatchObject({ allow: true });
    expect(await at('198.51.100.7', 12)).toMatchObject({ allow: false, reasons: [['address_not_allowed']] });
    expect(await at('203.0.113.7')).toMatchObject({ allow: false, reasons: [['rtt_required']] });
  });

  it('a verifier with rtt challenges the device, times its retry, and keeps the best sample (B10 N2)', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const grants = [{ actions: ['hashbin:content:write'], net: { client: { latency: { max_rtt_ms: 40, samples: 2, reuse_s: 60 } } } }];
    const { approve } = await enroll(env, 'alice', device, { grants });
    const credential = approve.body.credential;
    let ms = Date.now();
    const verifier = verifierFor(env, 'hashbin.org', { rtt: { secret: 'r'.repeat(32), now: () => ms } });
    const location = { network: { ip: '203.0.113.7' } };
    const send = async nonce => {
      const url = 'https://hashbin.org/api/content';
      const proof = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential, nonce });
      return verifier.verifyRequest(new Request(url, { method: 'POST', headers: { Authorization: `DBA ${credential}`, DPoP: proof } }), { action: 'hashbin:content:write', location });
    };
    const first = await send();
    expect(first).toMatchObject({ allow: false, status: 401, code: 'use_dpop_nonce', rtt: { samples_left: 2 }, reasons: [['rtt_required']] });
    expect(first.headers).toEqual({ 'WWW-Authenticate': 'DPoP error="use_dpop_nonce", algs="ES256"', 'DPoP-Nonce': first.dpop_nonce });
    ms += 90; // a slow first sample: one more is allowed
    const second = await send(first.dpop_nonce);
    expect(second).toMatchObject({ allow: false, status: 401, code: 'use_dpop_nonce', rtt: { samples_left: 1 }, reasons: [['rtt_exceeded']] });
    ms += 25;
    expect(await send(second.dpop_nonce)).toMatchObject({ allow: true });
    ms += 1000; // within reuse_s, for the same key and address, no new challenge
    expect(await send()).toMatchObject({ allow: true });
    location.network.ip = '203.0.113.8';
    expect(await send()).toMatchObject({ allow: false, code: 'use_dpop_nonce' });
  });

  it('a verifier with rtt denies once every sample was too slow, and never times a nonce for another address (B10 N2)', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const { approve } = await enroll(env, 'alice', device, { grants: [{ actions: ['hashbin:content:write'], net: { client: { latency: { max_rtt_ms: 40 } } } }] });
    const credential = approve.body.credential;
    let ms = Date.now();
    const verifier = verifierFor(env, 'hashbin.org', { rtt: { secret: 'r'.repeat(32), now: () => ms } });
    const send = async (nonce, ip = '203.0.113.7') => {
      const url = 'https://hashbin.org/api/content';
      const proof = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential, nonce });
      return verifier.verifyRequest(new Request(url, { method: 'POST', headers: { Authorization: `DBA ${credential}`, DPoP: proof } }), { action: 'hashbin:content:write', location: { network: { ip } } });
    };
    const challenge = await send();
    ms += 41;
    expect(await send(challenge.dpop_nonce)).toMatchObject({ allow: false, status: 403, code: 'forbidden', reasons: [['rtt_exceeded']] });
    const again = await send(); ms += 3;
    expect(await send(again.dpop_nonce, '198.51.100.1')).toMatchObject({ allow: false, code: 'use_dpop_nonce', reasons: [['rtt_required']] });
  });

  it('a verifier with dns allows addresses of a named host and refuses unvalidated answers where DNSSEC is required (B10 N4)', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const grants = [
      { actions: ['hashbin:content:write'], net: { client: { addresses: { dns: { names: ['vpn.example.com'] } } } } },
      { actions: ['hashbin:content:delete'], net: { client: { addresses: { dns: { names: ['vpn.example.com'], dnssec: true } } } } }
    ];
    const { approve } = await enroll(env, 'alice', device, { grants });
    const asked = [];
    const doh = async url => {
      const u = new URL(url); asked.push(u.origin);
      const A = u.searchParams.get('type') === 'A' ? [{ type: 1, TTL: 60, data: '203.0.113.7' }] : [];
      return Response.json({ Status: 0, AD: false, Answer: A });
    };
    const verifier = verifierFor(env, 'hashbin.org', { dns: { endpoint: 'https://doh.test/dns-query', fetch: doh } });
    const check = async (action, ip) => verifier.verifyRequest(await requestWith(device, approve.body.credential), { action, location: { network: { ip } } });
    expect(await check('hashbin:content:write', '203.0.113.7')).toMatchObject({ allow: true });
    expect(await check('hashbin:content:write', '203.0.113.8')).toMatchObject({ allow: false, reasons: [['address_not_allowed'], ['action_not_granted', 'address_not_allowed', 'dns_unvalidated:vpn.example.com']] });
    expect(await check('hashbin:content:delete', '203.0.113.7')).toMatchObject({ allow: false, reasons: [['action_not_granted'], ['address_not_allowed', 'dns_unvalidated:vpn.example.com']] });
    expect(asked).toEqual(['https://doh.test', 'https://doh.test']); // cached after the first request
    const without = verifierFor(env);
    expect(await without.verifyRequest(await requestWith(device, approve.body.credential), { action: 'hashbin:content:write', location: { network: { ip: '203.0.113.7' } } }))
      .toMatchObject({ allow: false, reasons: [['address_not_allowed', 'dns_unresolved:vpn.example.com'], ['action_not_granted', 'address_not_allowed', 'dns_unresolved:vpn.example.com']] });
  });

  it('accepts only https origins (or http://localhost) as return_origin', async () => {
    const device = await newDevice();
    const start = async origin => call(env, 'POST', '/api/v1/enrollments', { body: { request: await device.enrollRequest({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], return_origin: origin }) } });
    for (const origin of ['ws://localhost:9000', 'wss://app.example', 'http://app.example', 'https://app.example/path']) expect((await start(origin)).body.code, origin).toBe('invalid_return_origin');
    for (const origin of ['https://app.example', 'http://localhost:9000']) expect((await start(origin)).status, origin).toBe(200);
  });

  it('enrolls a device, charges the issue price and verifies offline', async () => {
    await fund(env, 'alice');
    const device = await newDevice();
    const { start, approve } = await enroll(env, 'alice', device);
    expect(start.approval_url).toMatch(/^http:\/\/localhost:8787\/approve\.html#enr_/);
    expect(approve.status).toBe(200);
    expect(approve.body.cost_microdollars).toBe(price('issue'));
    const credential = approve.body.credential;
    const { header, payload } = inspectCredential(credential);
    expect(header).toMatchObject({ typ: 'dba-device+jwt', kid: 'test-1' });
    expect(payload).toMatchObject({ iss: ORIGIN, acct: 'alice', aud: ['hashbin.org'], cnf: { jkt: device.jkt }, grants: [{ actions: ['hashbin:content:write'] }] });

    const poll = await call(env, 'GET', `/api/v1/enrollments/${start.enrollment_id}?poll_token=${encodeURIComponent(start.poll_token)}`);
    expect(poll.body).toMatchObject({ status: 'approved', credential });

    const account = await call(env, 'GET', '/api/v1/account', { auth: 'alice' });
    expect(account.body.balance_microdollars).toBe(1_000_000 - price('issue'));

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
    expect(rotated.body).toMatchObject({ rotated: true, cost_microdollars: price('issue') });
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
    expect(result.body).toMatchObject({ token_type: 'Bearer', expires_in: 600, audience: 'cronly.org', cost_microdollars: price('token') });
    expect(result.headers.get('X-DBA-Cost-Microdollars')).toBe(String(price('token')));
    // This device's grants cover two sites, not the account: it does not see the owner's balance.
    expect(result.body.balance_microdollars).toBeUndefined();
    expect(result.headers.get('X-DBA-Balance-Microdollars')).toBeNull();
    const token = inspectCredential(result.body.access_token);
    expect(token.header.typ).toBe('dba-access+jwt');
    expect(token.payload.grants).toEqual([{ actions: ['cronly:run'] }]);
    const verifier = verifierFor(env, 'cronly.org');
    const allowed = await verifier.verifyRequest(new Request('https://cronly.org/api/jobs/x/run', { method: 'POST', headers: { Authorization: `Bearer ${result.body.access_token}` } }), { action: 'cronly:run' });
    expect(allowed.allow).toBe(true);
    expect((await call(env, 'GET', '/api/v1/account', { auth: 'alice' })).body.today.aggregates.token).toEqual({ count: 1, amount: price('token') });
  });
});

describe('account budget guards', () => {
  it('validates settings, and only a session may change them', async () => {
    await fund(env, 'alice');
    expect((await call(env, 'GET', '/api/v1/account/settings', { auth: 'alice' })).body).toMatchObject({ max_issues_per_day: 500, max_renewals_per_credential_per_month: null });
    for (const body of [{}, { max_issues_per_day: 0 }, { max_issues_per_day: 1.5 }, { max_issues_per_day: null }, { colour: 'red' }]) {
      expect((await call(env, 'PATCH', '/api/v1/account/settings', { auth: 'alice', body })).body.code, JSON.stringify(body)).toBe('invalid_setting');
    }
    const key = await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'k', scopes: ['account:read', 'credentials:issue'] } });
    expect((await call(env, 'PATCH', '/api/v1/account/settings', { auth: `ApiKey ${key.body.secret}`, body: { max_issues_per_day: 9 } })).status).toBe(403);
    const changed = await call(env, 'PATCH', '/api/v1/account/settings', { auth: 'alice', body: { max_renewals_per_credential_per_month: 3 } });
    expect(changed.body).toMatchObject({ max_issues_per_day: 500, max_renewals_per_credential_per_month: 3 });
    const audit = await call(env, 'GET', '/api/v1/audit', { auth: 'alice' });
    // Events in the same millisecond have no defined order; find this one by type.
    expect(audit.body.items.find(e => e.type === 'settings.changed')).toMatchObject({ after: { max_renewals_per_credential_per_month: 3 } });
  });

  it('stops issuing at the daily limit and charges nothing for the refusal', async () => {
    await fund(env, 'alice');
    await call(env, 'PATCH', '/api/v1/account/settings', { auth: 'alice', body: { max_issues_per_day: 2 } });
    expect((await enroll(env, 'alice', await newDevice())).approve.status).toBe(200);
    expect((await enroll(env, 'alice', await newDevice())).approve.status).toBe(200);
    const third = await enroll(env, 'alice', await newDevice());
    expect(third.approve.status).toBe(429);
    expect(third.approve.body).toMatchObject({ code: 'issuance_limit', limit: 2 });
    expect((await call(env, 'GET', '/api/v1/account', { auth: 'alice' })).body.balance_microdollars).toBe(1_000_000 - 2 * price('issue'));
    await call(env, 'PATCH', '/api/v1/account/settings', { auth: 'alice', body: { max_issues_per_day: 3 } });
    expect((await enroll(env, 'alice', await newDevice())).approve.status).toBe(200);
  });

  it('caps renewals per credential per month when the owner sets a cap', async () => {
    await fund(env, 'alice');
    await call(env, 'PATCH', '/api/v1/account/settings', { auth: 'alice', body: { max_renewals_per_credential_per_month: 2 } });
    const device = await newDevice();
    let credential = (await enroll(env, 'alice', device)).approve.body.credential;
    const path = `/api/v1/credentials/${inspectCredential(credential).payload.cid}/renew`;
    const renew = async () => call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: {} });
    for (let i = 0; i < 2; i++) { const r = await renew(); expect(r.status).toBe(200); credential = r.body.credential; }
    const refused = await renew();
    expect(refused.status).toBe(429);
    expect(refused.body).toMatchObject({ code: 'renewal_limit', limit: 2 });
    await call(env, 'PATCH', '/api/v1/account/settings', { auth: 'alice', body: { max_renewals_per_credential_per_month: null } });
    expect((await renew()).status).toBe(200);
  });
});
