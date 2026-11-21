import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv, call, newDevice, settle } from '../test-utils/env.js';
import { generateKeyPair, exportPublicJwk, signJws, verifyJws, decodeJws } from '../packages/verify/src/index.js';
import { price } from './utils/pricing.js';
import { hotp } from './services/totp.js';
import { answerChallenge } from './services/webauthn.js';
import { softAuthenticator } from '../test-utils/authenticator.js';
import { gateHelpers } from '../test-utils/gates.js';

// STATUS B7 (done/additional_gates.md): gate kinds beyond a dba device, namely TOTP and security
// keys (G4), webhooks (G5), and Duo and Okta Verify (G8).

let env; const realNow = Date.now; let t;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  env = await testEnv();
  for (const who of ['alice', 'operator']) await call(env, 'POST', '/api/v1/dev/deposit', { auth: who, body: { amount_microdollars: 1_000_000 } });
});
afterEach(() => { Date.now = realNow; });
const { balance, asker } = gateHelpers(() => env);

describe('TOTP and security-key gates (G4)', () => {
  const unbase32 = text => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0; let value = 0; const out = []; for (const c of text) { value = (value << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } } return new Uint8Array(out); };
  const codeAt = (secret, ms) => hotp(secret, Math.floor(ms / 30000));
  const linkOf = url => url.split('#')[1];

  async function totpGate() {
    const created = await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'totp', label: 'Authenticator' } });
    expect(created.body).toMatchObject({ kind: 'totp', state: 'pending', setup: { otpauth_uri: expect.stringMatching(/^otpauth:\/\/totp\//) } });
    const secret = unbase32(created.body.setup.secret);
    // Not usable before it is set up.
    expect((await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: (await newDevice()).publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [created.body.id] }] } }] } })).body.code).toBe('gate_not_active');
    expect((await call(env, 'POST', `/api/v1/gates/${created.body.id}/activate`, { auth: 'alice', body: { code: '000000' === await codeAt(secret, t) ? '111111' : '000000' } })).body.code).toBe('invalid_code');
    const activated = await call(env, 'POST', `/api/v1/gates/${created.body.id}/activate`, { auth: 'alice', body: { code: await codeAt(secret, t) } });
    expect(activated.body).toMatchObject({ state: 'active' });
    expect(JSON.stringify((await call(env, 'GET', '/api/v1/gates', { auth: 'alice' })).body)).not.toContain(created.body.setup.secret);
    return { gate: created.body.id, secret };
  }

  it('answers with a TOTP code on the approval page, each code once', async () => {
    const { gate, secret } = await totpGate();
    const { ask } = await asker([{ actions: ['hashbin:content:delete', 'hashbin:content:write'], require: { gates: [{ any: [gate] }] } }]);
    t += 30000; // the next step: the activation code is spent
    const pending = await ask();
    expect(pending.gate_request.approve_url).toMatch(/^http:\/\/localhost:8787\/gate\.html#dbag_/);
    const link = linkOf(pending.gate_request.approve_url);
    // The owner's dashboard list links to the same approval page.
    const listed = (await call(env, 'GET', '/api/v1/gate-requests', { auth: 'alice' })).body.items.find(r => r.id === pending.gate_request.id);
    expect(linkOf(listed.approve_url)).toBe(link);
    const view = (await call(env, 'GET', `/api/v1/gate-links/${link}`)).body;
    expect(view).toMatchObject({ id: pending.gate_request.id, action: 'hashbin:content:delete', status: 'pending', factors: { entries: [{ gates: [{ id: gate, kind: 'totp', label: 'Authenticator' }] }] } });
    const code = await codeAt(secret, t);
    expect((await call(env, 'POST', `/api/v1/gate-links/${link}/answer`, { body: { gate, decision: 'allow', totp: { code: code === '123456' ? '654321' : '123456' } } })).body.code).toBe('invalid_code');
    expect((await call(env, 'POST', `/api/v1/gate-links/${link}/answer`, { body: { gate, decision: 'allow', totp: { code } } })).body.status).toBe('allowed');
    expect((await ask()).allow).toBe(true);
    // The same code cannot answer another request.
    const other = await ask('hashbin:content:write');
    const replay = await call(env, 'POST', `/api/v1/gate-links/${linkOf(other.gate_request.approve_url)}/answer`, { body: { gate, decision: 'allow', totp: { code } } });
    expect(replay).toMatchObject({ status: 403, body: { code: 'invalid_code' } });
    // A tampered link is refused.
    expect((await call(env, 'GET', `/api/v1/gate-links/${link.slice(0, -2)}xx`)).status).toBe(404);
  });

  it('stops guessing after 5 wrong codes', async () => {
    const { gate, secret } = await totpGate();
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate] }] } }]);
    t += 30000;
    const link = linkOf((await ask()).gate_request.approve_url);
    const right = await codeAt(secret, t);
    const wrong = right === '000001' ? '000002' : '000001';
    for (let i = 0; i < 5; i++) expect((await call(env, 'POST', `/api/v1/gate-links/${link}/answer`, { body: { gate, decision: 'allow', totp: { code: wrong } } })).status).toBe(403);
    expect((await call(env, 'POST', `/api/v1/gate-links/${link}/answer`, { body: { gate, decision: 'allow', totp: { code: right } } })).status).toBe(429);
  });

  it('registers a security key and answers with it', async () => {
    const key = await softAuthenticator();
    const created = (await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'webauthn', label: 'YubiKey', user_verification: 'required' } })).body;
    expect(created.setup.public_key).toMatchObject({ rp: { id: 'localhost' }, pubKeyCredParams: [{ alg: -7 }] });
    const registration = await key.register(created.setup.public_key, 'http://localhost:8787');
    expect((await call(env, 'POST', `/api/v1/gates/${created.id}/activate`, { auth: 'alice', body: { registration } })).body.state).toBe('active');
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [created.id] }] } }]);
    const pending = await ask();
    const link = linkOf(pending.gate_request.approve_url);
    const view = (await call(env, 'GET', `/api/v1/gate-links/${link}`)).body;
    expect(view.factors.entries[0].gates[0]).toMatchObject({ kind: 'webauthn', credential_id: key.id, user_verification: 'required' });
    const sign = decision => answerChallenge({ requestId: view.id, entry: 0, decision, salt: view.factors.salt }).then(challenge => key.assert({ challenge, rpId: view.factors.rp_id }, 'http://localhost:8787'));
    // An assertion made to deny does not allow.
    expect((await call(env, 'POST', `/api/v1/gate-links/${link}/answer`, { body: { gate: created.id, decision: 'allow', webauthn: await sign('deny') } })).body.code).toBe('invalid_webauthn');
    expect((await call(env, 'POST', `/api/v1/gate-links/${link}/answer`, { body: { gate: created.id, decision: 'allow', webauthn: await sign('allow') } })).body.status).toBe('allowed');
    expect((await ask()).allow).toBe(true);
  });
});

describe('webhook gates (G5)', () => {
  /** A fake approval service: answers each signed gate request with `reply(payload)`. */
  async function service(reply) {
    const pair = await generateKeyPair(true);
    const seen = [];
    env.WEBHOOK_FETCH = async (url, init) => {
      const { header, payload } = decodeJws(init.body);
      seen.push({ url, header, payload, jws: init.body });
      const r = await reply(payload);
      if (r === 'down') throw new TypeError('connection refused');
      return typeof r === 'number' ? new Response(null, { status: r }) : Response.json(r);
    };
    const created = await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'webhook', label: 'Approvals service', url: 'https://approvals.example.com/dba', public_jwk: await exportPublicJwk(pair.publicKey) } });
    expect(created.body).toMatchObject({ kind: 'webhook', state: 'active', url: 'https://approvals.example.com/dba' });
    const lateAnswer = (payload, decision, key = pair.privateKey) => signJws({ typ: 'dba-gate-answer+jwt' }, { gate: payload.gate, request: payload.request, entry: payload.entry, decision, iat: Math.floor(t / 1000) }, key);
    return { gate: created.body.id, seen, lateAnswer };
  }

  it('tests a webhook gate with a signed gate.test message and reports the answer (G9)', async () => {
    const { gate, seen } = await service(payload => (payload.type === 'gate.test' ? { decision: 'deny' } : 500));
    const before = await balance('alice');
    const result = await call(env, 'POST', `/api/v1/gates/${gate}/test`, { auth: 'alice' });
    expect(result.body).toMatchObject({ gate, delivered: true, status: 200, decision: 'deny', cost_microdollars: price('read') });
    expect(before - await balance('alice')).toBe(price('read'));
    expect(seen[0].header.typ).toBe('dba-gate+jwt');
    expect(seen[0].payload).toMatchObject({ type: 'gate.test', aud: 'https://approvals.example.com/dba', gate, account: 'alice' });
    expect(seen[0].payload.request).toBeUndefined();
    expect(seen[0].payload.exp - seen[0].payload.iat).toBe(60);
    env.WEBHOOK_FETCH = async () => { throw new TypeError('connection refused'); };
    expect((await call(env, 'POST', `/api/v1/gates/${gate}/test`, { auth: 'alice' })).body).toMatchObject({ delivered: false, error: 'network_error' });
    expect((await call(env, 'POST', '/api/v1/gates/owner/test', { auth: 'alice' })).body.code).toBe('not_testable');
    expect((await call(env, 'POST', '/api/v1/gates/gate_00000000/test', { auth: 'alice' })).status).toBe(404);
  });

  it('refuses webhook URLs that are not public https hosts', async () => {
    const key = await exportPublicJwk((await generateKeyPair(true)).publicKey);
    for (const url of ['http://approvals.example.com/x', 'https://10.0.0.1/x', 'https://user:pw@approvals.example.com/', 'https://approvals.example.com:8443/', 'https://intranet/x']) {
      expect((await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'webhook', label: 'x', url, public_jwk: key } })).body.code, url).toBe('invalid_gate');
    }
  });

  it('posts a request signed by the issuer and takes an answer in the response', async () => {
    const { gate, seen } = await service(payload => ({ decision: payload.action === 'hashbin:content:delete' ? 'allow' : 'deny' }));
    const { ask } = await asker([{ actions: ['hashbin:content:delete', 'hashbin:content:write'], require: { gates: [{ any: [gate] }] } }]);
    expect((await ask()).code).toBe('gate_pending');
    await settle(env);
    expect(seen).toHaveLength(1);
    const jwks = (await call(env, 'GET', '/.well-known/jwks.json')).body;
    expect(seen[0].header.typ).toBe('dba-gate+jwt');
    expect(await verifyJws(seen[0].jws, jwks.keys.find(k => k.kid === seen[0].header.kid))).toBeTruthy();
    expect(seen[0].payload).toMatchObject({ type: 'gate.request', gate, entry: 0, action: 'hashbin:content:delete', audience: 'hashbin.org', device: { name: 'Test device' }, callback: expect.stringMatching(/\/api\/v1\/gate-links\/dbag_.*\/callback$/) });
    expect((await ask()).allow).toBe(true);
    expect((await ask('hashbin:content:write')).code).toBe('gate_pending');
    await settle(env);
    expect((await ask('hashbin:content:write')).code).toBe('gate_denied');
  });

  it('takes a late answer signed with the registered key, and refuses one signed by another', async () => {
    const { gate, seen, lateAnswer } = await service(() => 202);
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate] }] } }]);
    await ask(); await settle(env);
    const { payload } = seen[0];
    const callback = payload.callback.replace('http://localhost:8787', '');
    const forged = await lateAnswer(payload, 'allow', (await generateKeyPair(true)).privateKey);
    expect((await call(env, 'POST', callback, { body: forged, headers: { 'Content-Type': 'application/jwt' } })).body.code).toBe('invalid_signature');
    expect((await ask()).code).toBe('gate_pending');
    const answered = await call(env, 'POST', callback, { body: await lateAnswer(payload, 'allow'), headers: { 'Content-Type': 'application/jwt' } });
    expect(answered.body).toMatchObject({ status: 'allowed' });
    expect((await ask()).allow).toBe(true);
  });

  it('follows on_timeout when the service cannot be reached', async () => {
    const { gate } = await service(() => 'down');
    const { ask } = await asker([
      { actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate], timeout_s: 30, on_timeout: 'allow' }] } },
      { actions: ['hashbin:content:write'], require: { gates: [{ any: [gate], timeout_s: 30 }] } }
    ]);
    const pending = await ask('hashbin:content:delete'); await ask('hashbin:content:write');
    await settle(env);
    expect((await call(env, 'GET', `/api/v1/gate-requests/${pending.gate_request.id}`, { auth: 'alice' })).body.entries[0].gates[0].delivery).toBe('failed');
    t += 31000;
    expect((await ask('hashbin:content:delete')).allow).toBe(true);
    expect((await ask('hashbin:content:write')).code).toBe('gate_denied');
  });

  it('charges the webhook price for a webhook gate', async () => {
    const { gate } = await service(() => 202);
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate] }] } }]);
    const before = await balance('alice');
    await ask(); await settle(env);
    expect(before - await balance('alice')).toBe(price('gate_webhook'));
  });
});

describe('Duo and Okta Verify gates (G8)', () => {
  /** A recorded vendor: answers the start and then `answers` in turn to status polls. */
  function vendor(answers) {
    const calls = [];
    env.VENDOR_FETCH = async (url, init) => {
      calls.push({ url, method: init.method, headers: init.headers, body: init.body });
      if (url.endsWith('/auth/v2/auth')) return Response.json({ stat: 'OK', response: { txid: '45f7c92b-f45f-4862-8545-e0f58e78075a' } });
      if (url.includes('/auth/v2/auth_status')) return Response.json({ stat: 'OK', response: { result: answers.shift() ?? 'waiting', status: 'pushed', status_msg: 'Pushed a login request to your phone...' } });
      if (url.endsWith('/verify')) return Response.json({ factorResult: 'WAITING', _links: { poll: { href: `${url.replace('/verify', '')}/transactions/v2mst.GldKV5VxTrifyeZmWSQguA` } } }, { status: 201 });
      if (url.includes('/transactions/')) return Response.json({ factorResult: answers.shift() ?? 'WAITING' });
      return new Response('unexpected', { status: 500 });
    };
    return calls;
  }
  const tick = async ms => { t += ms; for (const o of env.ACCOUNTS.objects.values()) if (o.storage.alarm !== null && o.storage.alarm <= t) { o.storage.alarm = null; await o.alarm(); } };

  it('pushes with Duo, polls until the user approves, and never stores the secret key in view', async () => {
    const calls = vendor(['waiting', 'allow']);
    const created = await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'duo', label: 'Duo', api_host: 'api-1234abcd.duosecurity.com', integration_key: 'DIWJ8X6AEYOR5OMC6TQ1', secret_key: 'Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep', username: 'alice' } });
    expect(created.body).toMatchObject({ kind: 'duo', state: 'active', api_host: 'api-1234abcd.duosecurity.com', username: 'alice' });
    expect(JSON.stringify(created.body)).not.toContain('Zh5eGmUq');
    expect((await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'duo', label: 'x', api_host: 'evil.example.com', integration_key: 'DIWJ8X6AEYOR5OMC6TQ1', secret_key: 'Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep', username: 'a' } })).body.code).toBe('invalid_gate');
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [created.body.id] }] } }]);
    expect((await ask()).code).toBe('gate_pending');
    await settle(env);
    expect(calls[0]).toMatchObject({ url: 'https://api-1234abcd.duosecurity.com/auth/v2/auth', method: 'POST' });
    expect(calls[0].body).toContain('factor=push');
    expect(calls[0].headers.Authorization).toMatch(/^Basic /);
    await tick(5000);
    expect((await ask()).code).toBe('gate_pending');
    await tick(5000);
    expect((await ask())).toMatchObject({ allow: true, gates: [{ kind: 'duo', by: 'answer' }] });
    expect(calls.filter(c => c.url.includes('auth_status'))).toHaveLength(2);
  });

  it('pushes with Okta Verify and takes a rejection; polls stop after 24', async () => {
    const calls = vendor([]);
    const created = (await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'okta-verify', label: 'Okta', org_url: 'https://example.okta.com', api_token: '00abcdefghijklmnopqrstuvwxyz0123456789AB', user_id: '00u1abcdefGHIJKLMN0x', factor_id: 'opf1abcdefGHIJKLMN0x' } })).body;
    expect(created).toMatchObject({ kind: 'okta-verify', org_url: 'https://example.okta.com' });
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [created.id], timeout_s: 600 }] } }]);
    await ask(); await settle(env);
    expect(calls[0].url).toBe('https://example.okta.com/api/v1/users/00u1abcdefGHIJKLMN0x/factors/opf1abcdefGHIJKLMN0x/verify');
    expect(calls[0].headers.Authorization).toMatch(/^SSWS /);
    for (let i = 0; i < 30; i++) await tick(5000);
    expect(calls.filter(c => c.url.includes('/transactions/')).length).toBeLessThanOrEqual(24);
    expect((await ask()).code).toBe('gate_pending');
    const okta = vendor(['REJECTED']);
    const second = await asker([{ actions: ['hashbin:content:write'], require: { gates: [{ any: [created.id] }] } }]);
    await second.ask('hashbin:content:write'); await settle(env);
    await tick(5000);
    expect((await second.ask('hashbin:content:write')).code).toBe('gate_denied');
    expect(okta.length).toBe(2);
  });

  it('charges the vendor price', async () => {
    vendor([]);
    const created = (await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'duo', label: 'Duo', api_host: 'api-1234abcd.duosecurity.com', integration_key: 'DIWJ8X6AEYOR5OMC6TQ1', secret_key: 'Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep', username: 'alice' } })).body;
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [created.id] }] } }]);
    const before = await balance('alice');
    await ask(); await settle(env);
    expect(before - await balance('alice')).toBe(price('gate_vendor'));
  });
});
