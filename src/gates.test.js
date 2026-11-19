import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv, call, newDevice, enroll, settle, runAlarms } from '../test-utils/env.js';
import { inspectCredential, createProof, generateKeyPair, exportPublicJwk, signJws, verifyJws, decodeJws } from '../packages/verify/src/index.js';
import { price } from './utils/pricing.js';
import { hotp } from './services/totp.js';
import { answerChallenge } from './services/webauthn.js';
import { softAuthenticator } from '../test-utils/authenticator.js';

// STATUS B7, phase G2 (todo/additional_gates.md): the gate registry and the gate request engine.

let env; const realNow = Date.now; let t;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  env = await testEnv();
  for (const who of ['alice', 'operator']) await call(env, 'POST', '/api/v1/dev/deposit', { auth: who, body: { amount_microdollars: 1_000_000 } });
});
afterEach(() => { Date.now = realNow; });

const balance = async who => (await call(env, 'GET', '/api/v1/account', { auth: who })).body.balance_microdollars;
const audit = async who => (await call(env, 'GET', '/api/v1/audit', { auth: who })).body.items.map(e => e.type);

/** A phone enrolled as a dba-device gate for `owner`, able to answer gate requests. */
async function phoneGate(owner = 'alice', label = 'Phone') {
  const phone = await newDevice();
  const credential = (await enroll(env, owner, phone, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:approvals:answer'] }], name: label })).approve.body.credential;
  const deviceId = inspectCredential(credential).payload.sub;
  const created = await call(env, 'POST', '/api/v1/gates', { auth: owner, body: { kind: 'dba-device', label, device_id: deviceId } });
  expect(created.status).toBe(200);
  const as = (method, path, body) => phone.headers(method, path, credential).then(headers => call(env, method, path, { headers, body }));
  return { gate: created.body.id, deviceId, as };
}

/** A device whose credential holds `grants` for hashbin.org, and an audience key to ask with. */
async function asker(grants, owner = 'alice') {
  const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'verifier', scopes: ['authorize'] } })).body.secret;
  const device = await newDevice();
  const issued = (await enroll(env, owner, device, { grants })).approve;
  expect(issued.status, JSON.stringify(issued.body)).toBe(200);
  const credential = issued.body.credential;
  const url = 'https://hashbin.org/api/content';
  const ask = async (action = 'hashbin:content:delete', resource) => (await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key}`, body: { credential, proof: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential }), request: { method: 'POST', url }, audience: 'hashbin.org', action, resource } })).body;
  return { ask, credential, deviceId: inspectCredential(credential).payload.sub };
}

describe('gate registry', () => {
  it('lists the built-in owner gate, adds and removes dba-device gates', async () => {
    const { gate, deviceId } = await phoneGate();
    const list = (await call(env, 'GET', '/api/v1/gates', { auth: 'alice' })).body.items;
    expect(list.map(g => g.id)).toEqual(['owner', gate]);
    expect(list[1]).toMatchObject({ kind: 'dba-device', label: 'Phone', device_id: deviceId, state: 'active' });
    expect((await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'sms', label: 'x' } })).body.code).toBe('gate_kind_not_available');
    expect((await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'dba-device', label: 'x', device_id: 'dev_NOTMYDEVICE1' } })).body.code).toBe('unknown_device');
    expect((await call(env, 'DELETE', `/api/v1/gates/${gate}`, { auth: 'alice' })).body.deleted).toBe(true);
    expect((await call(env, 'GET', '/api/v1/gates', { auth: 'alice' })).body.items).toHaveLength(1);
    expect(await audit('alice')).toEqual(expect.arrayContaining(['gate.created', 'gate.deleted']));
  });

  it('refuses a credential whose gate is its own device, or a gate that does not exist', async () => {
    const { gate } = await phoneGate();
    const phoneOwnGrant = [{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate] }] } }];
    // Issuing to the gate's own device (same key) would let it approve itself.
    const created = await call(env, 'GET', '/api/v1/gates', { auth: 'alice' });
    const deviceId = created.body.items[1].device_id;
    const device = (await call(env, 'GET', `/api/v1/devices/${deviceId}`, { auth: 'alice' })).body;
    const self = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: device.public_jwk, aud: ['hashbin.org'], grants: phoneOwnGrant } });
    expect(self).toMatchObject({ status: 400, body: { code: 'self_gate' } });
    expect((await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: (await newDevice()).publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:delete'], require: { gates: [{ any: ['gate_00000000'] }] } }] } })).body.code).toBe('unknown_gate');
  });
});

describe('gate requests', () => {
  it('waits for a dba-device gate, which sees and answers only its own requests', async () => {
    const { gate, as } = await phoneGate();
    const { ask, deviceId } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate], timeout_s: 120 }] } }]);
    const first = await ask();
    expect(first).toMatchObject({ allow: false, code: 'gate_pending', reasons: ['gate_pending'], gate_request: { retry_after: 2 } });
    expect((await ask()).gate_request.id).toBe(first.gate_request.id); // retries reuse it
    const mine = (await as('GET', '/api/v1/gate-requests')).body.items;
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatchObject({ id: first.gate_request.id, device_id: deviceId, action: 'hashbin:content:delete', status: 'pending', answer_as: [{ entry: 0, gate }] });
    expect((await as('GET', `/api/v1/gate-requests/${first.gate_request.id}`)).body.answer_as).toEqual([{ entry: 0, gate }]);
    expect((await call(env, 'GET', '/api/v1/gate-requests', { auth: 'alice' })).body.items[0].answer_as).toBeUndefined();
    // The owner may not answer for the phone's gate, and an API key may not answer at all.
    const path = `/api/v1/gate-requests/${first.gate_request.id}/answer`;
    expect((await call(env, 'POST', path, { auth: 'alice', body: { gate, decision: 'allow' } })).body.code).toBe('not_the_gate');
    const answered = await as('POST', path, { gate, decision: 'allow' });
    expect(answered.body).toMatchObject({ status: 'allowed', entries: [{ outcome: 'allow', by: 'answer' }] });
    expect((await as('GET', `/api/v1/gate-requests/${first.gate_request.id}`)).body.answer_as).toEqual([]);
    // One answer settles it; later answers change nothing.
    expect((await as('POST', path, { gate, decision: 'deny' })).status).toBe(409);
    const allowed = await ask();
    expect(allowed).toMatchObject({ allow: true, gates: [{ kind: 'dba-device', by: 'answer' }], expires_in: 0 });
    // Spent: the next use asks again.
    expect((await ask()).code).toBe('gate_pending');
    expect(await audit('alice')).toContain('gate.approved');
  });

  it('allows on timeout only when the entry says so, and announces it', async () => {
    const { gate } = await phoneGate();
    const { ask } = await asker([
      { actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate], timeout_s: 60, on_timeout: 'allow' }] } },
      { actions: ['hashbin:content:write'], require: { gates: [{ any: [gate], timeout_s: 60 }] } }
    ]);
    expect((await ask('hashbin:content:delete')).code).toBe('gate_pending');
    expect((await ask('hashbin:content:write')).code).toBe('gate_pending');
    t += 59000;
    expect((await ask('hashbin:content:delete')).code).toBe('gate_pending');
    t += 2000;
    expect(await ask('hashbin:content:delete')).toMatchObject({ allow: true, by_timeout: true, gates: [{ by: 'timeout' }] });
    expect(await ask('hashbin:content:write')).toMatchObject({ allow: false, code: 'gate_denied', reasons: ['gate_denied'] });
    expect(await audit('alice')).toEqual(expect.arrayContaining(['gate.allowed_by_timeout', 'gate.denied']));
    await settle(env);
  });

  it('denies at once when the gate was deleted, even on an allow-on-timeout entry', async () => {
    const { gate } = await phoneGate();
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate], timeout_s: 60, on_timeout: 'allow' }] } }]);
    expect((await ask()).code).toBe('gate_pending');
    await call(env, 'DELETE', `/api/v1/gates/${gate}`, { auth: 'alice' });
    expect(await ask()).toMatchObject({ allow: false, code: 'gate_denied' });
    t += 61000;
    // A new request after the old one's time is over still has no gate to wait for.
    expect(await ask()).toMatchObject({ allow: false, code: 'gate_denied' });
  });

  it('needs every entry, and any gate of an entry', async () => {
    const a = await phoneGate('alice', 'Phone A'); const b = await phoneGate('alice', 'Phone B');
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [a.gate, 'owner'] }, { any: [b.gate] }] } }]);
    const { id } = (await ask()).gate_request;
    await call(env, 'POST', `/api/v1/gate-requests/${id}/answer`, { auth: 'alice', body: { gate: 'owner', decision: 'allow' } });
    expect((await ask()).code).toBe('gate_pending');
    // Phone A's entry is settled by the owner already.
    expect((await a.as('POST', `/api/v1/gate-requests/${id}/answer`, { gate: a.gate, decision: 'allow' })).status).toBe(409);
    await b.as('POST', `/api/v1/gate-requests/${id}/answer`, { gate: b.gate, decision: 'allow' });
    expect((await ask()).allow).toBe(true);
  });

  it('charges the gates\' owner per gate contacted', async () => {
    const { gate } = await phoneGate();
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate, 'owner'] }] } }]);
    const before = await balance('alice');
    await ask(); await ask();
    expect(before - await balance('alice')).toBe(2 * price('gate'));
  });

  it('sends nothing it cannot pay for: the entry waits for its timeout (D13)', async () => {
    // carol can pay for exactly her gate's device and the asking device, then nothing more.
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'carol', body: { amount_microdollars: 2 * price('issue') } });
    const { gate } = await phoneGate('carol');
    const { ask } = await asker([
      { actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate], timeout_s: 30, on_timeout: 'allow' }] } },
      { actions: ['hashbin:content:write'], require: { gates: [{ any: [gate], timeout_s: 30 }] } }
    ], 'carol');
    const pending = await ask('hashbin:content:delete');
    const request = (await call(env, 'GET', `/api/v1/gate-requests/${pending.gate_request.id}`, { auth: 'carol' })).body;
    expect(request.entries[0].gates[0].delivery).toBe('unpaid');
    await ask('hashbin:content:write');
    t += 31000;
    expect((await ask('hashbin:content:delete')).allow).toBe(true);
    expect((await ask('hashbin:content:write')).code).toBe('gate_denied');
  });

  it('lets one approval cover repeated uses for gates_reuse_s', async () => {
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: ['owner'] }], gates_reuse_s: 600 } }]);
    const { id } = (await ask()).gate_request;
    await call(env, 'POST', `/api/v1/gate-requests/${id}/answer`, { auth: 'alice', body: { gate: 'owner', decision: 'allow' } });
    expect((await ask()).allow).toBe(true);
    t += 500000;
    expect((await ask()).allow).toBe(true);
    t += 101000;
    expect((await ask()).code).toBe('gate_pending');
  });

  it('refuses a device that keeps asking instead of letting it force a timeout', async () => {
    const { gate } = await phoneGate();
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate], timeout_s: 10, on_timeout: 'allow' }] } }]);
    for (let i = 0; i < 10; i++) expect((await ask('hashbin:content:delete', `r${i}`)).code).toBe('gate_pending');
    expect(await ask('hashbin:content:delete', 'r10')).toMatchObject({ allow: false, code: 'gate_rate_limited' });
  });

  it('prunes requests once their time is over', async () => {
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { step_up: true } }]);
    await ask();
    const account = [...env.ACCOUNTS.objects.values()].find(o => [...o.storage.rows.keys()].some(k => k.startsWith('gatereq:')));
    // Unanswered, it is kept 5 minutes past its deadline for the site's next retry, then pruned.
    t += 601000 + 300000;
    await runAlarms(env);
    expect([...account.storage.rows.keys()].some(k => k.startsWith('gatereq:'))).toBe(false);
  });
});

describe('audience gate policy (G3)', () => {
  /** hashbin.org (owned by the operator) requires gates on content:delete. */
  async function policy(gates) {
    const current = (await call(env, 'GET', '/api/v1/audiences/hashbin.org')).body;
    const catalog = current.catalog.map(e => e.action === 'hashbin:content:delete' ? { ...e, gates } : e);
    const changed = await call(env, 'PATCH', '/api/v1/audiences/hashbin.org', { auth: 'operator', body: { catalog } });
    expect(changed.status, JSON.stringify(changed.body)).toBe(200);
    // Online decisions cache audience records for a minute.
    t += 61000;
  }

  it('validates policies in the catalog and publishes them', async () => {
    const current = (await call(env, 'GET', '/api/v1/audiences/hashbin.org')).body;
    const bad = current.catalog.map(e => e.action === 'hashbin:content:delete' ? { ...e, gates: { require: true, kinds: ['sms'] } } : e);
    expect((await call(env, 'PATCH', '/api/v1/audiences/hashbin.org', { auth: 'operator', body: { catalog: bad } })).body.code).toBe('invalid_catalog');
    await policy({ require: true, kinds: ['dba-device'], fail_open: false });
    const entry = (await call(env, 'GET', '/api/v1/audiences/hashbin.org')).body.catalog.find(e => e.action === 'hashbin:content:delete');
    expect(entry.gates).toEqual({ require: true, kinds: ['dba-device'], fail_open: false });
  });

  it('refuses to issue an ungated grant, or gates of the wrong kind, for a gated action', async () => {
    await policy({ require: true, kinds: ['dba-device'] });
    const issue = grants => call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: newKey.publicJwk, aud: ['hashbin.org'], grants } });
    const newKey = await newDevice();
    const ungated = await issue([{ actions: ['hashbin:content:delete'] }]);
    expect(ungated).toMatchObject({ status: 400, body: { code: 'gate_required', grant_index: 0, action: 'hashbin:content:delete', policy: { require: true, kinds: ['dba-device'] } } });
    expect((await issue([{ actions: ['hashbin:content:delete'], require: { step_up: true } }])).body.code).toBe('gate_required');
    const { gate } = await phoneGate();
    expect((await issue([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate] }] } }])).status).toBe(200);
  });

  it('applies at once to credentials issued before the policy', async () => {
    const { ask } = await asker([{ actions: ['hashbin:content:delete'] }, { actions: ['hashbin:content:write'] }]);
    expect((await ask()).allow).toBe(true);
    await policy({ require: true });
    expect(await ask()).toMatchObject({ allow: false, code: 'forbidden', reasons: ['gate_required'] });
    expect((await ask('hashbin:content:write')).allow).toBe(true);
  });

  it('refuses allows by timeout where the audience forbids fail-open', async () => {
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: ['owner'], timeout_s: 30, on_timeout: 'allow' }] } }]);
    await policy({ fail_open: false });
    expect((await ask()).code).toBe('gate_pending');
    t += 31000;
    expect(await ask()).toMatchObject({ allow: false, code: 'by_timeout_refused', reasons: ['by_timeout_refused'] });
  });
});

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

describe('sign-in gates (G6)', () => {
  const redirect_uri = 'https://cronly.org/auth/dba/callback';
  /** Sign in to cronly.org as alice: POST /oauth/authorize, and the token exchange when it passes. */
  async function signIn(extra = {}, as = 'alice') {
    const verifier = 'v'.repeat(43);
    const challenge = await (await import('../packages/verify/src/index.js')).sha256b64u(verifier);
    const body = { client_id: 'cronly.org', redirect_uri, response_type: 'code', scope: 'openid', code_challenge: challenge, code_challenge_method: 'S256', approve: true, ...extra };
    const consent = await call(env, 'POST', '/oauth/authorize', { auth: as, body });
    if (consent.body.pending || !new URL(consent.body.redirect).searchParams.get('code')) return consent.body;
    const form = new URLSearchParams({ grant_type: 'authorization_code', code: new URL(consent.body.redirect).searchParams.get('code'), redirect_uri, client_id: 'cronly.org', code_verifier: verifier });
    const token = await call(env, 'POST', '/oauth/token', { body: form.toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    return { ...consent.body, id_token: decodeJws(token.body.id_token).payload };
  }
  const error = result => new URL(result.redirect).searchParams.get('error_description');

  it('signs in at once without gates (acr session), and refuses acr_values it cannot meet', async () => {
    expect((await signIn()).id_token).toMatchObject({ acr: 'urn:devicebasedauth.org:acr:session', amr: ['session'] });
    expect(error(await signIn({ acr_values: 'urn:devicebasedauth.org:acr:gated' }))).toMatch(/acr_not_met/);
  });

  it('refuses the owner gate for sign-in, and validates entries', async () => {
    expect((await call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: 'alice', body: { default: [{ any: ['owner'] }] } })).body.code).toBe('invalid_gates');
    expect((await call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: 'alice', body: { default: [{ any: ['gate_NOSUCHGATE'] }] } })).body.code).toBe('unknown_gate');
  });

  it('waits for a device gate with number matching, then puts the gates in the ID token', async () => {
    const { gate, as } = await phoneGate();
    expect((await call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: 'alice', body: { audiences: { 'cronly.org': [{ any: [gate], timeout_s: 120 }] } } })).status).toBe(200);
    const pending = await signIn();
    expect(pending).toMatchObject({ pending: true, gate_request: { purpose: 'sign_in', action: 'sign_in', audience: 'cronly.org', number: expect.stringMatching(/^\d\d$/) } });
    expect((await signIn()).gate_request.id).toBe(pending.gate_request.id);
    // The approver does not see the number; it types what the sign-in page shows.
    expect((await as('GET', `/api/v1/gate-requests/${pending.gate_request.id}`)).body.number).toBeUndefined();
    const path = `/api/v1/gate-requests/${pending.gate_request.id}/answer`;
    const wrong = pending.gate_request.number === '10' ? '11' : '10';
    expect((await as('POST', path, { gate, decision: 'allow', number: wrong })).body.code).toBe('wrong_number');
    expect((await as('POST', path, { gate, decision: 'allow', number: pending.gate_request.number })).body.status).toBe('allowed');
    const done = await signIn({ acr_values: 'urn:devicebasedauth.org:acr:gated' });
    expect(done.id_token).toMatchObject({ acr: 'urn:devicebasedauth.org:acr:gated', amr: ['session', 'swk', 'mfa'], dba_gates: [{ kind: 'dba-device', by: 'answer' }] });
    // Spent: the next sign-in asks again.
    expect((await signIn()).pending).toBe(true);
  });

  it('returns access_denied when the gate refuses, and honours acr_values against a timeout', async () => {
    const { gate, as } = await phoneGate();
    await call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: 'alice', body: { default: [{ any: [gate], timeout_s: 30, on_timeout: 'allow' }] } });
    const pending = await signIn();
    await as('POST', `/api/v1/gate-requests/${pending.gate_request.id}/answer`, { gate, decision: 'deny' });
    const denied = await signIn();
    expect(new URL(denied.redirect).searchParams.get('error')).toBe('access_denied');
    // After the denial's time, a new request; nobody answers it.
    t += 31000;
    expect((await signIn()).pending).toBe(true);
    t += 31000;
    // Allowed by silence: not enough for a site that asks for an answered sign-in…
    expect(error(await signIn({ acr_values: 'urn:devicebasedauth.org:acr:gated' }))).toMatch(/acr_not_met/);
    // …and marked as such for one that does not.
    expect((await signIn()).id_token).toMatchObject({ acr: 'urn:devicebasedauth.org:acr:gated-timeout', amr: ['session'], dba_gates: [{ by: 'timeout' }] });
  });

  it('lets a site require sign-in gates', async () => {
    const changed = await call(env, 'PATCH', '/api/v1/audiences/cronly.org', { auth: 'operator', body: { sign_in_gates: { require: true, kinds: ['totp', 'webauthn'] } } });
    expect(changed.status).toBe(200);
    t += 61000;
    expect(error(await signIn())).toMatch(/requires a sign-in gate/);
    const { gate } = await phoneGate();
    await call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: 'alice', body: { default: [{ any: [gate] }] } });
    expect(error(await signIn())).toMatch(/other kinds/);
  });
});

describe('loosening sign-in gates (G6, finished in G9)', () => {
  const put = body => call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: 'alice', body });

  it('tightens at once, but loosening waits for the current gates, which may refuse', async () => {
    const { gate, as } = await phoneGate();
    const { gate: other } = await phoneGate('alice', 'Tablet');
    // Adding gates, or narrowing them, is never a loosening.
    expect((await put({ default: [{ any: [gate, other], timeout_s: 120, on_timeout: 'allow' }] })).status).toBe(200);
    expect((await put({ default: [{ any: [gate], timeout_s: 120 }] })).status).toBe(200);
    // Switching them off waits for the phone, for exactly this change.
    const off = await put({ default: null });
    expect(off.status).toBe(202);
    expect(off.body).toMatchObject({ status: 'pending', code: 'gate_pending', gate_request: { purpose: 'settings', action: 'sign_in_gates', retry_after: expect.any(Number) } });
    expect((await call(env, 'GET', '/api/v1/settings/sign-in-gates', { auth: 'alice' })).body.default[0].any).toEqual([gate]);
    // Another loosening is a different request, so approving one never approves the other.
    const wider = await put({ default: [{ any: [gate, other], timeout_s: 120 }] });
    expect(wider.status).toBe(202);
    expect(wider.body.gate_request.id).not.toBe(off.body.gate_request.id);
    expect((await put({ default: null })).body.gate_request.id).toBe(off.body.gate_request.id);
    const [mine] = (await as('GET', '/api/v1/gate-requests')).body.items.filter(r => r.id === off.body.gate_request.id);
    expect((await as('POST', `/api/v1/gate-requests/${mine.id}/answer`, { ...mine.answer_as[0], decision: 'allow' })).body.status).toBe('allowed');
    expect((await put({ default: null })).status).toBe(200);
    expect((await call(env, 'GET', '/api/v1/settings/sign-in-gates', { auth: 'alice' })).body.default).toBeNull();
    expect(await audit('alice')).toContain('sign_in_gates.changed');
    // The other change is still waiting; refused, it is 403.
    await as('POST', `/api/v1/gate-requests/${wider.body.gate_request.id}/answer`, { gate, decision: 'deny' });
  });

  it('refuses a loosening the gates turn down, and never lets silence or an API key switch them off', async () => {
    const { gate, as } = await phoneGate();
    expect((await put({ default: [{ any: [gate], timeout_s: 30, on_timeout: 'allow' }] })).status).toBe(200);
    const off = await put({ default: null });
    expect(off.status).toBe(202);
    // Even an allow-on-timeout entry does not pass a loosening by silence.
    t += 31000;
    expect(await put({ default: null })).toMatchObject({ status: 403, body: { code: 'by_timeout_refused' } });
    t += 5 * 60000;
    const again = await put({ default: null });
    await as('POST', `/api/v1/gate-requests/${again.body.gate_request.id}/answer`, { gate, decision: 'deny' });
    expect(await put({ default: null })).toMatchObject({ status: 403, body: { code: 'gate_denied' } });
    const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'k', scopes: ['gates:read', 'gates:write'] } })).body.secret;
    expect(await call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: `ApiKey ${key}`, body: { default: null } })).toMatchObject({ status: 403, body: { code: 'session_required' } });
  });
});

describe('dashboard sign-in gate and recovery codes (G6)', () => {
  // "LocalDev alice <session>" names a local browser session.
  const as = (session, method, path, body) => call(env, method, path, { auth: `alice ${session}`, body });

  it('needs recovery codes before a deny-on-timeout dashboard gate', async () => {
    const { gate } = await phoneGate();
    expect((await as('a', 'PUT', '/api/v1/settings/sign-in-gates', { dashboard: [{ any: [gate] }] })).body.code).toBe('recovery_codes_required');
    expect((await as('a', 'PUT', '/api/v1/settings/sign-in-gates', { dashboard: [{ any: [gate], on_timeout: 'allow' }] })).status).toBe(200);
  });

  it('locks other sessions until the gate confirms them, but never revocation', async () => {
    const { gate, as: phone } = await phoneGate();
    const codes = (await as('a', 'POST', '/api/v1/settings/recovery-codes')).body.codes;
    expect(codes).toHaveLength(10);
    expect((await as('a', 'PUT', '/api/v1/settings/sign-in-gates', { dashboard: [{ any: [gate], timeout_s: 120 }] })).status).toBe(200);
    // Session "a" made the change; it too is now held, like every session (a recent sign-in is no bypass).
    expect((await as('b', 'GET', '/api/v1/account')).body.code).toBe('sign_in_gate_required');
    expect((await as('b', 'GET', '/api/v1/session')).body).toMatchObject({ dashboard: 'locked', recovery_codes_left: 10 });
    expect((await as('b', 'GET', '/api/v1/whoami')).status).toBe(200);
    const pending = (await as('b', 'POST', '/api/v1/session/confirm', {})).body;
    expect(pending).toMatchObject({ status: 'pending', gate_request: { purpose: 'dashboard', number: expect.stringMatching(/^\d\d$/) } });
    // A locked session cannot answer gate requests (it might approve someone's step-up).
    expect((await as('b', 'POST', `/api/v1/gate-requests/${pending.gate_request.id}/answer`, { gate: 'owner', decision: 'allow' })).body.code).toBe('sign_in_gate_required');
    await phone('POST', `/api/v1/gate-requests/${pending.gate_request.id}/answer`, { gate, decision: 'allow', number: pending.gate_request.number });
    expect((await as('b', 'POST', '/api/v1/session/confirm', {})).body.status).toBe('confirmed');
    expect((await as('b', 'GET', '/api/v1/account')).status).toBe(200);
    // Another session is still locked, and can still revoke (the panic button always works).
    const cid = inspectCredential((await enroll(env, 'alice b', await newDevice())).approve.body.credential).payload.cid;
    expect((await as('c', 'GET', '/api/v1/credentials')).body.code).toBe('sign_in_gate_required');
    expect((await as('c', 'DELETE', `/api/v1/credentials/${cid}`)).status).toBe(200);
    expect((await as('c', 'POST', '/api/v1/revoke-all', { confirm: 'revoke-all' })).status).toBe(200);
  });

  it('opens with a recovery code, once per code, and tells every browser', async () => {
    const { gate } = await phoneGate();
    const codes = (await as('a', 'POST', '/api/v1/settings/recovery-codes')).body.codes;
    await as('a', 'PUT', '/api/v1/settings/sign-in-gates', { dashboard: [{ any: [gate] }] });
    expect((await as('b', 'POST', '/api/v1/session/recover', { code: 'AAAA-BBBB-CCCC' })).body.code).toBe('invalid_recovery_code');
    expect((await as('b', 'POST', '/api/v1/session/recover', { code: codes[3].toLowerCase() })).body).toMatchObject({ status: 'confirmed', recovery_codes_left: 9 });
    expect((await as('b', 'GET', '/api/v1/account')).status).toBe(200);
    expect((await as('c', 'POST', '/api/v1/session/recover', { code: codes[3] })).body.code).toBe('invalid_recovery_code');
    expect(await audit('alice b')).toContain('recovery_code.used');
  });
});

describe('periodic confirmation (G7)', () => {
  async function confirmable(gate, every_s = 600) {
    const device = await newDevice();
    const { approve } = await (async () => {
      const start = await call(env, 'POST', '/api/v1/enrollments', { body: { request: await device.enrollRequest({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], device: { name: 'Kiosk', kind: 'cli' } }) } });
      return { approve: await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: start.body.request, confirm: { gates: [{ any: [gate], timeout_s: 120 }], every_s } } }) };
    })();
    expect(approve.status, JSON.stringify(approve.body)).toBe(200);
    const credential = approve.body.credential;
    const { cid } = inspectCredential(credential).payload;
    const confirm = async () => (await call(env, 'POST', `/api/v1/credentials/${cid}/confirm`, { headers: await device.headers('POST', `/api/v1/credentials/${cid}/confirm`, credential), body: {} })).body;
    return { device, credential, cid, confirm };
  }

  it('issues every grant with require.confirmation and the confirm block', async () => {
    const { gate } = await phoneGate();
    const { credential } = await confirmable(gate);
    const { payload } = inspectCredential(credential);
    expect(payload.confirm).toEqual({ gates: [{ any: [gate], timeout_s: 120 }], every_s: 600 });
    expect(payload.grants).toEqual([{ actions: ['hashbin:content:write'], require: { confirmation: true } }]);
  });

  it('an offline verifier denies without a current confirmation and accepts one', async () => {
    const { gate, as } = await phoneGate();
    const { device, credential, cid, confirm } = await confirmable(gate);
    const { createVerifier } = await import('../packages/verify/src/index.js');
    const { worker } = await import('../test-utils/env.js');
    const verifier = createVerifier({ audience: 'hashbin.org', issuer: 'http://localhost:8787', fetch: (url, init) => worker.fetch(new Request(url, init), env), now: () => Math.floor(t / 1000) });
    const url = 'https://hashbin.org/api/content';
    const signed = async (extra = {}) => new Request(url, { method: 'POST', headers: { Authorization: `DBA ${credential}`, DPoP: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential, now: Math.floor(t / 1000) }), ...extra } });
    expect(await verifier.verifyRequest(await signed(), { action: 'hashbin:content:write' })).toMatchObject({ allow: false, reasons: [['confirmation_required']] });
    // Ask, the phone approves, ask again: a signed confirmation.
    const pending = await confirm();
    expect(pending).toMatchObject({ status: 'pending', gate_request: { purpose: 'confirm' } });
    await as('POST', `/api/v1/gate-requests/${pending.gate_request.id}/answer`, { gate, decision: 'allow' });
    const done = await confirm();
    expect(done).toMatchObject({ status: 'confirmed', by_timeout: false, confirmation: expect.stringMatching(/^ey/) });
    expect(decodeJws(done.confirmation)).toMatchObject({ header: { typ: 'dba-confirmation+jwt' }, payload: { cid, exp: Math.floor(t / 1000) + 600, gates: [{ kind: 'dba-device', by: 'answer' }] } });
    expect(await verifier.verifyRequest(await signed({ 'DBA-Confirmation': done.confirmation }), { action: 'hashbin:content:write' })).toMatchObject({ allow: true });
    // After every_s it expires.
    t += 661000;
    expect(await verifier.verifyRequest(await signed({ 'DBA-Confirmation': done.confirmation }), { action: 'hashbin:content:write' })).toMatchObject({ allow: false, reasons: [['confirmation_expired']] });
  });

  it('online checks use the account record, so stopping trust works at once; tokens never outlive it', async () => {
    const { gate, as } = await phoneGate();
    const { device, credential, cid, confirm } = await confirmable(gate);
    const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'v', scopes: ['authorize'] } })).body.secret;
    const url = 'https://hashbin.org/api/content';
    const ask = async () => (await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key}`, body: { credential, proof: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential }), request: { method: 'POST', url }, audience: 'hashbin.org', action: 'hashbin:content:write' } })).body;
    expect(await ask()).toMatchObject({ allow: false, reasons: ['confirmation_required'] });
    const tokenPath = '/api/v1/token';
    expect((await call(env, 'POST', tokenPath, { headers: await device.headers('POST', tokenPath, credential), body: { audience: 'hashbin.org' } })).body.code).toBe('confirmation_required');
    const pending = await confirm();
    await as('POST', `/api/v1/gate-requests/${pending.gate_request.id}/answer`, { gate, decision: 'allow' });
    const before = await balance('alice');
    expect((await confirm()).status).toBe('confirmed');
    expect(before - await balance('alice')).toBe(price('confirm'));
    expect((await ask()).allow).toBe(true);
    const token = (await call(env, 'POST', tokenPath, { headers: await device.headers('POST', tokenPath, credential), body: { audience: 'hashbin.org' } })).body;
    expect(decodeJws(token.access_token).payload.grants).toEqual([{ actions: ['hashbin:content:write'] }]);
    expect(token.expires_in).toBeLessThanOrEqual(600);
    expect((await call(env, 'POST', `/api/v1/credentials/${cid}/unconfirm`, { auth: 'alice', body: {} })).status).toBe(200);
    expect(await ask()).toMatchObject({ allow: false, reasons: ['confirmation_expired'] });
    const renewPath = `/api/v1/credentials/${cid}/renew`;
    expect((await call(env, 'POST', renewPath, { headers: await device.headers('POST', renewPath, credential), body: {} })).body.code).toBe('confirmation_required');
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

describe('MCP gate tools (G9)', () => {
  it('a device answers as its own gate over MCP; an API key cannot see or answer gate requests', async () => {
    const phone = await newDevice();
    const credential = (await enroll(env, 'alice', phone, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:approvals:answer'] }], name: 'Agent phone' })).approve.body.credential;
    const gate = (await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'dba-device', label: 'Agent phone', device_id: inspectCredential(credential).payload.sub } })).body.id;
    const { ask } = await asker([{ actions: ['hashbin:content:delete'], require: { gates: [{ any: [gate], timeout_s: 120 }] } }]);
    expect((await ask()).code).toBe('gate_pending');
    let id = 0;
    const tool = async (name, args = {}, auth = {}) => {
      const res = await call(env, 'POST', '/mcp', { ...auth, body: { jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name, arguments: args } } });
      return { isError: !!res.body.result.isError, value: JSON.parse(res.body.result.content[0].text) };
    };
    const asPhone = async () => ({ headers: await phone.headers('POST', '/mcp', credential) });
    const listed = await tool('list_gate_requests', {}, await asPhone());
    expect(listed.isError).toBe(false);
    const [req] = listed.value.items;
    expect(req.answer_as).toEqual([{ entry: 0, gate }]);
    const answered = await tool('answer_gate_request', { id: req.id, decision: 'allow', ...req.answer_as[0] }, await asPhone());
    expect(answered).toMatchObject({ isError: false, value: { status: 'allowed' } });
    expect(await ask()).toMatchObject({ allow: true });

    const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'agent', scopes: ['gates:read', 'credentials:read'] } })).body.secret;
    const gates = await tool('list_gates', {}, { auth: `ApiKey ${key}` });
    expect(gates.value.items.map(g => g.id)).toEqual(['owner', gate]);
    expect(await tool('list_gate_requests', {}, { auth: `ApiKey ${key}` })).toMatchObject({ isError: true, value: { code: 'insufficient_scope' } });
    expect(await tool('answer_gate_request', { id: req.id, decision: 'allow', gate: 'owner' }, { auth: `ApiKey ${key}` })).toMatchObject({ isError: true, value: { code: 'insufficient_scope' } });
  });
});
