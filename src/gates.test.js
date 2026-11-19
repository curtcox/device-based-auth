import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv, call, newDevice, enroll, settle, runAlarms } from '../test-utils/env.js';
import { inspectCredential, createProof } from '../packages/verify/src/index.js';
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
    expect((await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'webhook', label: 'x' } })).body.code).toBe('gate_kind_not_available');
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
    expect(mine[0]).toMatchObject({ id: first.gate_request.id, device_id: deviceId, action: 'hashbin:content:delete', status: 'pending' });
    // The owner may not answer for the phone's gate, and an API key may not answer at all.
    const path = `/api/v1/gate-requests/${first.gate_request.id}/answer`;
    expect((await call(env, 'POST', path, { auth: 'alice', body: { gate, decision: 'allow' } })).body.code).toBe('not_the_gate');
    const answered = await as('POST', path, { gate, decision: 'allow' });
    expect(answered.body).toMatchObject({ status: 'allowed', entries: [{ outcome: 'allow', by: 'answer' }] });
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
