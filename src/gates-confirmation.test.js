import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv, call, newDevice } from '../test-utils/env.js';
import { inspectCredential, createProof, decodeJws } from '../packages/verify/src/index.js';
import { price } from './utils/pricing.js';
import { gateHelpers } from '../test-utils/gates.js';

// STATUS B7 (done/additional_gates.md): periodic confirmation (G7), where a credential's grants
// hold only while its gates have confirmed it recently.

let env; const realNow = Date.now; let t;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  env = await testEnv();
  for (const who of ['alice', 'operator']) await call(env, 'POST', '/api/v1/dev/deposit', { auth: who, body: { amount_microdollars: 1_000_000 } });
});
afterEach(() => { Date.now = realNow; });
const { balance, phoneGate } = gateHelpers(() => env);

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
