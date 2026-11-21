/**
 * Helpers shared by the gate tests (src/gates-*.test.js, STATUS B7). Each test file builds its own
 * env and fake clock in beforeEach, so the helpers read the env through a getter rather than
 * holding one that the next test would replace.
 */
import { expect } from 'vitest';
import { call, newDevice, enroll } from './env.js';
import { inspectCredential, createProof } from '../packages/verify/src/index.js';

/**
 * Binds the gate test helpers to a test file's current env.
 * @param {() => object} getEnv returns the env the running test uses
 */
export function gateHelpers(getEnv) {
  const balance = async who => (await call(getEnv(), 'GET', '/api/v1/account', { auth: who })).body.balance_microdollars;
  const audit = async who => (await call(getEnv(), 'GET', '/api/v1/audit', { auth: who })).body.items.map(e => e.type);

  /** A phone enrolled as a dba-device gate for `owner`, able to answer gate requests. */
  async function phoneGate(owner = 'alice', label = 'Phone') {
    const env = getEnv();
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
    const env = getEnv();
    const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'verifier', scopes: ['authorize'] } })).body.secret;
    const device = await newDevice();
    const issued = (await enroll(env, owner, device, { grants })).approve;
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    const credential = issued.body.credential;
    const url = 'https://hashbin.org/api/content';
    const ask = async (action = 'hashbin:content:delete', resource) => (await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key}`, body: { credential, proof: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential }), request: { method: 'POST', url }, audience: 'hashbin.org', action, resource } })).body;
    return { ask, credential, deviceId: inspectCredential(credential).payload.sub };
  }

  return { balance, audit, phoneGate, asker };
}
