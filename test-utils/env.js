import { namespace } from './storage.js';
import { AccountDO } from '../src/durable-objects/account-do.js';
import { StatusListDO } from '../src/durable-objects/status-list-do.js';
import { RegistryDO } from '../src/durable-objects/registry-do.js';
import { EnrollmentDO } from '../src/durable-objects/enrollment-do.js';
import { SafetyDO } from '../src/durable-objects/safety-do.js';
import worker from '../src/index.js';
import { generateKeyPair, exportPublicJwk, jwkThumbprint, signJws, createProof } from '../packages/verify/src/index.js';

export const ORIGIN = 'http://localhost:8787';

/** An in-memory R2 bucket. */
export function memoryBucket() {
  const objects = new Map();
  return { objects, async put(key, value, options = {}) { objects.set(key, { value: String(value), httpMetadata: options.httpMetadata }); }, async get(key) { const o = objects.get(key); return o ? { text: async () => o.value, httpMetadata: o.httpMetadata } : null; }, async delete(key) { objects.delete(key); } };
}

let issuerKeysJson;
/** A complete local environment with real Durable Object classes on in-memory storage. */
export async function testEnv(overrides = {}) {
  if (!issuerKeysJson) {
    const pair = await generateKeyPair(true);
    issuerKeysJson = JSON.stringify([{ kid: 'test-1', jwk: await crypto.subtle.exportKey('jwk', pair.privateKey) }]);
  }
  const env = { ENVIRONMENT: 'local', APP_ORIGIN: ORIGIN, ISSUER: ORIGIN, STATUS_ORIGIN: `${ORIGIN}/status`, STATUS_SHARDS: '2', TOKEN_SIGNING_KEY: 'test-token-key', GATE_SEALING_KEYS: JSON.stringify([{ kid: 'test-sealing-1', key: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))) }]), ISSUER_KEYS: issuerKeysJson, OPERATOR_ACCOUNT: 'operator', STATUS_BUCKET: memoryBucket(), ...overrides };
  env.ACCOUNTS = namespace(AccountDO, env); env.STATUS = namespace(StatusListDO, env); env.REGISTRY = namespace(RegistryDO, env); env.ENROLLMENTS = namespace(EnrollmentDO, env); env.SAFETY = namespace(SafetyDO, env);
  return env;
}

/** Fire every pending alarm (status-list publishes, outbox delivery, pruning). */
export async function runAlarms(env) {
  for (const ns of [env.ACCOUNTS, env.STATUS, env.ENROLLMENTS]) for (const object of ns.objects.values()) {
    if (object.storage.alarm !== null && object.alarm) { object.storage.alarm = null; await object.alarm(); }
  }
}

/** Wait for work Durable Objects run after responding (security notices). */
export async function settle(env) {
  for (let pending = true; pending;) {
    const all = [...env.ACCOUNTS.objects.values()].flatMap(o => [...(o.inflight || [])]);
    pending = all.length > 0;
    await Promise.all(all);
  }
}

/** Call the Worker like a client would. */
export async function call(env, method, path, { auth, body, headers = {} } = {}) {
  const init = { method, headers: { ...headers } };
  if (auth) init.headers.Authorization = auth.startsWith('ApiKey ') || auth.startsWith('DBA ') || auth.startsWith('Bearer ') ? auth : `LocalDev ${auth}`;
  if (body !== undefined) { init.body = typeof body === 'string' ? body : JSON.stringify(body); init.headers['Content-Type'] ||= 'application/json'; }
  const response = await worker.fetch(new Request(`${ORIGIN}${path}`, init), env);
  const text = await response.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: response.status, body: json, headers: response.headers };
}

/** A device with a non-extractable key, able to sign enrollment requests and proofs. */
export async function newDevice() {
  const pair = await generateKeyPair(false);
  const publicJwk = await exportPublicJwk(pair.publicKey);
  const device = { privateKey: pair.privateKey, publicJwk, jkt: await jwkThumbprint(publicJwk) };
  device.enrollRequest = (payload) => signJws({ typ: 'dba-enroll+jwt', jwk: publicJwk }, { iat: Math.floor(Date.now() / 1000), ...payload }, pair.privateKey);
  device.headers = async (method, path, credential, nonce) => ({ Authorization: `DBA ${credential}`, DPoP: await createProof({ privateKey: pair.privateKey, publicJwk, method, url: `${ORIGIN}${path}`, credential, nonce }) });
  return device;
}

/** Enroll a device end to end: request, owner approval, returns the credential. */
export async function enroll(env, owner, device, { aud = ['hashbin.org'], grants = [{ actions: ['hashbin:content:write'] }], lifetime_seconds, name = 'Test device' } = {}) {
  const start = await call(env, 'POST', '/api/v1/enrollments', { body: { request: await device.enrollRequest({ aud, grants, device: { name, kind: 'cli' }, ...(lifetime_seconds ? { lifetime_seconds } : {}) }) } });
  if (start.status !== 200) throw new Error(`enroll start failed: ${JSON.stringify(start.body)}`);
  const approve = await call(env, 'POST', '/api/v1/enrollments/approve', { auth: owner, body: { request: start.body.request } });
  return { start: start.body, approve };
}

export { worker };

/**
 * Count Durable Object requests and storage row writes (puts and deletes) made from now on, to
 * check an operation against its worst case in src/utils/cost-policy.js. Returns a reader.
 */
export function meter(env) {
  const counts = { doRequests: 0, rowWrites: 0, byOp: [] };
  for (const name of ['ACCOUNTS', 'STATUS', 'REGISTRY', 'ENROLLMENTS', 'SAFETY']) {
    const ns = env[name]; const get = ns.get.bind(ns);
    ns.get = id => {
      const object = get(id);
      if (!object.metered) {
        object.metered = true;
        const fetch = object.fetch.bind(object);
        object.fetch = async request => { const args = await request.clone().json(); counts.doRequests++; counts.byOp.push(`${name}:${args.op}`); return fetch(request); };
        // A restarted object (namespace.restart) shares its storage, which is counted once.
        const { storage } = object;
        if (!storage.metered) {
          storage.metered = true;
          const put = storage.put.bind(storage); const del = storage.delete.bind(storage);
          storage.put = async (key, value) => { counts.rowWrites++; return put(key, value); };
          storage.delete = async key => { counts.rowWrites += Array.isArray(key) ? key.length : 1; return del(key); };
        }
      }
      return object;
    };
  }
  const start = { doRequests: 0, rowWrites: 0 };
  return {
    reset() { start.doRequests = counts.doRequests; start.rowWrites = counts.rowWrites; counts.byOp.length = 0; },
    read() { return { doRequests: counts.doRequests - start.doRequests, rowWrites: counts.rowWrites - start.rowWrites, ops: [...counts.byOp] }; }
  };
}
