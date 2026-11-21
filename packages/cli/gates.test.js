import { describe, it, expect } from 'vitest';
import { UsageError } from './errors.js';
import {
  needsConfirmation, currentConfirmation, waitForConfirmation, confirmationHeaders, formatGateList, gateInputFromOptions, describeGateRequest, answerFor,
  pendingGate, waitThroughGates, describePendingGate
} from './gates.js';
import { createClient } from './client.js';
import { newDeviceKey } from './device-key.js';
import { inspectCredential } from '../verify/src/index.js';
import { testEnv, call, worker, ORIGIN } from '../../test-utils/env.js';

describe('gates, approvals and confirmation (STATUS B7 G9)', () => {
  it('builds gate bodies from options and refuses kinds that need the dashboard', () => {
    expect(gateInputFromOptions({ kind: 'dba-device', label: 'Phone', device: 'dev_abcdefgh' })).toEqual({ kind: 'dba-device', label: 'Phone', device_id: 'dev_abcdefgh' });
    expect(gateInputFromOptions({ kind: 'webhook', label: 'Ops', url: 'https://ops.example.com/dba', 'public-jwk': '{"kty":"EC"}' })).toEqual({ kind: 'webhook', label: 'Ops', url: 'https://ops.example.com/dba', public_jwk: { kty: 'EC' } });
    expect(() => gateInputFromOptions({ kind: 'totp', label: 'x' })).toThrow(/dashboard/);
    expect(() => gateInputFromOptions({ kind: 'dba-device', label: 'x' })).toThrow(/--device/);
    expect(() => gateInputFromOptions({ kind: 'webhook', label: 'x', url: 'https://a.example', 'public-jwk': 'nope' })).toThrow(/JSON Web Key/);
    expect(() => gateInputFromOptions({ kind: 'dba-device', device: 'dev_x' })).toThrow(/--label/);
  });

  it('prints gates and requests without control characters', () => {
    const gates = formatGateList([{ id: 'owner', kind: 'owner', label: 'Account owner' }, { id: 'gate_abcdefgh', kind: 'dba-device', state: 'active', label: 'Ph\u001b[2Jone', device_id: 'dev_x' }]);
    expect(gates[0]).toMatch(/^GATE\s+KIND\s+STATE\s+LABEL$/);
    expect(gates[2]).toMatch(/^gate_abcdefgh\s+dba-device\s+active\s+Ph\[2Jone \(dev_x\)$/);
    expect(formatGateList([])).toEqual(['No gates.']);
    const lines = describeGateRequest({ id: 'gtr_1', purpose: 'authorize', device_name: 'Laptop\u0007', action: 'hashbin:content:delete', audience: 'hashbin.org', number: '42', status: 'pending', entries: [{ expires_in: 90, on_timeout: 'allow', outcome: null }] });
    expect(lines).toEqual(['gtr_1  Laptop asks to hashbin:content:delete on hashbin.org', '  Number: 42 (check it matches what the device shows)', '  Status: pending, 90 s left (then allowed by timeout)']);
    expect(describeGateRequest({ id: 'gtr_2', purpose: 'sign_in', audience: 'cronly.org', status: 'pending', entries: [] })[1]).toMatch(/--number NN/);
  });

  it('picks the device\'s own gate to answer with', () => {
    const req = { id: 'gtr_1', answer_as: [{ entry: 0, gate: 'gate_a' }, { entry: 1, gate: 'gate_b' }] };
    expect(answerFor(req, { decision: 'allow' })).toEqual({ entry: 0, gate: 'gate_a', decision: 'allow' });
    expect(answerFor(req, { decision: 'allow', entry: 1, number: '07' })).toEqual({ entry: 1, gate: 'gate_b', decision: 'allow', number: '07' });
    expect(answerFor(req, { decision: 'deny', number: '07' })).toEqual({ entry: 0, gate: 'gate_a', decision: 'deny' });
    expect(() => answerFor(req, { decision: 'allow', entry: 2 })).toThrow(/no gate that can still answer/);
    expect(() => answerFor({ id: 'x' }, { decision: 'allow' })).toThrow(UsageError);
    expect(() => answerFor(req, { decision: 'allow', number: '7' })).toThrow(/two-digit/);
    expect(() => answerFor(req, { decision: 'maybe' })).toThrow(/allow or deny/);
  });

  it('answers as a dba-device gate, and confirms a credential, against the Worker', async () => {
    const env = await testEnv();
    let now = Date.now();
    const client = createClient({ origin: ORIGIN, fetch: (url, init) => worker.fetch(new Request(url, init), env) });
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
    // The phone: a device holding dba:approvals:answer, registered as a gate with an API key.
    const phone = await newDeviceKey();
    const phoneCred = (await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: phone.publicJwk, aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:approvals:answer'] }] } })).body.credential;
    const apiKey = (await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'cli', scopes: ['gates:read', 'gates:write'] } })).body.secret;
    const gate = await client.request('POST', '/api/v1/gates', { apiKey, body: gateInputFromOptions({ kind: 'dba-device', label: 'Phone', device: inspectCredential(phoneCred).payload.sub }) });
    expect(formatGateList((await client.request('GET', '/api/v1/gates', { apiKey })).items)[2]).toContain(gate.id);

    // The laptop: a credential that needs confirmation by the phone every hour.
    const laptop = await newDeviceKey();
    const issued = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: laptop.publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], confirm: { gates: [{ any: [gate.id], timeout_s: 120 }], every_s: 3600 } } });
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    const device = { key: laptop, credential: issued.body.credential };
    const payload = inspectCredential(device.credential).payload;
    expect(needsConfirmation(payload)).toBe(true);
    expect(currentConfirmation(null, payload)).toBeNull();

    // While the laptop waits, the phone lists the request and allows it.
    const phoneDevice = { key: phone, credential: phoneCred };
    let pending = null; let polls = 0;
    const result = await waitForConfirmation(client, device, {
      onPending: req => { pending = req; },
      clock: () => now,
      sleep: async ms => {
        now += ms;
        if (++polls !== 2) return;
        const { items } = await client.request('GET', '/api/v1/gate-requests', { device: phoneDevice });
        expect(items).toHaveLength(1);
        expect(describeGateRequest(items[0])[0]).toContain('confirm it is still trusted');
        const req = await client.request('GET', `/api/v1/gate-requests/${items[0].id}`, { device: phoneDevice });
        await client.request('POST', `/api/v1/gate-requests/${req.id}/answer`, { device: phoneDevice, body: answerFor(req, { decision: 'allow' }) });
      }
    });
    expect(pending).toMatchObject({ purpose: 'confirm', retry_after: expect.any(Number) });
    expect(result).toMatchObject({ status: 'confirmed', by_timeout: false });
    const confirmation = currentConfirmation(result.confirmation, payload, { now: Math.floor(now / 1000) });
    expect(confirmation).toBe(result.confirmation);
    expect(confirmationHeaders(confirmation)).toEqual({ 'DBA-Confirmation': confirmation });
    expect(confirmationHeaders(null)).toEqual({});
    // It runs out: ask again 30 s before it ends. Another credential's confirmation is not used.
    expect(currentConfirmation(confirmation, payload, { now: result.expires_at - 29 })).toBeNull();
    expect(currentConfirmation(confirmation, { ...payload, cid: 'crd_other' })).toBeNull();

    // A denial comes back as denied, and a wait with nobody answering as a timeout.
    const denied = await waitForConfirmation(client, device, {
      sleep: async () => {
        const [req] = (await client.request('GET', '/api/v1/gate-requests', { device: phoneDevice })).items;
        if (req) await client.request('POST', `/api/v1/gate-requests/${req.id}/answer`, { device: phoneDevice, body: answerFor(req, { decision: 'deny' }) });
      }
    });
    expect(denied).toMatchObject({ status: 'denied', code: 'gate_denied' });
    await expect(client.request('DELETE', `/api/v1/gates/${gate.id}`, { device: phoneDevice })).rejects.toMatchObject({ status: 403 });
    await client.request('DELETE', `/api/v1/gates/${gate.id}`, { apiKey });
  });

  it('gives up waiting for a confirmation at the deadline', async () => {
    let now = 0;
    const client = { request: async () => ({ status: 'pending', gate_request: { id: 'gtr_x', retry_after: 2 } }) };
    const device = { credential: [{ alg: 'ES256' }, { cid: 'crd_x' }].map(p => Buffer.from(JSON.stringify(p)).toString('base64url')).join('.') + '.sig' };
    const result = await waitForConfirmation(client, device, { waitSeconds: 5, clock: () => now, sleep: async ms => { now += ms; } });
    expect(result).toEqual({ status: 'timeout', gate_request: { id: 'gtr_x', retry_after: 2 } });
    expect(now).toBe(4000);
  });
});

// The gate_pending side of `dba curl --dba-wait`; curl.test.js tests the option itself.
describe('dba curl --dba-wait (STATUS B7 G9)', () => {
  it('knows a gate_pending answer from any other', () => {
    expect(pendingGate(403, JSON.stringify({ code: 'gate_pending', gate_request: { id: 'gtr_1', retry_after: 2 } }))).toEqual({ id: 'gtr_1', retry_after: 2 });
    expect(pendingGate(403, JSON.stringify({ code: 'gate_pending' }))).toEqual({});
    expect(pendingGate(403, JSON.stringify({ code: 'gate_denied' }))).toBeNull();
    expect(pendingGate(200, JSON.stringify({ code: 'gate_pending' }))).toBeNull();
    expect(pendingGate(403, '<html>')).toBeNull();
  });

  it('retries every retry_after seconds until the site answers otherwise or the wait runs out', async () => {
    let now = 0; const sleeps = []; const told = [];
    const pending = { status: 403, body: JSON.stringify({ code: 'gate_pending', gate_request: { id: 'gtr_9', retry_after: 3 } }) };
    const answers = [pending, pending, { status: 200, body: 'ok' }];
    const result = await waitThroughGates(async () => answers.shift(), { waitSeconds: 60, onPending: g => told.push(g.id), sleep: async ms => { sleeps.push(ms); now += ms; }, clock: () => now });
    expect(result).toEqual({ response: { status: 200, body: 'ok' }, gaveUp: false });
    expect(sleeps).toEqual([3000, 3000]);
    expect(told).toEqual(['gtr_9']);
    now = 0;
    const timedOut = await waitThroughGates(async () => pending, { waitSeconds: 10, sleep: async ms => { now += ms; }, clock: () => now });
    expect(timedOut.gaveUp).toBe(true);
    expect(now).toBe(9000);
  });

  it('says where to approve, without the site\'s control characters', () => {
    expect(describePendingGate({ id: 'gtr_1\u001b[2J', approve_url: 'https://devicebasedauth.org/gate.html#dbag_x' })).toBe("dba: waiting for this request's gates (request gtr_1[2J). Approve it at https://devicebasedauth.org/gate.html#dbag_x, or from the dashboard's Approvals page or `dba approvals` on a gate device.");
    expect(describePendingGate({ approve_url: 'javascript:alert(1)' })).not.toContain('javascript');
  });
});
