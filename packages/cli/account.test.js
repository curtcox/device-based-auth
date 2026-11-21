import { describe, it, expect, beforeEach } from 'vitest';
import { testEnv, call, ORIGIN, worker } from '../../test-utils/env.js';
import { inspectCredential } from '../verify/src/index.js';
import { createClient } from './client.js';
import { newDeviceKey } from './device-key.js';
import { depositCents, recoveryVia, startSignup, startRecovery, pollTicket } from './account.js';

// `dba signup` and `dba recover` (STATUS B9): their network part against the real Worker in
// memory, through the CLI's own HTTP client. A local server without Stripe pays through the
// development route, as the command does.

let env; let client;
const device = { name: 'build box', kind: 'cli', keyProtection: 'software' };
const noSleep = { sleep: async () => {} };
beforeEach(async () => {
  env = await testEnv();
  client = createClient({ origin: ORIGIN, fetch: (url, init) => worker.fetch(new Request(url, init), env) });
});

async function signedUp() {
  const key = await newDeviceKey();
  const started = await startSignup(client, key, { credit: 500, device });
  await call(env, 'POST', '/api/v1/dev/signup-paid', { body: { ticket: started.ticket } });
  const done = await pollTicket(client, key, '/api/v1/signup/complete', started.ticket, { waitSeconds: 0, ...noSleep });
  return { key, account: started.account, credential: done.credential };
}

describe('dba signup and dba recover (B9)', () => {
  it('reads deposits and recovery options', () => {
    expect(depositCents()).toBe(500);
    expect(depositCents('12.50')).toBe(1250);
    expect(depositCents('$20')).toBe(2000);
    expect(() => depositCents('five')).toThrow(/dollars/);
    expect(recoveryVia({ account: 'acct_x', code: 'C' })).toBe('code');
    expect(recoveryVia({ email: 'a@example.com' })).toBe('email');
    expect(recoveryVia({ account: 'acct_x' })).toBe('gate');
    expect(() => recoveryVia({ code: 'C' })).toThrow(/--account/);
    expect(() => recoveryVia({ via: 'email', account: 'acct_x' })).toThrow(/--email/);
    expect(() => recoveryVia({ via: 'sms', account: 'acct_x' })).toThrow(/--via/);
  });

  it('signs up: pending until paid, then a dashboard credential for a cli device', async () => {
    const key = await newDeviceKey();
    const started = await startSignup(client, key, { credit: 500, device });
    expect(started).toMatchObject({ local_payment: true, account: expect.stringMatching(/^acct_/) });
    const waiting = await pollTicket(client, key, '/api/v1/signup/complete', started.ticket, { waitSeconds: 0, ...noSleep });
    expect(waiting).toMatchObject({ status: 'timeout', last: { status: 'pending' } });
    await call(env, 'POST', '/api/v1/dev/signup-paid', { body: { ticket: started.ticket } });
    const done = await pollTicket(client, key, '/api/v1/signup/complete', started.ticket, { waitSeconds: 0, ...noSleep });
    expect(inspectCredential(done.credential).payload).toMatchObject({ acct: started.account, grants: [{ actions: ['dba:session'] }], device: { name: 'build box', kind: 'cli', key_protection: 'software' } });
    // The new credential makes the recovery sheet (it counts as a recent sign-in).
    const sheet = await client.request('POST', '/api/v1/settings/recovery-codes', { device: { key, credential: done.credential } });
    expect(sheet).toMatchObject({ account: started.account, codes: expect.any(Array) });
  });

  it('recovers with a code at once, and waits for a gate', async () => {
    const { key, account, credential } = await signedUp();
    const { codes } = await client.request('POST', '/api/v1/settings/recovery-codes', { device: { key, credential } });
    const second = await newDeviceKey();
    const recovered = await startRecovery(client, second, { via: 'code', account, code: codes[0], device });
    expect(recovered).toMatchObject({ status: 'recovered', account, recovery_codes_left: 9 });

    const gate = await client.request('POST', '/api/v1/gates', { device: { key, credential }, body: { kind: 'dba-device', label: 'Laptop', device_id: inspectCredential(credential).payload.sub } });
    const third = await newDeviceKey();
    const asked = await startRecovery(client, third, { via: 'gate', account, device });
    expect(asked).toMatchObject({ status: 'pending', number: expect.stringMatching(/^\d\d$/) });
    const id = (await client.request('GET', '/api/v1/gate-requests', { device: { key, credential } })).items.find(r => r.purpose === 'recover').id;
    await client.request('POST', `/api/v1/gate-requests/${id}/answer`, { device: { key, credential }, body: { gate: gate.id, decision: 'allow', number: asked.number } });
    const done = await pollTicket(client, third, '/api/v1/recover/complete', asked.ticket, { waitSeconds: 0, ...noSleep });
    expect(inspectCredential(done.credential).payload.acct).toBe(account);
  });

  it('throws when the server refuses, and retries network errors until the deadline', async () => {
    const { key, account, credential } = await signedUp();
    const gate = await client.request('POST', '/api/v1/gates', { device: { key, credential }, body: { kind: 'dba-device', label: 'Laptop', device_id: inspectCredential(credential).payload.sub } });
    const other = await newDeviceKey();
    const asked = await startRecovery(client, other, { via: 'gate', account, device });
    const id = (await client.request('GET', '/api/v1/gate-requests', { device: { key, credential } })).items.find(r => r.purpose === 'recover').id;
    await client.request('POST', `/api/v1/gate-requests/${id}/answer`, { device: { key, credential }, body: { gate: gate.id, decision: 'deny' } });
    await expect(pollTicket(client, other, '/api/v1/recover/complete', asked.ticket, { waitSeconds: 0, ...noSleep })).rejects.toMatchObject({ code: 'recovery_denied' });

    let tries = 0; let now = 0;
    const offline = createClient({ origin: ORIGIN, fetch: async () => { tries++; throw new Error('offline'); } });
    const result = await pollTicket(offline, other, '/api/v1/recover/complete', asked.ticket, { waitSeconds: 10, sleep: async ms => { now += ms; }, clock: () => now });
    expect(result).toEqual({ status: 'timeout', last: null });
    expect(tries).toBeGreaterThan(1);
  });
});
