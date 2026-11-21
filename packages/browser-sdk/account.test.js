import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { DBA } from './dba.js';
import { testEnv, call, ORIGIN, worker } from '../../test-utils/env.js';
import { inspectCredential } from '../verify/src/index.js';

// The SDK's sign-up and recovery (STATUS B9, todo/clerk_free_accounts.md §3.8), against the real
// Worker in memory. A local server without Stripe pays through the development route.

let env;
/** A DBA slot whose storage is this test's memory (no IndexedDB in Node). */
const slot = () => { const dba = new DBA({ origin: ORIGIN, name: 'dashboard' }); dba.save = async () => {}; return dba; };

beforeEach(async () => {
  env = await testEnv();
  vi.stubGlobal('fetch', (input, init) => worker.fetch(input instanceof Request ? input : new Request(input, init), env));
  vi.stubGlobal('location', new URL(`${ORIGIN}/signup.html`));
});
afterEach(() => vi.unstubAllGlobals());

async function signedUp() {
  const dba = slot();
  const started = await dba.signUp({ creditCents: 500, acceptTerms: true, device: { name: 'Laptop' } });
  expect(started).toMatchObject({ local_payment: true, account: expect.stringMatching(/^acct_/) });
  expect(dba.pending).toMatchObject({ kind: 'signup', account: started.account });
  await call(env, 'POST', '/api/v1/dev/signup-paid', { body: { ticket: dba.pending.ticket } });
  await dba.finish({ timeoutMs: 0 });
  return { dba, account: started.account };
}

describe('browser SDK sign-up and recovery (B9)', () => {
  it('signs up: waits for the payment, then keeps the dashboard credential', async () => {
    const dba = slot();
    await dba.signUp({ creditCents: 500, acceptTerms: true, device: { name: 'Laptop' } });
    const seen = [];
    await expect(dba.finish({ timeoutMs: 0, onPending: answer => seen.push(answer.status) })).rejects.toMatchObject({ code: 'pending' });
    expect(seen).toEqual(['pending']);
    await call(env, 'POST', '/api/v1/dev/signup-paid', { body: { ticket: dba.pending.ticket } });
    const credential = await dba.finish({ timeoutMs: 0 });
    expect(dba.pending).toBeNull();
    expect(inspectCredential(credential).payload).toMatchObject({ grants: [{ actions: ['dba:session'] }], device: { name: 'Laptop', kind: 'browser' } });
    expect(await (await dba.fetch(`${ORIGIN}/api/v1/whoami`)).json()).toMatchObject({ account: dba.payload.acct });
    // A working credential is not thrown away by accident.
    await expect(dba.signUp({ creditCents: 500, acceptTerms: true })).rejects.toMatchObject({ code: 'already_enrolled' });
  });

  it('recovers with a code at once, and through a device gate after it approves', async () => {
    const { dba, account } = await signedUp();
    const sheet = await (await dba.fetch(`${ORIGIN}/api/v1/settings/recovery-codes`, { method: 'POST' })).json();
    const phone = slot();
    expect(await phone.recover({ account, code: sheet.codes[0] })).toMatchObject({ status: 'recovered', account });
    expect(phone.payload.acct).toBe(account);

    // The laptop becomes a device gate; a third browser asks it.
    const gate = await (await dba.fetch(`${ORIGIN}/api/v1/gates`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ kind: 'dba-device', label: 'Laptop', device_id: dba.payload.sub }) })).json();
    const tablet = slot();
    const asked = await tablet.recover({ account, via: 'gate' });
    expect(tablet.pending).toMatchObject({ kind: 'recover-gate', number: asked.number });
    const id = (await (await dba.fetch(`${ORIGIN}/api/v1/gate-requests`)).json()).items.find(r => r.purpose === 'recover').id;
    await dba.fetch(`${ORIGIN}/api/v1/gate-requests/${id}/answer`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ gate: gate.id, decision: 'allow', number: asked.number }) });
    await tablet.finish({ timeoutMs: 0 });
    expect(tablet.payload.acct).toBe(account);
  });

  it('forgets a recovery that was refused', async () => {
    const { dba, account } = await signedUp();
    const gate = await (await dba.fetch(`${ORIGIN}/api/v1/gates`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ kind: 'dba-device', label: 'Laptop', device_id: dba.payload.sub }) })).json();
    const tablet = slot();
    await tablet.recover({ account, via: 'gate' });
    const id = (await (await dba.fetch(`${ORIGIN}/api/v1/gate-requests`)).json()).items.find(r => r.purpose === 'recover').id;
    await dba.fetch(`${ORIGIN}/api/v1/gate-requests/${id}/answer`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ gate: gate.id, decision: 'deny' }) });
    await expect(tablet.finish({ timeoutMs: 0 })).rejects.toMatchObject({ code: 'recovery_denied' });
    expect(tablet.pending).toBeNull();
    await expect(slot().finish()).rejects.toMatchObject({ code: 'nothing_pending' });
  });
});
