import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';
import { inspectCredential } from '../packages/verify/src/index.js';
import { RECORD_RETENTION_MS, EXPIRED_VISIBLE_MS, COMPACTION_INTERVAL_MS } from './durable-objects/account-do.js';

// Master plan §8.3: issuance prepays 13 months of records; after that compaction drops them, so an
// account's storage never grows on what it paid once. Revoked devices, deposits and daily/monthly
// summaries stay.

const DAY = 86400000;
let env; const realNow = Date.now; let t;
beforeEach(async () => {
  t = realNow();
  Date.now = () => t;
  env = await testEnv();
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
});
afterEach(() => { Date.now = realNow; });

const accountOf = cid => [...env.ACCOUNTS.objects.values()].find(o => o.storage.rows.has(`cred:${cid}`));
const keys = (account, prefix) => [...account.storage.rows.keys()].filter(k => k.startsWith(prefix));
/** Run the account's alarm at time `at`, as Cloudflare would. */
async function alarmAt(account, at) { t = at; account.storage.alarm = null; await account.alarm(); }

async function issue(lifetime_seconds = 3600) {
  const device = await newDevice();
  const { approve } = await enroll(env, 'alice', device, { lifetime_seconds });
  return { device, deviceId: approve.body.device_id, cid: inspectCredential(approve.body.credential).payload.cid };
}

describe('record compaction', () => {
  it('schedules itself for when the first record ages out', async () => {
    const { cid } = await issue();
    const account = accountOf(cid);
    expect(account.storage.rows.get('compaction').next_at).toBe(t + RECORD_RETENTION_MS);
    expect(account.storage.alarm).toBeLessThanOrEqual(t + RECORD_RETENTION_MS);
  });

  it('drops an expired credential, its device and its paid rows after 13 months, and keeps deposits and summaries', async () => {
    const start = t;
    const { cid, deviceId } = await issue();
    const account = accountOf(cid);
    await call(env, 'DELETE', `/api/v1/credentials/${cid}`, { auth: 'alice' });
    for (const prefix of ['audit:', 'receipt:', 'device:']) expect(keys(account, prefix).length).toBeGreaterThan(0);
    const charges = () => keys(account, 'ledger:').filter(k => account.storage.rows.get(k).amount_microdollars < 0);
    expect(charges()).toHaveLength(1);

    // A day before the 13 months are up nothing goes.
    await alarmAt(account, start + RECORD_RETENTION_MS - DAY);
    expect(account.storage.rows.has(`cred:${cid}`)).toBe(true);

    await alarmAt(account, start + RECORD_RETENTION_MS + DAY);
    expect(account.storage.rows.has(`cred:${cid}`)).toBe(false);
    // Only the credential was revoked, not the device, so the device goes with its last credential.
    expect(account.storage.rows.has(`device:${deviceId}`)).toBe(false);
    expect(keys(account, 'audit:')).toHaveLength(0);
    expect(keys(account, 'receipt:')).toHaveLength(0);
    expect(charges()).toHaveLength(0);
    // The deposit's ledger row and the balance are untouched.
    expect(keys(account, 'ledger:').length).toBeGreaterThan(0);
    expect(keys(account, 'ledger:').every(k => account.storage.rows.get(k).amount_microdollars > 0)).toBe(true);
    expect((await call(env, 'GET', '/api/v1/account', { auth: 'alice' })).body.balance_microdollars).toBe(1_000_000 - 85);
    expect((await call(env, 'GET', `/api/v1/credentials/${cid}`, { auth: 'alice' })).status).toBe(404);
  });

  it('drops a device once it has no credential left, but never a revoked device', async () => {
    const start = t;
    const kept = await issue();
    const account = accountOf(kept.cid);
    const gone = await issue();
    await call(env, 'POST', `/api/v1/devices/${kept.deviceId}/revoke`, { auth: 'alice', body: {} });
    await alarmAt(account, start + RECORD_RETENTION_MS + DAY);
    expect(keys(account, 'cred:')).toHaveLength(0);
    expect(account.storage.rows.has(`device:${gone.deviceId}`)).toBe(false);
    expect(account.storage.rows.get(`device:${kept.deviceId}`).revoked_at).toBeTruthy();
    // The revoked key still cannot come back without a recent sign-in: the device record is there.
  });

  it('keeps a live credential however old, and an expired one visible for a while after it expires', async () => {
    const start = t;
    const long = await issue(400 * 86400);
    const account = accountOf(long.cid);
    await alarmAt(account, start + RECORD_RETENTION_MS + DAY);
    expect(account.storage.rows.has(`cred:${long.cid}`)).toBe(true); // 400 days > 13 months
    expect(account.storage.rows.has(`device:${long.deviceId}`)).toBe(true);
    const expiresAt = account.storage.rows.get(`cred:${long.cid}`).exp * 1000;
    expect(account.storage.rows.get('compaction').next_at).toBe(Math.max(expiresAt + EXPIRED_VISIBLE_MS, t + COMPACTION_INTERVAL_MS));
    await alarmAt(account, expiresAt + EXPIRED_VISIBLE_MS + 1000);
    expect(account.storage.rows.has(`cred:${long.cid}`)).toBe(false);
    expect(account.storage.rows.has(`device:${long.deviceId}`)).toBe(false);
    // Nothing is left to age out, so the account needs no more wake-ups.
    expect(account.storage.rows.has('compaction')).toBe(false);
    expect(account.storage.alarm).toBeNull();
  });

  it('runs at most weekly, sharing each wake-up among everything that fell due', async () => {
    const start = t;
    const first = await issue();
    const account = accountOf(first.cid);
    t = start + 2 * DAY; await issue();
    await alarmAt(account, start + RECORD_RETENTION_MS + 1000);
    expect(keys(account, 'cred:')).toHaveLength(1);
    expect(account.storage.rows.get('compaction').next_at).toBe(t + COMPACTION_INTERVAL_MS);
    // An alarm for other work in between does not compact early.
    await alarmAt(account, t + 3 * DAY);
    expect(keys(account, 'cred:')).toHaveLength(1);
    await alarmAt(account, start + RECORD_RETENTION_MS + 1000 + COMPACTION_INTERVAL_MS);
    expect(keys(account, 'cred:')).toHaveLength(0);
  });

  it('does not drop a credential whose revocation is still being published', async () => {
    const start = t;
    const { cid } = await issue();
    const account = accountOf(cid);
    await account.storage.put(`outbox:${cid}`, { shard: 0, idx: 0, at: t, cid, hooks: [] });
    t = start + RECORD_RETENTION_MS + DAY;
    await account.compact(t);
    expect(account.storage.rows.has(`cred:${cid}`)).toBe(true);
  });
});
