import { it, expect } from 'vitest';
import { MemoryStorage } from '../../test-utils/storage.js';
import { charge, deposit, readBalance } from './ledger.js';
import { StatusListDO, SHARD_SIZE } from './status-list-do.js';

const day = iso => Date.parse(iso);

it('never lets the balance go negative and reports what is needed', async () => {
  const storage = new MemoryStorage();
  await storage.transaction(tx => deposit(tx, { id: 'd1', amount: 50 }));
  await expect(storage.transaction(tx => charge(tx, { id: 'c1', kind: 'issue', amount: 75 }))).rejects.toMatchObject({ status: 402, details: { needed_microdollars: 25 } });
  expect((await storage.get('balance')).balance_microdollars).toBe(50);
});

it('credits deposits and charges exactly once per id', async () => {
  const storage = new MemoryStorage();
  await storage.transaction(tx => deposit(tx, { id: 'd1', amount: 100 }));
  expect(await storage.transaction(tx => deposit(tx, { id: 'd1', amount: 100 }))).toEqual({ duplicate: true });
  await storage.transaction(tx => charge(tx, { id: 'c1', kind: 'issue', amount: 75 }));
  expect((await storage.transaction(tx => charge(tx, { id: 'c1', kind: 'issue', amount: 75 }))).duplicate).toBe(true);
  expect((await storage.get('balance')).balance_microdollars).toBe(25);
});

it('aggregates small charges and flushes them to one ledger row per kind at day rollover', async () => {
  const storage = new MemoryStorage();
  await storage.transaction(tx => deposit(tx, { id: 'd', amount: 1000 }, day('2026-11-17T01:00:00Z')));
  for (let i = 0; i < 3; i++) await storage.transaction(tx => charge(tx, { kind: 'decision', amount: 10, aggregate: true }, day('2026-11-17T12:00:00Z')));
  expect((await storage.list({ prefix: 'ledger:' })).size).toBe(1);
  await storage.transaction(tx => charge(tx, { kind: 'read', amount: 5, aggregate: true }, day('2026-11-18T00:00:01Z')));
  const rows = [...(await storage.list({ prefix: 'ledger:' })).values()];
  expect(rows.find(r => r.aggregate)).toMatchObject({ kind: 'decision', count: 3, amount_microdollars: -30, period: '2026-11-17' });
  const state = await storage.transaction(tx => readBalance(tx, day('2026-11-18T00:00:02Z')));
  expect(state.day.aggregates).toEqual({ read: { count: 1, amount: 5 } });
  expect(state.month.spent_microdollars).toBe(35);
});

it('archives the month summary when the month changes', async () => {
  const storage = new MemoryStorage();
  await storage.transaction(tx => deposit(tx, { id: 'd', amount: 1000 }, day('2026-11-30T23:00:00Z')));
  await storage.transaction(tx => charge(tx, { id: 'a', kind: 'issue', amount: 75 }, day('2026-11-30T23:30:00Z')));
  await storage.transaction(tx => charge(tx, { id: 'b', kind: 'issue', amount: 75 }, day('2026-12-01T00:30:00Z')));
  expect(await storage.get('month:2026-11')).toMatchObject({ spent_microdollars: 75, counts: { issue: 1 } });
  expect((await storage.get('balance')).month).toMatchObject({ period: '2026-12', spent_microdollars: 75 });
});

it('refuses to allocate past the end of a status-list shard', async () => {
  const storage = new MemoryStorage();
  const shard = new StatusListDO({ storage }, {});
  await storage.put('next', SHARD_SIZE - 1); await storage.put('shard', 3);
  expect(await shard.allocate(3)).toEqual({ shard: 3, idx: SHARD_SIZE - 1 });
  await expect(shard.allocate(3)).rejects.toMatchObject({ code: 'shard_full' });
});
