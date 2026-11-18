import { it, expect } from 'vitest';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';
import { republishStatusLists, alertStatusCapacity } from './api/status.js';
import { SHARD_SIZE } from './durable-objects/status-list-do.js';

// Status indexes are never reused, so the operator must hear about filling shards before
// issuance stops (docs/ops/deployment.md §7).

it('counts allocated indexes and alerts at 80% of capacity', async () => {
  const sent = [];
  const env = await testEnv({ STATUS_SHARDS: '2', ALERT_WEBHOOK_URL: 'https://alerts.example/hook', ALERT_FETCH: async (url, init) => { sent.push({ url, body: JSON.parse(init.body) }); return new Response('ok'); } });
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
  await enroll(env, 'alice', await newDevice());
  const capacity = await republishStatusLists(env);
  expect(capacity).toEqual({ used: 1, capacity: 2 * SHARD_SIZE });
  expect(await alertStatusCapacity(env, capacity)).toBe(false);
  expect(sent).toHaveLength(0);
  expect(await alertStatusCapacity(env, { used: Math.ceil(1.6 * SHARD_SIZE), capacity: 2 * SHARD_SIZE })).toBe(true);
  expect(sent[0].url).toBe('https://alerts.example/hook');
  expect(sent[0].body.text).toMatch(/80% allocated.*raise STATUS_SHARDS/);
});

it('skips full shards and refuses with 503 capacity when every shard is full', async () => {
  const env = await testEnv({ STATUS_SHARDS: '2', STATUS_ORIGIN: 'https://status.capacity.test' });
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
  const shard = n => env.STATUS.get(`shard-${n}`);
  await shard(0).storage.put('shard', 0); await shard(0).storage.put('next', SHARD_SIZE);
  const { approve } = await enroll(env, 'alice', await newDevice());
  expect(approve.status).toBe(200);
  expect(await shard(1).storage.get('next')).toBe(1);
  await shard(1).storage.put('next', SHARD_SIZE);
  const refused = await enroll(env, 'alice', await newDevice());
  expect(refused.approve.status).toBe(503);
  expect(refused.approve.body.code).toBe('capacity');
});
