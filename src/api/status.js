import { assert } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { SHARD_SIZE } from '../durable-objects/status-list-do.js';

const HEADERS = { 'Content-Type': 'application/statuslist+jwt', 'Cache-Control': 'public, max-age=60', 'Access-Control-Allow-Origin': '*' };

/**
 * Serve a status list. Production verifiers normally fetch status.devicebasedauth.org (the R2
 * bucket's public custom domain, so cache hits never reach this Worker); this route is the
 * same object through the Worker, and creates a shard's first list on demand.
 */
export async function statusList(route, env) {
  const shard = Number(route.params.shard);
  assert(Number.isSafeInteger(shard) && shard >= 0 && shard < Math.max(1, Number(env.STATUS_SHARDS) || 16), 'not_found', 'Unknown status list', 404);
  let object = await env.STATUS_BUCKET.get(`v1/lists/${shard}`);
  if (object) return new Response(await object.text(), { headers: HEADERS });
  const published = await rpc(env.STATUS, `shard-${shard}`, 'publish', { shard });
  return new Response(published.jwt, { headers: HEADERS });
}

/**
 * Hourly: re-sign lists before they expire, publish any pending revocations. Returns how many
 * status indexes are allocated out of the total, from the same `info` calls.
 * @returns {Promise<{ used: number, capacity: number }>}
 */
export async function republishStatusLists(env, now = Date.now()) {
  const shards = Math.max(1, Number(env.STATUS_SHARDS) || 16);
  let used = 0;
  for (let shard = 0; shard < shards; shard++) {
    const info = await rpc(env.STATUS, `shard-${shard}`, 'info', { shard });
    used += info.next || 0;
    if (!info.published_at || info.published_at < now - 12 * 3600000) await rpc(env.STATUS, `shard-${shard}`, 'publish', { shard });
  }
  return { used, capacity: shards * SHARD_SIZE };
}

/** Alert when this share of all status indexes is allocated (indexes are never reused). */
export const STATUS_CAPACITY_ALERT = 0.8;

/**
 * Daily: warn the operator before issuance stops with 503 `capacity`, which happens when every
 * shard is full. The fix is raising STATUS_SHARDS (docs/ops/deployment.md §7).
 * @returns {Promise<boolean>} whether an alert was due
 */
export async function alertStatusCapacity(env, { used, capacity }) {
  if (used < capacity * STATUS_CAPACITY_ALERT) return false;
  const text = `devicebasedauth.org status lists are ${Math.floor(100 * used / capacity)}% allocated (${used} of ${capacity} indexes); raise STATUS_SHARDS before issuance stops.`;
  if (env.ALERT_WEBHOOK_URL) await (env.ALERT_FETCH || fetch)(env.ALERT_WEBHOOK_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }), signal: AbortSignal.timeout(10000) }).catch(() => null);
  return true;
}
