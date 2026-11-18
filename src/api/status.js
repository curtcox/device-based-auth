import { assert } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';

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

/** Hourly: re-sign lists before they expire, publish any pending revocations. */
export async function republishStatusLists(env, now = Date.now()) {
  const shards = Math.max(1, Number(env.STATUS_SHARDS) || 16);
  for (let shard = 0; shard < shards; shard++) {
    const info = await rpc(env.STATUS, `shard-${shard}`, 'info', { shard });
    if (!info.published_at || info.published_at < now - 12 * 3600000) await rpc(env.STATUS, `shard-${shard}`, 'publish', { shard });
  }
}
