import { assert, errorResponse } from '../utils/errors.js';
import { setBit, getBit } from '../../packages/verify/src/status-list.js';
import { signStatusList } from '../../packages/verify/src/issuer.js';
import { activeSigner, statusUri, issuerName } from '../services/issuer.js';

export const SHARD_SIZE = 262144; // 32 KiB of bits per shard keeps every stored value small.
const PUBLISH_DELAY_MS = 30000;
const REPUBLISH_AFTER_MS = 12 * 3600000;

/**
 * One status-list shard: allocates indexes, records revocations, and publishes the signed list
 * to R2 (served at status.devicebasedauth.org and /status/v1/lists/:n). Revocations are
 * debounced into at most one publish per PUBLISH_DELAY_MS.
 */
export class StatusListDO {
  constructor(ctx, env) { this.ctx = ctx; this.storage = ctx.storage; this.env = env; }

  async fetch(request) {
    try {
      const args = await request.json();
      const shard = Number(args.shard ?? (await this.storage.get('shard')));
      switch (args.op) {
        case 'allocate': return Response.json(await this.allocate(args.shard));
        case 'revoke': return Response.json(await this.revoke(args.indexes, args.now ?? Date.now()));
        case 'publish': return Response.json(await this.publish(shard, args.now ?? Date.now()));
        case 'get': return Response.json(await this.read(args.idx));
        case 'info': return Response.json({ shard, next: (await this.storage.get('next')) || 0, published_at: (await this.storage.get('published'))?.at ?? null });
        default: assert(false, 'unknown_operation', 'Unknown status operation', 500);
      }
    } catch (error) { return errorResponse(error); }
  }

  async allocate(shard) {
    return this.storage.transaction(async tx => {
      if ((await tx.get('shard')) === undefined) await tx.put('shard', shard);
      const next = (await tx.get('next')) || 0;
      assert(next < SHARD_SIZE, 'shard_full', 'Status list shard is full', 409);
      await tx.put('next', next + 1);
      return { shard, idx: next };
    });
  }

  async read(idx) {
    const bytes = (await this.storage.get('bits')) || new Uint8Array(0);
    return { revoked: getBit(bytes, idx) === 1 };
  }

  async revoke(indexes, now) {
    await this.storage.transaction(async tx => {
      let bytes = (await tx.get('bits')) || new Uint8Array(1024);
      for (const idx of indexes) { assert(Number.isSafeInteger(idx) && idx >= 0 && idx < SHARD_SIZE, 'invalid_index', 'Invalid status index'); bytes = setBit(bytes, idx); }
      await tx.put('bits', bytes); await tx.put('dirty', true);
      if (!(await tx.getAlarm())) await tx.setAlarm(now + (Number(this.env.STATUS_PUBLISH_DELAY_MS) || PUBLISH_DELAY_MS));
    });
    return { ok: true };
  }

  /** Sign and store the current list. Called by the alarm, on first read, and by the hourly cron. */
  async publish(shard, now) {
    assert(Number.isSafeInteger(shard), 'unknown_shard', 'Shard is not initialised', 404);
    const bytes = (await this.storage.get('bits')) || new Uint8Array(1024);
    const uri = statusUri(this.env, shard);
    const jwt = await signStatusList({ uri, bytes, issuer: issuerName(this.env), ttl: 60, now: Math.floor(now / 1000) }, await activeSigner(this.env));
    await this.env.STATUS_BUCKET.put(`v1/lists/${shard}`, jwt, { httpMetadata: { contentType: 'application/statuslist+jwt', cacheControl: 'public, max-age=60' } });
    await this.storage.put('published', { at: now }); await this.storage.delete('dirty');
    return { shard, uri, published_at: now, jwt };
  }

  async alarm() {
    const now = Date.now();
    const published = await this.storage.get('published');
    if ((await this.storage.get('dirty')) || !published || published.at < now - REPUBLISH_AFTER_MS) await this.publish(await this.storage.get('shard'), now);
  }
}
