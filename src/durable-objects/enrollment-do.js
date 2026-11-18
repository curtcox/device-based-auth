import { assert, errorResponse } from '../utils/errors.js';

const KEEP_MS = 3600000;

/** Holds one enrollment's outcome so the device can poll for it. Written only on approval or denial. */
export class EnrollmentDO {
  constructor(ctx) { this.storage = ctx.storage; }
  async fetch(request) {
    try {
      const args = await request.json(); const now = args.now ?? Date.now();
      if (args.op === 'put') {
        const prior = await this.storage.get('result');
        assert(!prior, 'already_decided', 'This enrollment was already approved or denied', 409);
        await this.storage.put('result', { ...args.result, decided_at: now });
        await this.storage.setAlarm(now + KEEP_MS);
        return Response.json({ ok: true });
      }
      assert(args.op === 'get', 'unknown_operation', 'Unknown enrollment operation', 500);
      return Response.json((await this.storage.get('result')) || { status: 'pending' });
    } catch (error) { return errorResponse(error); }
  }
  async alarm() { await this.storage.deleteAll?.() ?? await this.storage.delete('result'); }
}
