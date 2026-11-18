import { assert, errorResponse } from '../utils/errors.js';

const STALE_MS = 36 * 3600000;

/**
 * The cost-safety brake (ported in spirit from cronly/hashbin). Paid operations are prepaid and
 * keep working; the brake stops the free, unauthenticated paths when measured infrastructure
 * cost is projected past the limit or measurements are missing.
 */
export class SafetyDO {
  constructor(ctx, env) { this.storage = ctx.storage; this.env = env; }
  async fetch(request) {
    try {
      const args = await request.json();
      if (args.op === 'record') { await this.storage.put('report', args.report); return Response.json(args.report); }
      assert(args.op === 'status', 'unknown_operation', 'Unknown safety operation', 500);
      if (this.env.ENVIRONMENT === 'local') return Response.json({ brake: false, local: true });
      const report = await this.storage.get('report');
      const stale = !report || Date.now() - report.checked_at > STALE_MS;
      return Response.json({ ...report, stale, brake: this.env.COST_SAFETY_HARD_STOP === 'true' || (this.env.COST_SAFETY_FAIL_OPEN !== 'true' && stale) || !!report?.brake });
    } catch (error) { return errorResponse(error); }
  }
}
