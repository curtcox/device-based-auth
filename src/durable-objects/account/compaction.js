import { RECORD_RETENTION_MS, EXPIRED_VISIBLE_MS, COMPACTION_INTERVAL_MS, enrollmentTokenState } from './shared.js';

const COMPACTION_PAGE = 500;

/**
 * Ageing out records whose prepaid storage is over. Mixed into AccountDO (account-do.js): `this`
 * is the account's Durable Object.
 */
export class AccountCompaction {
  /**
   * Drop records whose prepaid 13 months are over (master plan §8.3): expired credentials issued
   * more than RECORD_RETENTION_MS ago (and expired at least EXPIRED_VISIBLE_MS ago), devices with no
   * credential left and nothing issued to them in that time, and audit, ledger and receipt rows
   * older than that, and revoked API keys and ended enrollment tokens. Kept: revoked devices (so a revoked key never comes back without a recent
   * sign-in), deposits, the daily aggregate ledger rows and monthly summaries (one per day or month,
   * not per operation), and anything with a revocation still in the outbox. Each issue, renewal
   * and audience change prepays the deletes of the rows it wrote (cost-policy.js).
   * Returns the time it next has work, or null when the account has no records left to age out.
   */
  async compact(now) {
    const state = await this.storage.get('compaction');
    if (!state || state.next_at > now) return state?.next_at ?? null;
    const cutoff = now - RECORD_RETENTION_MS;
    const due = []; let nextDue = Infinity; let more = false;
    const soonest = at => { nextDue = Math.min(nextDue, at); };
    const pending = new Set([...(await this.storage.list({ prefix: 'outbox:' })).keys()].map(k => k.split(':')[1]));
    const liveDevices = new Set();
    let startAfter;
    for (;;) {
      const rows = await this.storage.list({ prefix: 'cred:', limit: COMPACTION_PAGE, ...(startAfter ? { startAfter } : {}) });
      for (const [key, cred] of rows) {
        const dropAt = Math.max(cred.created_at + RECORD_RETENTION_MS, cred.exp * 1000 + EXPIRED_VISIBLE_MS);
        if (dropAt <= now && !pending.has(cred.cid) && due.length < COMPACTION_PAGE) due.push(key);
        else { liveDevices.add(cred.device_id); soonest(dropAt); }
      }
      if (rows.size < COMPACTION_PAGE) break;
      startAfter = [...rows.keys()].at(-1);
    }
    more ||= due.length === COMPACTION_PAGE;
    for (const [key, device] of await this.storage.list({ prefix: 'device:' })) {
      if (device.revoked_at || liveDevices.has(device.id)) continue;
      const dropAt = (device.last_issued_at ?? device.created_at) + RECORD_RETENTION_MS;
      if (dropAt <= now && !more) due.push(key); else soonest(dropAt);
    }
    // audit: and ledger: keys start with an ISO timestamp, so the old ones come first.
    for (const prefix of ['audit:', 'ledger:']) {
      const old = await this.storage.list({ prefix, end: `${prefix}${new Date(cutoff).toISOString()}`, limit: COMPACTION_PAGE });
      for (const [key, row] of old) if (prefix === 'audit:' || (row.amount_microdollars < 0 && !row.aggregate)) due.push(key);
      if (old.size === COMPACTION_PAGE) more = true;
    }
    // Charges' ledger rows age with their receipts (same id, same time), so only audit needs a look.
    const [firstAudit] = await this.storage.list({ prefix: 'audit:', start: `audit:${new Date(cutoff).toISOString()}`, limit: 1 });
    if (firstAudit) soonest(firstAudit[1].at + RECORD_RETENTION_MS);
    for (const [key, receipt] of await this.storage.list({ prefix: 'receipt:' })) {
      if (receipt.created_at <= cutoff) due.push(key); else soonest(receipt.created_at + RECORD_RETENTION_MS);
    }
    // Revoked API keys and connected apps, and enrollment tokens that ended, go 13 months after
    // they stopped working (they are free to make, and capped only while active).
    for (const [key, apiKey] of await this.storage.list({ prefix: 'key:' })) {
      if (!apiKey.revoked_at) continue;
      if (apiKey.revoked_at <= cutoff) due.push(key); else soonest(apiKey.revoked_at + RECORD_RETENTION_MS);
    }
    for (const [key, token] of await this.storage.list({ prefix: 'etok:' })) {
      const state = enrollmentTokenState(token, now);
      const ended = state === 'active' ? token.expires_at : state === 'revoked' ? token.revoked_at : state === 'expired' ? token.expires_at : (token.last_used_at ?? token.created_at);
      if (state !== 'active' && ended <= cutoff) due.push(key); else soonest(ended + RECORD_RETENTION_MS);
    }
    for (let i = 0; i < due.length; i += 128) await this.storage.delete(due.slice(i, i + 128));
    const nextAt = more ? now + 60000 : nextDue === Infinity ? null : Math.max(nextDue, now + COMPACTION_INTERVAL_MS);
    if (nextAt === null) await this.storage.delete('compaction');
    else await this.storage.put('compaction', { next_at: nextAt, compacted_at: now, dropped: due.length });
    return nextAt;
  }
}
