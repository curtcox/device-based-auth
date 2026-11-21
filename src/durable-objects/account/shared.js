/**
 * Constants and record helpers shared by the AccountDO (account-do.js) and its operation groups
 * in this folder. account-do.js re-exports the public ones, so importers keep using that path.
 */

/** Default page size for the account's lists. */
export const PAGE = 50;

// Records are prepaid for 13 months (master plan §8.3, docs/business/pricing.md). After that,
// compact() drops them so no account's storage grows forever on what it once paid.
export const RECORD_RETENTION_MS = 395 * 86400000;
// An expired credential stays visible this long even if it is older than the retention period
// (a renewed credential can be years old when it finally expires).
export const EXPIRED_VISIBLE_MS = 30 * 86400000;
// Compaction runs at most this often, so its alarm wake-up and bookkeeping write are shared by
// everything that fell due in between.
export const COMPACTION_INTERVAL_MS = 7 * 86400000;

/** Make sure compaction will look at this account once the rows written now age out. */
export async function scheduleCompaction(tx, now) {
  if (await tx.get('compaction')) return;
  const at = now + RECORD_RETENTION_MS;
  await tx.put('compaction', { next_at: at });
  const alarm = await tx.getAlarm();
  if (!alarm || alarm > at) await tx.setAlarm(at);
}

/** active | expired | revoked | used_up */
export function enrollmentTokenState(token, now = Date.now()) {
  if (token.revoked_at) return 'revoked';
  if (token.expires_at <= now) return 'expired';
  if (token.uses >= token.max_uses) return 'used_up';
  return 'active';
}

/**
 * Does the dashboard gate hold this session (a Clerk session, a local session, or a dashboard
 * device's credential)? 'open' without a dashboard gate, else 'confirmed' or 'locked'.
 */
export async function dashboardState(storage, session, now) {
  const settings = await storage.get('signin_gates');
  if (!settings?.dashboard) return 'open';
  const confirmed = await storage.get(`dashsess:${session}`);
  return confirmed && confirmed.until > now ? 'confirmed' : 'locked';
}
