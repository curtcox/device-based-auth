import { charge, readBalance } from '../ledger.js';
import { price } from '../../utils/pricing.js';
import { randomId } from '../../utils/ids.js';
import { emailConfigured, emailLine, sendEmail } from '../../services/email.js';
import { NOTICE_INTERVAL_MS } from '../../services/push.js';
import { scheduleCompaction } from './shared.js';

/** Wait before the second and third attempt when SES did not take a message. */
export const EMAIL_RETRY_MS = Object.freeze([60_000, 600_000]);
/** How much of the audit trail one digest reads, and how many of those it lists. */
const DIGEST_SCAN = 200;
const DIGEST_LINES = 20;
const DIGEST_TYPES = new Set(['credential.issued', 'credential.rotated']);

/** The owner's choice (account settings `security_email`), from fewest emails to most. */
export const SECURITY_EMAIL_LEVELS = Object.freeze(['off', 'sensitive', 'all']);

/**
 * Security email (STATUS S8, D9; master plan §10). Mixed into AccountDO (account-do.js).
 *
 * Takeover-sensitive events (credentials that can act on the account, API keys and connected
 * apps, enrollment tokens, gates, sign-in gates and recovery codes, raised limits, reinstated
 * devices) are emailed at once; other issuances and rotations at most once an hour, in a digest
 * read from the audit trail when it is sent. Each email is charged the `notice` price when it is
 * queued, so it is paid for before anything is sent; an account that cannot pay, has no address,
 * or turned emails off gets none (the Web Push notices still go out).
 */
export class AccountEmail {
  /** Push the notice to the owner's browsers and email it (takeover-sensitive events). */
  async alert(notice, now) {
    this.notify(notice, now);
    await this.emailNow(notice, now);
  }

  /**
   * Queue one email now. `always` sends it even when the owner chose fewer emails (the email
   * that says they were turned down). Never throws: the event it reports already happened.
   */
  async emailNow({ title, body, path, url }, now, { always = false } = {}) {
    try {
      return await this.tx(async tx => {
        if (!(await this.emailReady(tx, now, always ? 'off' : 'sensitive'))) return false;
        const id = randomId('mail', 10);
        await this.chargeNotice(tx, id, 'event', now);
        await tx.put(`mailq:${new Date(now).toISOString()}:${id}`, { id, subject: emailLine(title), text: emailBody(this.env, { body, link: url || appLink(this.env, path), at: now }), at: now, send_at: now, attempts: 0 });
        await this.scheduleWake(tx, now);
        return true;
      });
    } catch { return false; }
  }

  /**
   * An ordinary issuance or rotation happened: make sure a digest is queued. The first one in an
   * hour pays for it; the rest find it queued and cost nothing (they are read from the audit
   * trail when it is sent). Never throws.
   */
  async emailDigest(now) {
    try {
      return await this.tx(async tx => {
        if (await tx.get('mailq:digest')) return false;
        if (!(await this.emailReady(tx, now, 'all'))) return false;
        const last = (await tx.get('mail:digest'))?.sent_at;
        const sendAt = last ? Math.max(now, last + NOTICE_INTERVAL_MS) : now;
        await this.chargeNotice(tx, randomId('mail', 10), 'digest', now);
        // It starts at this issuance: every earlier one was in a digest already, or happened while
        // digests were off or unaffordable (one at the very millisecond a digest went out may be
        // listed twice, never missed).
        await tx.put('mailq:digest', { id: 'digest', digest: true, since: now, at: now, send_at: sendAt, attempts: 0 });
        await this.scheduleWake(tx, sendAt);
        return true;
      });
    } catch { return false; }
  }

  /** The address to email, if this server sends email and the owner wants emails at `level`. */
  async emailReady(tx, now, level) {
    if (!emailConfigured(this.env)) return null;
    const email = (await tx.get('profile'))?.email;
    if (!email) return null;
    const chosen = (await this.settings(tx)).security_email;
    if (SECURITY_EMAIL_LEVELS.indexOf(chosen) < SECURITY_EMAIL_LEVELS.indexOf(level)) return null;
    // Check first: charge() refuses with a throw, which would undo the caller's transaction.
    const state = await readBalance(tx, now, { flush: false });
    return state.balance_microdollars >= price('notice') ? email : null;
  }

  async chargeNotice(tx, id, kind, now) {
    await charge(tx, { id: `notice-${id}`, kind: 'notice', amount: price('notice'), detail: { email: kind } }, now);
    await scheduleCompaction(tx, now);
  }

  /** Send what is due (from the alarm). Returns the next time something is due, or null. */
  async deliverEmail(now) {
    const digest = await this.storage.get('mailq:digest');
    if (digest && digest.send_at <= now) await this.freezeDigest(digest, now);
    let next = null;
    for (const [key, item] of await this.storage.list({ prefix: 'mailq:' })) {
      if (item.digest) { next = Math.min(next ?? Infinity, item.send_at); continue; }
      if (item.send_at > now) { next = Math.min(next ?? Infinity, item.send_at); continue; }
      const to = (await this.storage.get('profile'))?.email;
      const result = to ? await sendEmail(this.env, { to, subject: item.subject, text: item.text }, now) : { ok: false, retry: false, error: 'no address' };
      if (!result.ok && result.retry && item.attempts < EMAIL_RETRY_MS.length) {
        const at = now + EMAIL_RETRY_MS[item.attempts];
        await this.storage.put(key, { ...item, attempts: item.attempts + 1, send_at: at, last_status: result.status });
        next = Math.min(next ?? Infinity, at);
        continue;
      }
      await this.tx(async tx => {
        await tx.delete(key);
        await this.audit(tx, now, result.ok ? 'email.sent' : 'email.failed', { subject: item.subject, ...(result.ok ? {} : { status: result.status ?? null, error: result.error }) });
      });
    }
    return next;
  }

  /**
   * Turn the queued digest into a fixed message covering everything up to now, and record now as
   * its sending time, before the network call: an issuance arriving while it is being sent then
   * queues the next digest instead of being folded into one already written.
   */
  async freezeDigest(digest, now) {
    const start = `audit:${new Date(digest.since).toISOString()}`;
    const end = `audit:${new Date(now).toISOString()}~`;
    const events = [...(await this.storage.list({ start, end, limit: DIGEST_SCAN })).values()].filter(e => DIGEST_TYPES.has(e.type));
    await this.tx(async tx => {
      await tx.delete('mailq:digest');
      await tx.put('mail:digest', { sent_at: now });
      if (!events.length) return;
      const lines = [];
      for (const e of events.slice(0, DIGEST_LINES)) {
        const cred = await tx.get(`cred:${e.cid}`);
        const device = await tx.get(`device:${e.device_id || cred?.device_id}`);
        const aud = (e.aud || cred?.aud || []).join(', ');
        lines.push(`- ${utc(e.at)}  ${e.type === 'credential.rotated' ? 'rotated' : 'issued'}  ${emailLine(device?.name, 64) || 'a device'} for ${emailLine(aud, 120)}  (${e.cid})`);
      }
      const more = events.length > DIGEST_LINES ? `\n…and ${events.length - DIGEST_LINES}${events.length === DIGEST_SCAN ? '+' : ''} more.` : '';
      const count = `${events.length}${events.length === DIGEST_SCAN ? '+' : ''}`;
      const id = randomId('mail', 10);
      await tx.put(`mailq:${new Date(now).toISOString()}:${id}`, {
        id, subject: `${count} credential${events.length === 1 ? '' : 's'} issued or rotated`,
        text: emailBody(this.env, { body: `Credentials issued or moved to a new key on your account since ${utc(digest.since)}:\n\n${lines.join('\n')}${more}`, link: appLink(this.env, '#credentials'), at: now }),
        at: now, send_at: now, attempts: 0
      });
    });
  }
}

const utc = at => `${new Date(at).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
const appLink = (env, path) => `${env.APP_ORIGIN || ''}/app.html${path || ''}`;

/** Plain text: what happened, when, where to look, and why this email came. */
function emailBody(env, { body, link, at }) {
  return [
    body, '',
    `When: ${utc(at)}`,
    `Review: ${link}`, '',
    'If this was not you, sign in, revoke what you do not recognise, and change your sign-in.', '',
    '--',
    `This address gets security emails for your devicebasedauth.org account. Each costs ${price('notice')} µ$ from your balance; choose which you get, or turn them off, on the Account page: ${appLink(env, '#account')}`
  ].join('\n');
}
