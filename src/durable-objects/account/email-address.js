import { assert } from '../../utils/errors.js';
import { randomId } from '../../utils/ids.js';
import { price } from '../../utils/pricing.js';
import { signToken } from '../../auth/tokens.js';
import { readBalance } from '../ledger.js';
import { cleanEmailAddress, emailConfigured, emailLine } from '../../services/email.js';
import { recentRecoveryStarts, withRecoveryStart } from './recovery.js';

// How long an email recovery waits after its link is used, so the owner's devices and browsers
// can cancel it (done/clerk_free_accounts.md O1, approved by the owner 2026-11-21).
export const EMAIL_RECOVERY_WAIT_MS = 72 * 3600000;
// How long a verification or recovery link works.
export const EMAIL_LINK_MS = 3600000;
// A recovery that waited its time can be completed this long; a cancelled one is kept a day so the
// new device learns it was refused.
const READY_KEEP_MS = 7 * 86400000;
const CANCELLED_KEEP_MS = 86400000;
// Email recoveries anyone may start per account per hour (each emails the owner).
const EMAIL_RECOVERIES_PER_HOUR = 3;

const utc = at => `${new Date(at).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
const linkUrl = (env, token) => `${env.APP_ORIGIN || ''}/email-link.html#${token}`;
const emailKey = id => `emailrec:${id}`;

/**
 * An address devicebasedauth.org verified itself (done/clerk_free_accounts.md §3.5, §3.7, STATUS
 * B9), for security email and for recovery by email; and recovery by email, which waits
 * EMAIL_RECOVERY_WAIT_MS after its link is used so any of the owner's devices can cancel it. An
 * address Clerk verified stays Clerk's (email_source 'clerk'); a verified one is not overwritten by
 * Clerk. Mixed into AccountDO (account-do.js): `this` is the account's Durable Object.
 */
export class AccountEmailAddress {
  /** Queue one email to `to` (or the profile's address), paid if the balance covers it. */
  async queueEmail(tx, { to, subject, text }, now, { mustPay }) {
    const id = randomId('mail', 10);
    const state = await readBalance(tx, now, { flush: false });
    if (state.balance_microdollars >= price('notice')) await this.chargeNotice(tx, id, 'account', now);
    else assert(!mustPay, 'insufficient_balance', 'Insufficient balance', 402, { needed_microdollars: price('notice') - state.balance_microdollars, price_microdollars: price('notice') });
    await tx.put(`mailq:${new Date(now).toISOString()}:${id}`, { id, ...(to ? { to } : {}), subject: emailLine(subject), text, at: now, send_at: now, attempts: 0 });
    await this.scheduleWake(tx, now);
  }

  /** Send a verification link to `address`, charged the notice price; the address changes once it is used. */
  async op_email_verify_start({ address, account }, now) {
    const clean = cleanEmailAddress(address);
    assert(clean, 'invalid_email', 'email must be one plain address, like you@example.com');
    assert(emailConfigured(this.env), 'email_unavailable', 'This server does not send email', 503);
    const nonce = randomId('emv', 16);
    const token = await signToken('emv_', { a: account, n: nonce, exp: Math.ceil((now + EMAIL_LINK_MS) / 1000) }, this.env.TOKEN_SIGNING_KEY);
    await this.tx(async tx => {
      const profile = await tx.get('profile');
      assert(profile, 'not_found', 'Account not found', 404);
      await tx.put('profile', { ...profile, email_pending: { address: clean, nonce, expires_at: now + EMAIL_LINK_MS } });
      await this.queueEmail(tx, { to: clean, subject: 'Confirm your security email address', text: [
        'Someone signed in to a devicebasedauth.org account asked to use this address for its security email and for recovering the account by email.', '',
        `Confirm within an hour: ${linkUrl(this.env, token)}`, '',
        'If that was not you, ignore this email; nothing changes.'
      ].join('\n') }, now, { mustPay: true });
      await this.audit(tx, now, 'account.email_verification_sent', {});
    });
    return { pending: true, expires_at: now + EMAIL_LINK_MS };
  }

  /** The address a verification link would set (no write), and the verified one it replaces. */
  async op_email_verify_check({ nonce }, now) {
    const profile = await this.storage.get('profile');
    const pending = profile?.email_pending;
    assert(pending && pending.nonce === nonce && pending.expires_at > now, 'invalid_link', 'This link is not valid any more; ask for a new one on the Account page', 410);
    return { address: pending.address, previous: profile.email_source === 'verified' ? profile.email : null };
  }

  /** Use a verification link: the address becomes the security email and recovery address. */
  async op_email_verify_finish({ nonce }, now) {
    return this.tx(async tx => {
      const profile = await tx.get('profile');
      const pending = profile?.email_pending;
      assert(pending && pending.nonce === nonce && pending.expires_at > now, 'invalid_link', 'This link is not valid any more; ask for a new one on the Account page', 410);
      const { email_pending: _done, ...rest } = profile;
      await tx.put('profile', { ...rest, email: pending.address, email_source: 'verified' });
      await this.audit(tx, now, 'account.email_changed', { had_address: !!profile.email, has_address: true, source: 'verified' });
      return { security_email_address: pending.address, security_email_source: 'verified' };
    });
  }

  /** Stop using the address (security email and recovery by email). Returns the one removed. */
  async op_email_remove(_args, now) {
    return this.tx(async tx => {
      const profile = await tx.get('profile');
      if (!profile?.email) return { removed: null };
      const { email, email_source: source, email_pending: _p, ...rest } = profile;
      await tx.put('profile', rest);
      await this.audit(tx, now, 'account.email_changed', { had_address: true, has_address: false });
      return { removed: email, source: source ?? 'clerk' };
    });
  }

  /**
   * Someone asked to recover the account by email for key `jkt`: email the verified address a
   * link (free when the balance cannot pay: an empty balance must not lock the owner out). At
   * most EMAIL_RECOVERIES_PER_HOUR an hour; beyond that, or without a verified address, nothing
   * is sent or stored, and the Worker answers the same either way.
   */
  async op_email_recovery_start({ id, jkt, device_name = null, account }, now) {
    const profile = await this.storage.get('profile');
    const limited = p => !p?.email || p.email_source !== 'verified' || recentRecoveryStarts(p, 'email', now).length >= EMAIL_RECOVERIES_PER_HOUR;
    if (limited(profile)) return { sent: false };
    const token = await signToken('erl_', { a: account, i: id, exp: Math.ceil((now + EMAIL_LINK_MS) / 1000) }, this.env.TOKEN_SIGNING_KEY);
    const name = emailLine(device_name || 'A new device', 80);
    const sent = await this.tx(async tx => {
      // Checked again inside the transaction, against the count in storage (see recentRecoveryStarts).
      const current = await tx.get('profile');
      if (limited(current)) return false;
      await tx.put('profile', withRecoveryStart(current, 'email', now));
      await tx.put(emailKey(id), { id, jkt, device_name: name, state: 'link_sent', requested_at: now, until: now + EMAIL_LINK_MS });
      await this.queueEmail(tx, { subject: 'Recover your devicebasedauth.org account?', text: [
        `“${name}” asked to be let into your devicebasedauth.org account by email, after losing every other device.`, '',
        `If that is you, open this link within an hour: ${linkUrl(this.env, token)}`,
        `The device gets in ${EMAIL_RECOVERY_WAIT_MS / 3600000} hours after the link is used. Until then any of your signed-in devices or browsers can cancel it.`, '',
        'If it was not you, ignore this email: nothing happens unless the link is used.'
      ].join('\n') }, now, { mustPay: false });
      await this.audit(tx, now, 'recovery.email_requested', { id, jkt });
      await this.scheduleWake(tx, now + EMAIL_LINK_MS);
      return true;
    });
    if (!sent) return { sent: false };
    this.notify({ title: 'Someone asked to recover your account by email', body: `“${name}” asked for a recovery link at your security email address. Nothing happens unless the link is used, and you can cancel for ${EMAIL_RECOVERY_WAIT_MS / 3600000} hours after that.`, path: '#account', tag: `email-recovery-${id}` }, now);
    return { sent: true };
  }

  /** The emailed link was used: the recovery completes after the wait unless cancelled. */
  async op_email_recovery_confirm({ id }, now) {
    const row = await this.tx(async tx => {
      const rec = await tx.get(emailKey(id));
      assert(rec && rec.state === 'link_sent' && rec.until > now, 'invalid_link', 'This recovery link is not valid any more', 410);
      const next = { ...rec, state: 'waiting', confirmed_at: now, ready_at: now + EMAIL_RECOVERY_WAIT_MS, until: now + EMAIL_RECOVERY_WAIT_MS + READY_KEEP_MS };
      await tx.put(emailKey(id), next);
      await this.audit(tx, now, 'recovery.email_confirmed', { id, ready_at: next.ready_at });
      await this.scheduleWake(tx, next.until);
      return next;
    });
    await this.alert({ title: 'Your account will be recovered by email', body: `The recovery link was used: “${row.device_name}” gets into your account at ${utc(row.ready_at)}. If that is not you, cancel it now on the Account page.`, path: '#account', tag: `email-recovery-${id}` }, now);
    return { status: 'waiting', ready_at: row.ready_at };
  }

  /** The owner (any dashboard sign-in) stops an email recovery before it completes. */
  async op_email_recovery_cancel({ id }, now) {
    await this.tx(async tx => {
      const rec = await tx.get(emailKey(id));
      assert(rec && (rec.state === 'link_sent' || rec.state === 'waiting'), 'not_found', 'No email recovery waiting with that id', 404);
      await tx.put(emailKey(id), { ...rec, state: 'cancelled', cancelled_at: now, until: now + CANCELLED_KEEP_MS });
      await this.audit(tx, now, 'recovery.email_cancelled', { id });
    });
    this.notify({ title: 'Email recovery cancelled', body: 'A recovery of your account by email was cancelled.', path: '#account', tag: `email-recovery-${id}` }, now);
    return { cancelled: id };
  }

  /**
   * Where an email recovery stands for the key that asked: pending (waiting for the link, or for
   * the wait to end), denied (cancelled), or allowed; the first allowed answer is audited and
   * announced, and the Worker issues the credential (the same one on every repeat).
   */
  async op_email_recovery_status({ id, jkt }, now) {
    let announce = null;
    const result = await this.tx(async tx => {
      announce = null;
      const rec = await tx.get(emailKey(id));
      if (!rec || rec.jkt !== jkt || (rec.state === 'link_sent' && rec.until <= now)) return { status: 'pending', stage: 'waiting_for_link' };
      if (rec.state === 'link_sent') return { status: 'pending', stage: 'waiting_for_link' };
      if (rec.state === 'cancelled') return { status: 'denied' };
      if (rec.ready_at > now) return { status: 'pending', stage: 'waiting', ready_at: rec.ready_at };
      if (rec.state !== 'done') {
        await tx.put(emailKey(id), { ...rec, state: 'done', recovered_at: now });
        await this.audit(tx, now, 'recovery.email_completed', { id, jkt });
        announce = rec;
      }
      return { status: 'allowed' };
    });
    if (announce) await this.alert({ title: 'Account recovered onto a new device', body: `After the ${EMAIL_RECOVERY_WAIT_MS / 3600000}-hour wait, “${announce.device_name}” got into your account by email. If that was not you, revoke it and remove the email address.`, path: '#credentials', tag: `recovered-${id}` }, now);
    return result;
  }

  /** Email recoveries still waiting, for the owner to see and cancel. */
  async pendingEmailRecoveries(now) {
    return [...(await this.storage.list({ prefix: 'emailrec:' })).values()]
      .filter(r => (r.state === 'link_sent' || r.state === 'waiting') && r.until > now)
      .map(r => ({ id: r.id, device_name: r.device_name, state: r.state, requested_at: r.requested_at, ready_at: r.ready_at ?? null }));
  }
}
