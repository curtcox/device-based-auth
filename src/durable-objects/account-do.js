import { assert, errorResponse, ApiError } from '../utils/errors.js';
import { charge, deposit, readBalance, money } from './ledger.js';
import { randomId } from '../utils/ids.js';
import { requestUntil } from './gate-requests.js';
import { PAGE, scheduleCompaction, dashboardState } from './account/shared.js';
import { AccountKeys } from './account/keys.js';
import { AccountCredentials } from './account/credentials.js';
import { AccountNotices } from './account/notices.js';
import { AccountAuthorize } from './account/authorize.js';
import { AccountGates } from './account/gates.js';
import { AccountGateDelivery } from './account/gate-delivery.js';
import { AccountSignIn } from './account/sign-in.js';
import { AccountReverify } from './account/reverify.js';
import { AccountRecovery } from './account/recovery.js';
import { AccountEmailAddress } from './account/email-address.js';
import { AccountClerkLink } from './account/clerk-link.js';
import { AccountCompaction } from './account/compaction.js';
import { AccountEmail, SECURITY_EMAIL_LEVELS } from './account/email.js';
import { AccountAddressLists } from './account/address-lists.js';
import { cleanEmailAddress } from '../services/email.js';

export { RECORD_RETENTION_MS, EXPIRED_VISIBLE_MS, COMPACTION_INTERVAL_MS, enrollmentTokenState } from './account/shared.js';
export { credentialState } from './account/credentials.js';
export { usageCounter, sameStatusEntry } from './account/authorize.js';

const DECISION_RETENTION_MS = 90 * 86400000;

/**
 * Budget guards the owner can change in the dashboard (master plan §5.4, §10). A stolen session or
 * a runaway script can issue at most max_issues_per_day credentials; a device stuck in a renewal
 * loop stops after max_renewals_per_credential_per_month (null: no cap). security_email chooses
 * which security emails the owner gets (account/email.js): all, sensitive events only, or none.
 */
export const SETTINGS_DEFAULTS = Object.freeze({ max_issues_per_day: 500, max_renewals_per_credential_per_month: null, security_email: 'all' });
export const SETTINGS_CHOICES = Object.freeze({ security_email: SECURITY_EMAIL_LEVELS });
export const SETTINGS_LIMITS = Object.freeze({ max_issues_per_day: [1, 100000], max_renewals_per_credential_per_month: [1, 100000] });

/**
 * One Durable Object per account: balance and ledger, API keys, devices, credentials,
 * usage counters, step-up approvals, online decisions and the audit trail.
 * Its storage is the source of truth for revocation; status lists are published copies.
 * This file holds the entry points (fetch, alarm) and the account's balance, settings and lists;
 * the other operations live by area in ./account/ and are mixed in below.
 */
export class AccountDO {
  constructor(ctx, env) {
    this.ctx = ctx; this.storage = ctx.storage; this.env = env;
    this.proofs = new Map(); this.rates = new Map();
    // The seen-proof caches above start empty whenever this object starts (an eviction after idle,
    // a deploy, a move), so it cannot tell whether a proof made before it started was already used.
    // Until CLOCK_SKEW seconds after the start it asks for its own nonce in each proof (RFC 9449 §8;
    // account/credentials.js op_credential_status), which no earlier object could have seen.
    this.startedAt = Date.now(); this.dpopNonce = randomId('dpn', 22);
    // New gate requests per (device, gate) in the last hour (in memory, like the request limit).
    this.gateRates = new Map();
    // Wrong TOTP codes and security-key answers per gate (in memory; a guessing limit).
    this.factorFailures = new Map();
    // When each vendor push was last polled ("<request>:<entry>:<gate>" -> ms), to space polls.
    this.vendorPolls = new Map();
    // Work that outlives the request (security notices). Tests await it with settle().
    this.inflight = new Set();
  }

  /** Run work after the response; a Durable Object stays alive while it is pending. */
  background(promise) {
    const tracked = promise.catch(() => {}).finally(() => this.inflight.delete(tracked));
    this.inflight.add(tracked);
    this.ctx.waitUntil?.(tracked);
  }

  async fetch(request) {
    try {
      const args = await request.json();
      const handler = this[`op_${args.op.replaceAll('-', '_')}`];
      assert(typeof handler === 'function', 'unknown_operation', 'Unknown account operation', 500);
      return Response.json(await handler.call(this, args, args.now ?? Date.now()));
    } catch (error) { return errorResponse(error); }
  }

  tx(fn) { return this.storage.transaction(fn); }

  async audit(tx, now, type, detail = {}) {
    const id = randomId('evt', 10);
    await tx.put(`audit:${new Date(now).toISOString()}:${id}`, { id, type, at: now, ...detail });
  }

  async settings(tx) { return { ...SETTINGS_DEFAULTS, ...((await tx.get('settings')) || {}) }; }

  async op_get_settings() { return this.tx(tx => this.settings(tx)); }

  /**
   * Change settings (validated by the caller); audited, because raising a cap matters. Raising a
   * limit is emailed like other takeover-sensitive changes, and turning security emails down
   * sends one last email even when they are now off.
   */
  async op_update_settings({ changes }, now) {
    const { before, next } = await this.tx(async tx => {
      const before = await this.settings(tx);
      const next = { ...before, ...changes };
      await tx.put('settings', next);
      await this.audit(tx, now, 'settings.changed', { before, after: next });
      return { before, next };
    });
    const raised = Object.keys(SETTINGS_LIMITS).filter(name => before[name] !== null && (next[name] === null || next[name] > before[name]));
    if (raised.length) await this.alert({ title: 'Budget limit raised', body: `Raised: ${raised.map(name => `${name.replaceAll('_', ' ')} ${before[name]} → ${next[name] ?? 'no cap'}`).join('; ')}.`, path: '#account', tag: `settings-${now}` }, now);
    const levels = SECURITY_EMAIL_LEVELS;
    if (levels.indexOf(next.security_email) < levels.indexOf(before.security_email)) {
      await this.emailNow({ title: next.security_email === 'off' ? 'Security emails turned off' : 'Security emails reduced', body: next.security_email === 'off' ? 'Security emails for your account were turned off; this is the last one.' : 'From now on only takeover-sensitive events (credentials that can act on your account, API keys, enrollment tokens, gates, raised limits) are emailed; other issuances are not.', path: '#account' }, now, { always: true });
    }
    return next;
  }

  /**
   * Create the account on first sight. `email` (the primary address Clerk verified, from its
   * user.created/user.updated webhook) is where security emails go; a change is audited. An
   * address devicebasedauth.org verified itself (account/email-address.js) is never replaced by
   * Clerk's.
   * `signup` ({ id, jkt }, from a paid sign-up: api/signup.js) binds a new account to the key that
   * signed up; it never attaches to an account that already exists. `link_sub` (a Clerk session or
   * webhook naming this account through `dba_account`) must be the Clerk user linked here
   * (account/clerk-link.js); otherwise nothing is created and the session is refused.
   */
  async op_init({ account, rate, session, email, signup, link_sub }, now) {
    if (rate) await this.op_rate_limit(rate, now);
    const address = email === undefined ? undefined : cleanEmailAddress(email);
    return this.tx(async tx => {
      let profile = await tx.get('profile');
      if (link_sub !== undefined) assert(profile?.clerk_sub === link_sub, 'invalid_auth', 'This sign-in is not linked to that account', 401);
      const dashboard = session ? await dashboardState(tx, session, now) : undefined;
      if (!profile) { profile = { account, created_at: now, ...(signup ? { created_via: 'signup', signup: { id: signup.id, jkt: signup.jkt }, terms_accepted_at: now } : {}) }; await tx.put('profile', profile); }
      if (address !== undefined && profile.email_source !== 'verified' && (profile.email ?? null) !== address) {
        const had = !!profile.email;
        profile = { ...profile, email: address, email_source: 'clerk' };
        if (!address) { delete profile.email; delete profile.email_source; }
        await tx.put('profile', profile);
        await this.audit(tx, now, 'account.email_changed', { had_address: had, has_address: !!address });
      }
      return { ...profile, dashboard };
    });
  }

  /**
   * Has this sign-up been paid (the webhook created the account bound to this key)? Reads only:
   * a device polling before the payment arrives must not create the account.
   */
  async op_signup_status({ id, jkt }) {
    const signup = (await this.storage.get('profile'))?.signup;
    return { paid: !!signup && signup.id === id && signup.jkt === jkt };
  }

  /** The account summary. `funds_check: true` (a pre-check before a charge) writes nothing. */
  async op_account({ funds_check = false }, now) {
    return this.tx(async tx => {
      const profile = (await tx.get('profile')) || {};
      const state = await readBalance(tx, now, funds_check ? { flush: false } : undefined);
      return { account: profile.account, created_at: profile.created_at, security_email_address: profile.email ?? null, security_email_source: profile.email ? profile.email_source ?? 'clerk' : null, security_email_pending: profile.email_pending && profile.email_pending.expires_at > now ? profile.email_pending.address : null, created_via: profile.created_via ?? 'clerk', clerk_linked: !!profile.clerk_sub, balance_microdollars: state.balance_microdollars, month: state.month, today: state.day };
    });
  }

  /**
   * One audience's online decisions, sign-ins and spend per month, newest first (this month plus
   * up to `months - 1` earlier ones). The caller checks that the account owns the audience.
   */
  async op_audience_usage({ audience, months = 12 }, now) {
    return this.tx(async tx => {
      const state = await readBalance(tx, now);
      const older = Math.min(months, 24) - 1;
      const earlier = older > 0 ? [...(await tx.list({ prefix: 'month:', reverse: true, limit: older })).values()] : [];
      const items = [state.month, ...earlier].map(m => {
        const usage = m.by_audience?.[audience] || { counts: {}, spent_microdollars: 0 };
        return { period: m.period, decisions: usage.counts.decision || 0, logins: usage.counts.login || 0, spent_microdollars: usage.spent_microdollars };
      });
      return { audience, items };
    });
  }

  /** Local development only: forget seen proofs and start a new nonce epoch, as a restart would. */
  async op_dev_fresh_object(_args, now) {
    assert(this.env.ENVIRONMENT === 'local', 'not_found', 'Not found', 404);
    this.proofs = new Map(); this.startedAt = now; this.dpopNonce = randomId('dpn', 22);
    return { fresh: true };
  }

  async op_deposit({ id, amount, kind }, now) { return this.tx(tx => deposit(tx, { id, amount, kind }, now)); }

  async op_charge({ id, kind, amount, aggregate, detail }, now) {
    return this.tx(async tx => {
      const paid = await charge(tx, { id, kind, amount, aggregate, detail }, now);
      // A charge of its own (an audience change) leaves ledger and receipt rows to age out.
      if (!aggregate && !paid.duplicate) await scheduleCompaction(tx, now);
      return paid;
    });
  }

  /** Best-effort per-account request limit (in memory; no storage writes). */
  async op_rate_limit({ id = 'api', limit = 120, window_ms = 60000 }, now) {
    const entry = this.rates.get(id);
    if (!entry || entry.reset <= now) { this.rates.set(id, { count: 1, reset: now + window_ms }); return { ok: true }; }
    entry.count += 1;
    assert(entry.count <= limit, 'rate_limited', 'Too many requests for this account', 429);
    return { ok: true };
  }

  async op_list({ prefix, cursor, limit = PAGE }) {
    assert(['ledger:', 'audit:'].includes(prefix), 'invalid_prefix', 'Unknown list');
    const rows = [...await this.storage.list({ prefix, reverse: true, limit: Math.min(limit, 200), ...(cursor ? { end: cursor } : {}) })];
    return { items: rows.map(([, v]) => v), next_cursor: rows.length === Math.min(limit, 200) ? rows.at(-1)[0] : null };
  }

  // ---- Alarms -------------------------------------------------------------------

  /** Make sure the alarm fires no later than `at`. */
  async alarmBy(at) {
    const current = await this.storage.getAlarm();
    if (!current || current > at) await this.storage.setAlarm(at);
  }

  async scheduleWake(tx, at) {
    const alarm = await tx.getAlarm();
    if (!alarm || alarm > at) await tx.setAlarm(at);
  }

  async alarm() {
    const now = Date.now();
    const pollAt = await this.pollPushes(now);
    const compactAt = await this.compact(now);
    const { next_at: outboxAt } = await this.deliverOutbox(now);
    const mailAt = await this.deliverEmail(now);
    const listsAt = await this.publishDueLists(now);
    let more = false;
    // Prune expired decisions, usage windows, step-ups and authorization codes.
    for (const [key, value] of await this.storage.list({ prefix: 'decision:', limit: 500 })) {
      if (value.at < now - DECISION_RETENTION_MS) await this.storage.delete(key);
    }
    // Gate requests and authorization codes are useless once their time is over; the next wake-up
    // is set for the first one still live, so none outlives it for long on an account that has
    // nothing else to do.
    let shortLived = null;
    for (const prefix of ['gatereq:', 'code:', 'dashsess:', 'emailrec:']) for (const [key, value] of await this.storage.list({ prefix })) {
      const until = prefix === 'gatereq:' ? requestUntil(value) : prefix === 'dashsess:' || prefix === 'emailrec:' ? value.until : value.expires_at;
      if (until <= now) await this.storage.delete(key);
      else shortLived = Math.min(shortLived ?? Infinity, until);
    }
    const usage = await this.storage.list({ prefix: 'usage:', limit: 1000 });
    for (const key of usage.keys()) {
      const [, cid, , start] = key.split(':');
      const cred = await this.storage.get(`cred:${cid}`);
      if (!cred || (cred.exp * 1000 < now) || (Number(start) > 0 && Number(start) * 1000 < now - 31 * 86400000)) await this.storage.delete(key);
    }
    more = usage.size === 1000;
    const hasWork = (await this.storage.list({ prefix: 'decision:', limit: 1 })).size || (await this.storage.list({ prefix: 'outbox:', limit: 1 })).size;
    // The outbox's retry time wins over the daily pruning pass.
    const next = [hasWork || more ? now + (more ? 60000 : 86400000) : null, outboxAt, compactAt, mailAt, shortLived === null ? null : Math.max(shortLived, now + 60000), pollAt, listsAt].filter(t => t !== null);
    if (next.length) await this.storage.setAlarm(Math.min(...next));
  }
}

/**
 * The account's operations by area (./account/). Each group is a class whose methods run with
 * `this` bound to the AccountDO, as when they were written in one class: they are copied onto its
 * prototype so op_* dispatch, the alarm and tests find them on the object itself.
 */
const OPERATION_GROUPS = [AccountKeys, AccountCredentials, AccountNotices, AccountAuthorize, AccountGates, AccountGateDelivery, AccountSignIn, AccountReverify, AccountRecovery, AccountEmailAddress, AccountClerkLink, AccountCompaction, AccountEmail, AccountAddressLists];
for (const group of OPERATION_GROUPS) {
  for (const [name, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(group.prototype))) {
    if (name === 'constructor') continue;
    // Two groups defining one name would silently replace a method; refuse to load instead.
    if (Object.hasOwn(AccountDO.prototype, name)) throw new Error(`AccountDO.${name} is defined twice`);
    Object.defineProperty(AccountDO.prototype, name, descriptor);
  }
}

export { money, ApiError };
