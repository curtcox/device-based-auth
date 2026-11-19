import { assert, errorResponse, ApiError } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { charge, deposit, readBalance, money } from './ledger.js';
import { periodSeconds, actionNamespace } from '../../packages/verify/src/grants.js';
import { randomId } from '../utils/ids.js';
import { signEvent, postEvent, WEBHOOK_ATTEMPTS, WEBHOOK_BACKOFF_MS } from '../services/webhooks.js';
import { MAX_SUBSCRIPTIONS, broadcast, nextNotice, noticeText } from '../services/push.js';
import { hasDbaAction } from '../auth/reverify.js';

const PAGE = 50;
const EVENTS_KEPT = 50;
const DECISION_RETENTION_MS = 90 * 86400000;
const STEP_UP_TTL_MS = 10 * 60000;
const STEP_UP_APPROVED_TTL_MS = 5 * 60000;
const OUTBOX_RETRY_MS = 60000;
// Records are prepaid for 13 months (master plan §8.3, docs/business/pricing.md). After that,
// compact() drops them so no account's storage grows forever on what it once paid.
export const RECORD_RETENTION_MS = 395 * 86400000;
// An expired credential stays visible this long even if it is older than the retention period
// (a renewed credential can be years old when it finally expires).
export const EXPIRED_VISIBLE_MS = 30 * 86400000;
// Compaction runs at most this often, so its alarm wake-up and bookkeeping write are shared by
// everything that fell due in between.
export const COMPACTION_INTERVAL_MS = 7 * 86400000;
const COMPACTION_PAGE = 500;
const pad = n => String(n).padStart(15, '0');

/**
 * One Durable Object per account: balance and ledger, API keys, devices, credentials,
 * usage counters, step-up approvals, online decisions and the audit trail.
 * Its storage is the source of truth for revocation; status lists are published copies.
 */
/**
 * Budget guards the owner can change in the dashboard (master plan §5.4, §10). A stolen session or
 * a runaway script can issue at most max_issues_per_day credentials; a device stuck in a renewal
 * loop stops after max_renewals_per_credential_per_month (null: no cap).
 */
export const SETTINGS_DEFAULTS = Object.freeze({ max_issues_per_day: 500, max_renewals_per_credential_per_month: null });
export const SETTINGS_LIMITS = Object.freeze({ max_issues_per_day: [1, 100000], max_renewals_per_credential_per_month: [1, 100000] });

const monthOf = now => new Date(now).toISOString().slice(0, 7);

export class AccountDO {
  constructor(ctx, env) {
    this.ctx = ctx; this.storage = ctx.storage; this.env = env;
    this.proofs = new Map(); this.rates = new Map();
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

  /** Change settings (validated by the caller); audited, because raising a cap matters. */
  async op_update_settings({ changes }, now) {
    return this.tx(async tx => {
      const before = await this.settings(tx);
      const next = { ...before, ...changes };
      await tx.put('settings', next);
      await this.audit(tx, now, 'settings.changed', { before, after: next });
      return next;
    });
  }

  async op_init({ account, rate }, now) {
    if (rate) await this.op_rate_limit(rate, now);
    return this.tx(async tx => {
      const profile = await tx.get('profile');
      if (profile) return profile;
      const created = { account, created_at: now };
      await tx.put('profile', created);
      return created;
    });
  }

  /** The account summary. `funds_check: true` (a pre-check before a charge) writes nothing. */
  async op_account({ funds_check = false }, now) {
    return this.tx(async tx => {
      const profile = (await tx.get('profile')) || {};
      const state = await readBalance(tx, now, funds_check ? { flush: false } : undefined);
      return { account: profile.account, created_at: profile.created_at, balance_microdollars: state.balance_microdollars, month: state.month, today: state.day };
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

  // ---- API keys -------------------------------------------------------------

  /**
   * An API key, or (with `oauth`) an app connected through the MCP OAuth flow, whose hash is the
   * digest of its current refresh token (src/api/mcp-oauth.js). Both count toward the 25.
   */
  async op_create_key({ id, name, scopes, hash, oauth }, now) {
    return this.tx(async tx => {
      const keys = await tx.list({ prefix: 'key:' });
      assert([...keys.values()].filter(k => !k.revoked_at).length < 25, 'too_many_keys', 'At most 25 active API keys and connected apps; revoke one in the dashboard');
      const key = { id, name, scopes, hash, created_at: now, ...(oauth ? { kind: 'oauth', oauth } : {}) };
      await tx.put(`key:${id}`, key); await this.audit(tx, now, oauth ? 'app.connected' : 'key.created', { key_id: id, name, scopes });
      return visibleKey(key);
    }).then(async key => {
      this.notify({ title: oauth ? 'App connected to your account' : 'API key created', body: `${oauth ? 'An app' : 'An API key'} “${noticeText(name)}” can now act for your devicebasedauth.org account (${scopes.join(', ')}).`, path: '#keys', tag: `key-${id}` }, now);
      return key;
    });
  }

  async op_list_keys() {
    const keys = await this.storage.list({ prefix: 'key:' });
    const refreshed = (await this.storage.get('balance'))?.refresh || {};
    return { items: [...keys.values()].map(k => visibleKey(refreshed[k.id] ? { ...k, refreshed_at: refreshed[k.id].at } : k)) };
  }

  /** A connected app's access token: the record must exist, be an app, and not be revoked. */
  async op_authenticate_oauth_key({ id, rate }, now) {
    if (rate) await this.op_rate_limit(rate, now);
    // Reads only: a "last used" write here would be an unpaid row every hour. The hourly refresh
    // already records refreshed_at.
    const key = await this.storage.get(`key:${id}`);
    assert(key && key.kind === 'oauth' && !key.revoked_at, 'invalid_token', 'This app connection was revoked', 401);
    return { scopes: key.scopes };
  }

  /**
   * Rotate a connected app's refresh token. Presenting an old one means a copy leaked (or the app
   * raced itself): the connection is revoked (OAuth 2.1 §4.3.1) and the caller refused.
   */
  async op_rotate_oauth_key({ id, hash, client, new_hash, scopes, price }, now) {
    const outcome = await this.tx(async tx => {
      const key = await tx.get(`key:${id}`);
      if (!key || key.kind !== 'oauth' || key.revoked_at || key.oauth.client !== client) return { refused: true };
      // The current refresh token's digest lives on the balance row once the app has refreshed
      // (see below); before that, on the key record.
      const current = (await readBalance(tx, now, { flush: false })).refresh?.[id]?.hash ?? key.hash;
      if (current !== hash) {
        key.revoked_at = now; key.revoked_reason = 'refresh token reused';
        await tx.put(`key:${id}`, key); await this.audit(tx, now, 'key.revoked', { key_id: id, reason: key.revoked_reason });
        await scheduleCompaction(tx, now);
        await forgetRefresh(tx, id, now);
        return { refused: true };
      }
      const granted = scopes ?? key.scopes;
      if (!granted.every(s => key.scopes.includes(s))) return { refused: true, scope: true };
      // A refresh issues an hour's access token: charged as a token. The new digest rides on the
      // balance row the charge writes anyway, so the refresh costs no row of its own.
      const paid = await charge(tx, { kind: 'token', amount: price, aggregate: true, annotate: state => { (state.refresh ||= {})[id] = { hash: new_hash, at: now }; } }, now);
      return { scopes: granted, charged: paid.charged };
    });
    assert(!outcome.scope, 'invalid_scope', 'scope must be within what was approved', 400);
    assert(!outcome.refused, 'invalid_grant', 'Refresh token is invalid, used or revoked', 400);
    return outcome;
  }

  async op_revoke_key({ id }, now) {
    return this.tx(async tx => {
      const key = await tx.get(`key:${id}`); assert(key, 'not_found', 'API key not found', 404);
      if (!key.revoked_at) { key.revoked_at = now; await tx.put(`key:${id}`, key); await this.audit(tx, now, 'key.revoked', { key_id: id }); await scheduleCompaction(tx, now); if (key.kind === 'oauth') await forgetRefresh(tx, id, now); }
      return visibleKey(key);
    });
  }

  async op_authenticate_key({ id, hash, rate }, now) {
    if (rate) await this.op_rate_limit(rate, now);
    const key = await this.storage.get(`key:${id}`);
    assert(key && key.kind !== 'oauth' && !key.revoked_at && key.hash === hash, 'invalid_auth', 'Invalid API key', 401);
    return { scopes: key.scopes };
  }

  // ---- Enrollment tokens (B2) ---------------------------------------------------
  // A pre-approved template (audiences, grants, lifetime) with a use count and an expiry. Devices
  // holding the token enroll without a per-device approval; each use issues and pays like any
  // other credential. Only the token's digest is stored.

  async op_create_enrollment_token({ id, name, hash, template, max_uses, expires_at }, now) {
    return this.tx(async tx => {
      const active = [...(await tx.list({ prefix: 'etok:' })).values()].filter(t => enrollmentTokenState(t, now) === 'active');
      assert(active.length < 50, 'too_many_tokens', 'At most 50 active enrollment tokens');
      const token = { id, name, hash, template, max_uses, uses: 0, expires_at, created_at: now };
      await tx.put(`etok:${id}`, token);
      await this.audit(tx, now, 'enrollment_token.created', { token_id: id, name, aud: template.aud, max_uses });
      await scheduleCompaction(tx, now);
      return visibleToken(token, now);
    }).then(token => {
      this.notify({ title: 'Enrollment token created', body: `“${noticeText(name)}” lets up to ${max_uses} devices enroll for ${noticeText(template.aud.join(', '), 120)} without approval.`, path: '#tokens', tag: `etok-${id}` }, now);
      return token;
    });
  }

  async op_list_enrollment_tokens(_args, now) {
    return { items: [...(await this.storage.list({ prefix: 'etok:' })).values()].map(t => visibleToken(t, now)).reverse() };
  }

  async op_revoke_enrollment_token({ id }, now) {
    return this.tx(async tx => {
      const token = await tx.get(`etok:${id}`); assert(token, 'not_found', 'Enrollment token not found', 404);
      if (!token.revoked_at) { token.revoked_at = now; await tx.put(`etok:${id}`, token); await this.audit(tx, now, 'enrollment_token.revoked', { token_id: id }); }
      return visibleToken(token, now);
    });
  }

  /** Check a presented token before any issuing work (no writes; rate-limited per token in memory). */
  async op_check_enrollment_token({ id, hash }, now) {
    const token = await this.storage.get(`etok:${id}`);
    assert(token && token.hash === hash, 'invalid_enrollment_token', 'Enrollment token is invalid', 401);
    assert(enrollmentTokenState(token, now) === 'active', 'enrollment_token_inactive', `Enrollment token is ${enrollmentTokenState(token, now)}`, 403);
    await this.op_rate_limit({ id: `etok:${id}`, limit: 60 }, now);
    return { template: token.template, name: token.name };
  }

  // ---- Credentials ------------------------------------------------------------

  /**
   * Charge and store a newly signed credential (and its device). The Worker signs first so the
   * stored JWS is exactly what the device receives; if the charge fails nothing is kept.
   */
  async op_store_credential({ record, device, price, charge_id, fingerprint, reinstate = false, source, enrollment_token }, now) {
    let announce = 0; let reinstated = false;
    const urgent = hasDbaAction(record.grants);
    const stored = await this.tx(async tx => {
      announce = 0; reinstated = false;
      const subscribed = (await tx.get('push:subs'))?.length > 0;
      const settings = await this.settings(tx);
      let token = null;
      if (enrollment_token) {
        token = await tx.get(`etok:${enrollment_token.id}`);
        assert(token && token.hash === enrollment_token.hash, 'invalid_enrollment_token', 'Enrollment token is invalid', 401);
      }
      const issuedToday = (await readBalance(tx, now, { flush: false })).day.counts?.issue || 0; // before this charge counts
      const paid = await charge(tx, { id: charge_id, kind: 'issue', amount: price, detail: { cid: record.cid }, receipt: { cid: record.cid, ...(fingerprint ? { fingerprint } : {}) }, annotate: subscribed ? state => { announce = nextNotice(state, now, urgent); } : undefined }, now);
      // The same charge id again (an Idempotency-Key retry, two approvals of one enrollment racing):
      // hand back what the first request issued. Storing this one would be a credential nobody paid for.
      if (paid.duplicate) return this.issuedBefore(tx, paid, fingerprint, now);
      // Count the token use in the same transaction that stores the credential, so a token can never
      // issue more than max_uses even under concurrent redemptions. A throw below undoes the charge.
      if (token) {
        assert(enrollmentTokenState(token, now) === 'active', 'enrollment_token_inactive', `Enrollment token is ${enrollmentTokenState(token, now)}`, 403);
        token.uses += 1; token.last_used_at = now;
        await tx.put(`etok:${token.id}`, token);
        record = { ...record, enrollment_token: token.id };
      }
      assert(issuedToday < settings.max_issues_per_day, 'issuance_limit', `This account may issue ${settings.max_issues_per_day} credentials a day (UTC); the owner can raise the limit in the dashboard`, 429, { limit: settings.max_issues_per_day });
      const existing = await tx.get(`device:${device.id}`);
      // A revoked device stays revoked unless a person who signed in recently issues to it again
      // (master plan §10); a fleet token or a delegating device never brings it back.
      assert(!existing?.revoked_at || reinstate, 'device_revoked', 'This device was revoked. Only the account owner, signed in within the last few minutes, can issue to it again', 403, { device_id: device.id });
      const stored = existing ? { ...existing, name: device.name || existing.name, ...(device.attestation ? { attestation: device.attestation, key_protection: device.key_protection } : {}), last_issued_at: now } : { ...device, created_at: now, last_issued_at: now };
      if (stored.revoked_at) { delete stored.revoked_at; stored.reinstated_at = now; }
      await tx.put(`device:${device.id}`, stored);
      const cred = { ...record, created_at: now, events: [{ at: now, type: 'issued', jti: record.jti, source }] };
      await tx.put(`cred:${record.cid}`, cred);
      await this.audit(tx, now, 'credential.issued', { cid: record.cid, device_id: device.id, aud: record.aud, source, ...(record.enrollment_token ? { token_id: record.enrollment_token } : {}) });
      if (existing?.revoked_at) { reinstated = true; await this.audit(tx, now, 'device.reinstated', { device_id: device.id, cid: record.cid }); }
      await scheduleCompaction(tx, now);
      return { cid: record.cid, charged: price, balance_microdollars: paid.balance_microdollars };
    });
    if (announce || (reinstated && (await this.storage.get('push:subs'))?.length)) {
      const what = `${noticeText(device.name) || 'a device'} for ${noticeText(record.aud.join(', '), 120)}`;
      const more = announce > 1 ? ` (and ${announce - 1} more since the last notice)` : '';
      this.notify({
        title: reinstated ? 'Revoked device reinstated' : urgent ? 'Credential with account access issued' : 'Credential issued',
        body: reinstated ? `A revoked device, ${what}, was issued a credential again.` : urgent ? `${what} can now act on your devicebasedauth.org account.` : `${what}${more}.`,
        path: `#credential/${encodeURIComponent(record.cid)}`, tag: urgent || reinstated ? `cred-${record.cid}` : 'issued'
      }, now);
    }
    return stored;
  }

  /** The credential a repeated charge id already paid for, if the request is the same one. */
  async issuedBefore(tx, receipt, fingerprint, now) {
    assert(receipt.cid && (receipt.fingerprint ?? null) === (fingerprint ?? null), 'idempotency_key_reused', 'This Idempotency-Key was already used for a different request', 422);
    const cred = await tx.get(`cred:${receipt.cid}`);
    assert(cred, 'idempotency_key_reused', 'This Idempotency-Key was already used for a different request', 422);
    return { duplicate: true, cid: cred.cid, jws: cred.jws, device_id: cred.device_id, charged: 0, balance_microdollars: (await readBalance(tx, now)).balance_microdollars };
  }

  async op_get_credential({ cid }) {
    const cred = await this.storage.get(`cred:${cid}`);
    assert(cred, 'not_found', 'Credential not found', 404);
    return cred;
  }

  async op_list_credentials({ status, audience, device_id, cursor, limit = PAGE }, now) {
    const items = []; let next = null;
    const rows = await this.storage.list({ prefix: 'cred:', ...(cursor ? { startAfter: cursor } : {}) });
    for (const [key, cred] of rows) {
      const state = credentialState(cred, now);
      if (status && state !== status) continue;
      if (audience && !cred.aud.includes(audience)) continue;
      if (device_id && cred.device_id !== device_id) continue;
      if (items.length === Math.min(limit, 200)) { next = items.at(-1).key; break; }
      const { jws: _jws, events: _events, ...summary } = cred;
      items.push({ ...summary, state, key });
    }
    return { items: items.map(({ key: _key, ...i }) => i), next_cursor: next };
  }

  async op_list_devices({ cursor }, now) {
    const devices = [...(await this.storage.list({ prefix: 'device:', ...(cursor ? { startAfter: cursor } : {}), limit: 200 })).values()];
    const creds = [...(await this.storage.list({ prefix: 'cred:' })).values()];
    return { items: devices.map(d => ({ ...d, credentials: creds.filter(c => c.device_id === d.id).map(c => ({ cid: c.cid, aud: c.aud, state: credentialState(c, now), exp: c.exp })) })) };
  }

  async op_get_device({ id }, now) {
    const device = await this.storage.get(`device:${id}`);
    assert(device, 'not_found', 'Device not found', 404);
    const creds = [...(await this.storage.list({ prefix: 'cred:' })).values()].filter(c => c.device_id === id);
    return { ...device, credentials: creds.map(({ jws: _jws, ...c }) => ({ ...c, state: credentialState(c, now) })) };
  }

  /** Online status for one credential (used by the API's own DBA-credential auth and renewals). */
  /**
   * proof_key/proof_exp: a DPoP proof presented to devicebasedauth.org's own API. DPoP does not
   * sign the body, so a proof seen once (a logging proxy, a leaked header) must not be accepted
   * again with another body. The account's single DO instance makes this a global check.
   */
  async op_credential_status({ cid, with_jws = false, proof_key, proof_exp, rate }, now) {
    if (rate) await this.op_rate_limit(rate, now);
    const cred = await this.storage.get(`cred:${cid}`);
    if (!cred) return { exists: false, revoked: true };
    if (proof_key) {
      const nowSeconds = Math.floor(now / 1000);
      for (const [key, exp] of this.proofs) { if (exp > nowSeconds) break; this.proofs.delete(key); }
      if (this.proofs.has(proof_key)) return { exists: true, replayed: true };
      this.proofs.set(proof_key, proof_exp);
    }
    return { exists: true, ...(with_jws ? { jws: cred.jws } : {}), revoked: !!cred.revoked_at, state: credentialState(cred, now), jti: cred.jti, exp: cred.exp, grants: cred.grants, aud: cred.aud, device_id: cred.device_id, jkt: cred.jkt, lifetime: cred.lifetime, max_exp: cred.max_exp, status: cred.status, device: cred.device, ...(cred.parent_cid ? { parent_cid: cred.parent_cid } : {}) };
  }

  async revokeOne(tx, cred, now, reason) {
    if (cred.revoked_at) return false;
    cred.revoked_at = now; cred.revoked_reason = reason;
    cred.events = [...cred.events, { at: now, type: 'revoked', reason }].slice(-EVENTS_KEPT);
    await tx.put(`cred:${cred.cid}`, cred);
    // One outbox entry carries both jobs: publish the status bit, and tell each audience that has a
    // revocation webhook (B1). Sharing the entry keeps the success path free of extra writes.
    await tx.put(`outbox:${cred.cid}`, { shard: cred.status.shard, idx: cred.status.idx, at: now, cid: cred.cid, jti: cred.jti, exp: cred.exp, uri: cred.status.uri, hooks: [...cred.aud] });
    await this.audit(tx, now, 'credential.revoked', { cid: cred.cid, reason });
    return true;
  }

  /** Revoke one credential, every credential of a device, or every credential (optionally for one audience). */
  async op_revoke({ cid, device_id, all, audience, reason = 'revoked by owner' }, now) {
    const revoked = await this.tx(async tx => {
      const targets = [];
      if (cid) { const cred = await tx.get(`cred:${cid}`); assert(cred, 'not_found', 'Credential not found', 404); targets.push(cred); }
      else {
        assert(device_id || all, 'invalid_request', 'Name a credential, a device, or all');
        if (device_id) {
          const device = await tx.get(`device:${device_id}`); assert(device, 'not_found', 'Device not found', 404);
          if (!device.revoked_at) { device.revoked_at = now; await tx.put(`device:${device_id}`, device); }
        }
        for (const cred of (await tx.list({ prefix: 'cred:' })).values()) {
          if (device_id && cred.device_id !== device_id) continue;
          if (audience && !cred.aud.includes(audience)) continue;
          targets.push(cred);
        }
      }
      const done = [];
      for (const cred of targets) if (await this.revokeOne(tx, cred, now, reason)) done.push(cred.cid);
      // Credentials a revoked device delegated are revoked with it (transitively).
      const every = [...(await tx.list({ prefix: 'cred:' })).values()];
      for (let i = 0; i < done.length; i++) {
        for (const child of every) if (child.parent_cid === done[i] && await this.revokeOne(tx, child, now, `issuer ${done[i]} revoked`)) done.push(child.cid);
      }
      return done;
    });
    await this.deliverOutbox(now, { send: false });
    return { revoked, count: revoked.length };
  }

  /** Make sure the alarm fires no later than `at`. */
  async alarmBy(at) {
    const current = await this.storage.getAlarm();
    if (!current || current > at) await this.storage.setAlarm(at);
  }

  /**
   * Push revocations to the status-list shards (retried by alarm until delivered) and to the
   * revocation webhooks of the credentials' audiences (WEBHOOK_ATTEMPTS rounds, then dropped:
   * webhooks only speed things up, the status lists stay authoritative). Returns the time the
   * outbox next needs attention, or null. send=false publishes status bits only and leaves the
   * webhook calls to an alarm that fires at once, so a revoke never waits on someone's endpoint.
   */
  async deliverOutbox(now = Date.now(), { send = true } = {}) {
    let nextAt = null; const later = at => { nextAt = nextAt === null ? at : Math.min(nextAt, at); };
    let failed = false; let startAfter;
    // Page through the outbox, so entries waiting on a webhook's backoff never hide newer ones.
    for (let page = 0; page < 10; page++) {
      const result = await this.deliverOutboxPage(now, send, startAfter, later);
      failed ||= result.failed;
      if (!result.last) break;
      startAfter = result.last;
      if (page === 9) later(now + 1000);
    }
    if (nextAt !== null) await this.alarmBy(nextAt);
    return { delivered: !failed, next_at: nextAt };
  }

  /** One page (≤ 100 entries) of deliverOutbox. Returns { failed, last } (last: key to continue after). */
  async deliverOutboxPage(now, send, startAfter, later) {
    const pending = await this.storage.list({ prefix: 'outbox:', limit: 100, ...(startAfter ? { startAfter } : {}) });
    if (!pending.size) return { failed: false, last: null };
    const items = new Map([...pending].map(([key, item]) => [key, { ...item }]));

    const byShard = new Map();
    for (const [key, item] of items) if (!item.status_done) (byShard.get(item.shard) || byShard.set(item.shard, []).get(item.shard)).push([key, item]);
    let failed = false;
    for (const [shard, group] of byShard) {
      try {
        await rpc(this.env.STATUS, `shard-${shard}`, 'revoke', { indexes: group.map(([, i]) => i.idx) });
        for (const [, item] of group) item.status_done = true;
      } catch { failed = true; later(now + OUTBOX_RETRY_MS); }
    }

    const withHooks = [...items.values()].filter(i => i.hooks?.length);
    let urls = null;
    if (withHooks.length) {
      try { urls = await rpc(this.env.REGISTRY, 'global', 'webhooks', { names: [...new Set(withHooks.flatMap(i => i.hooks))] }); } catch { later(now + OUTBOX_RETRY_MS); }
    }
    if (urls) {
      // Most audiences have no webhook: forget them before anything is written.
      for (const item of withHooks) item.hooks = item.hooks.filter(aud => urls[aud]);
      const due = send ? withHooks.filter(i => i.hooks.length && (i.hook_next ?? 0) <= now) : [];
      const byAudience = new Map();
      for (const item of due) for (const aud of item.hooks) (byAudience.get(aud) || byAudience.set(aud, []).get(aud)).push(item);
      for (const [aud, group] of byAudience) {
        let ok = false;
        try {
          const credentials = group.map(i => ({ cid: i.cid, jti: i.jti, exp: i.exp, revoked_at: Math.floor(i.at / 1000), status: { idx: i.idx, uri: i.uri } }));
          const event = await signEvent(this.env, aud, 'credentials.revoked', { credentials }, now);
          ok = (await postEvent(this.env, urls[aud], event.jws)).ok;
        } catch { ok = false; }
        if (ok) for (const item of group) item.hooks = item.hooks.filter(a => a !== aud);
      }
      for (const item of due) {
        if (!item.hooks.length) continue;
        item.hook_attempts = (item.hook_attempts || 0) + 1;
        if (item.hook_attempts >= WEBHOOK_ATTEMPTS) item.hooks = [];
        else item.hook_next = now + WEBHOOK_BACKOFF_MS[item.hook_attempts - 1];
      }
    }

    for (const [key, item] of items) {
      const before = pending.get(key);
      if (item.status_done && !item.hooks?.length) { await this.storage.delete(key); continue; }
      if (item.hooks?.length) later(Math.max(item.hook_next ?? 0, now));
      if (item.status_done !== before.status_done || item.hooks?.length !== before.hooks?.length || item.hook_attempts !== before.hook_attempts) await this.storage.put(key, item);
    }
    return { failed, last: pending.size === 100 ? [...pending.keys()].pop() : null };
  }

  /**
   * Store a renewed (or rotated) version. Rotation keeps the credential id but moves it to a new
   * key and status index, and revokes the old index so old copies stop working everywhere.
   */
  async op_renew({ cid, from_jti, update, price, charge_id, rotation, recovery = false }, now) {
    let announce = 0; let rotated = null;
    const result = await this.tx(async tx => {
      announce = 0;
      const cred = await tx.get(`cred:${cid}`);
      assert(cred, 'not_found', 'Credential not found', 404);
      assert(!cred.revoked_at, 'revoked', 'Credential has been revoked', 403);
      assert(cred.jti === from_jti, 'superseded', 'Only the current version of a credential can be renewed', 409);
      if (rotation) {
        // The new key's device record is written below; never over another device's, and above all
        // not over a revoked one, which would bring that key back (master plan §10).
        const taken = await tx.get(`device:${rotation.device.id}`);
        assert(!taken?.revoked_at, 'device_revoked', 'The new key belongs to a device that was revoked; rotate to a fresh key', 403, { device_id: rotation.device.id });
        assert(!taken, 'key_in_use', 'The new key already belongs to a device on this account; rotate to a fresh key', 409, { device_id: rotation.device.id });
      }
      const cap = (await this.settings(tx)).max_renewals_per_credential_per_month;
      const used = cred.renewals?.period === monthOf(now) ? cred.renewals.count : 0;
      // A recovery renewal (issuer key withdrawn) is DBA's doing, not the device's: it neither
      // counts against the renewal cap nor costs anything unless it also rotates. It can happen
      // once per credential per withdrawn key, since the result is signed by the active key.
      const free = recovery && !rotation;
      assert(free || cap === null || used < cap, 'renewal_limit', `This credential has been renewed ${used} times this month, the account's limit; the owner can raise it in the dashboard`, 429, { limit: cap });
      // A rotation moves a credential to a new key: announced like an issuance.
      const subscribed = rotation && (await tx.get('push:subs'))?.length > 0;
      rotated = rotation ? cred : null;
      const paid = free ? null : await charge(tx, { id: charge_id, kind: rotation ? 'rotate' : 'renew', amount: price, detail: { cid }, annotate: subscribed ? state => { announce = nextNotice(state, now, hasDbaAction(cred.grants)); } : undefined }, now);
      if (rotation) await tx.put(`outbox:${cid}:${cred.status.idx}`, { shard: cred.status.shard, idx: cred.status.idx, at: now });
      const type = rotation ? 'rotated' : recovery ? 'recovered' : 'renewed';
      const next = { ...cred, ...update, renewed_at: now, renewals: { period: monthOf(now), count: used + (free ? 0 : 1) }, events: [...cred.events, { at: now, type, jti: update.jti }].slice(-EVENTS_KEPT) };
      await tx.put(`cred:${cid}`, next);
      if (rotation) {
        const device = await tx.get(`device:${cred.device_id}`);
        await tx.put(`device:${rotation.device.id}`, { ...rotation.device, created_at: now, last_issued_at: now, rotated_from: device?.id });
      }
      await this.audit(tx, now, `credential.${type}`, { cid, jti: update.jti });
      return { cid, jti: update.jti, charged: free ? 0 : price, ...(paid ? { balance_microdollars: paid.balance_microdollars } : {}) };
    });
    if (announce) {
      const more = announce > 1 ? ` (and ${announce - 1} more issuances since the last notice)` : '';
      this.notify({ title: 'Credential moved to a new key', body: `${noticeText(rotated.device?.name) || 'A device'} rotated its credential for ${noticeText(rotated.aud.join(', '), 120)} to a new key${more}.`, path: `#credential/${encodeURIComponent(cid)}`, tag: hasDbaAction(rotated.grants) ? `cred-${cid}` : 'issued' }, now);
    }
    if (rotation) await this.deliverOutbox(now);
    return result;
  }

  // ---- Security notices (Web Push, master plan §10) ------------------------------
  // Up to MAX_SUBSCRIPTIONS browsers, kept in one row so issuance reads them with one get.

  /** Send a notice to every subscribed browser after the response; drop browsers that left. */
  notify({ title, body, path, tag }, now) {
    this.background((async () => {
      const subs = (await this.storage.get('push:subs')) || [];
      if (!subs.length) return;
      const results = await broadcast(this.env, subs, { title, body, url: `${this.env.APP_ORIGIN || ''}/app.html${path || ''}`, tag }, now);
      await this.dropGone(results.filter(r => r.gone).map(r => r.id));
    })());
  }

  async dropGone(ids) {
    if (!ids.length) return;
    await this.tx(async tx => {
      const subs = (await tx.get('push:subs')) || [];
      const left = subs.filter(s => !ids.includes(s.id));
      if (left.length !== subs.length) await tx.put('push:subs', left);
    });
  }

  async op_push_list() {
    return { items: ((await this.storage.get('push:subs')) || []).map(visibleSubscription) };
  }

  /** Add (or refresh, for the same endpoint) a browser, then send it a first notice to prove it works. */
  async op_push_subscribe({ id, subscription, name }, now) {
    const item = await this.tx(async tx => {
      const subs = (await tx.get('push:subs')) || [];
      const same = subs.find(s => s.endpoint === subscription.endpoint);
      const others = subs.filter(s => s !== same);
      assert(others.length < MAX_SUBSCRIPTIONS, 'too_many_subscriptions', `At most ${MAX_SUBSCRIPTIONS} browsers get security notices; turn one off first`, 409);
      const entry = { id: same?.id || id, name, ...subscription, created_at: same?.created_at || now };
      await tx.put('push:subs', [...others, entry]);
      if (!same) await this.audit(tx, now, 'push.subscribed', { subscription_id: entry.id, name });
      return entry;
    });
    const [first] = await broadcast(this.env, [item], { title: 'Security notices are on', body: `This browser (“${noticeText(name)}”) will be told when credentials, API keys or enrollment tokens are issued on your devicebasedauth.org account.`, url: `${this.env.APP_ORIGIN || ''}/app.html#account`, tag: 'subscribed' }, now);
    if (first.gone) await this.dropGone([item.id]);
    return { ...visibleSubscription(item), delivered: first.ok, ...(first.ok ? {} : { delivery_status: first.status, delivery_error: first.error }) };
  }

  /** Turn notices off for one browser. Every browser, the removed one included, is told. */
  async op_push_unsubscribe({ id }, now) {
    const removed = await this.tx(async tx => {
      const subs = (await tx.get('push:subs')) || [];
      const entry = subs.find(s => s.id === id);
      assert(entry, 'not_found', 'Subscription not found', 404);
      await tx.put('push:subs', subs.filter(s => s !== entry));
      await this.audit(tx, now, 'push.unsubscribed', { subscription_id: id, name: entry.name });
      return { entry, all: subs };
    });
    this.background(broadcast(this.env, removed.all, { title: 'Security notices turned off', body: `Notices to “${noticeText(removed.entry.name)}” were turned off. If that was not you, sign in and check your account.`, url: `${this.env.APP_ORIGIN || ''}/app.html#account`, tag: 'unsubscribed' }, now));
    return { ...visibleSubscription(removed.entry), removed: true };
  }

  // ---- Online authorization ---------------------------------------------------

  /**
   * Final online checks for one decision: revocation, proof replay, step-up and usage counters.
   * candidates: grant indexes that passed every static check, in order, with their online needs.
   */
  async op_authorize({ cid, jti, status_list, proof_jti, proof_exp, candidates, action, resource, audience, caller, country, token_namespace = null }, now) {
    const nowSeconds = Math.floor(now / 1000);
    for (const [key, exp] of this.proofs) { if (exp > nowSeconds) break; this.proofs.delete(key); }
    let asked = null;
    const decision = await this.tx(async tx => {
      asked = null;
      const cred = await tx.get(`cred:${cid}`);
      let decision;
      if (!cred) decision = { allow: false, code: 'unknown_credential', reasons: ['unknown_credential'] };
      else if (cred.revoked_at) decision = { allow: false, code: 'revoked', reasons: ['revoked'] };
      // Rotation moves the credential to a new status entry and sets the old one: a version (or an
      // access token) carrying the old entry belongs to the replaced key and is revoked.
      else if (status_list && !sameStatusEntry(cred.status, status_list)) decision = { allow: false, code: 'revoked', reasons: ['revoked'] };
      else if (proof_jti && this.proofs.has(proof_jti)) decision = { allow: false, code: 'replayed_proof', reasons: ['replayed_proof'] };
      else {
        if (proof_jti) this.proofs.set(proof_jti, proof_exp);
        const reasons = []; let chosen = null; let stepUpNeeded = null;
        for (const candidate of candidates) {
          // Check both before spending either, so a grant that is out of uses does not burn the
          // owner's step-up approval (nor a step-up refusal count as a use).
          let usage = null;
          if (candidate.uses) {
            const counter = usageCounter(cred, candidate.index, token_namespace);
            if (!counter) { reasons.push('invalid_grant'); continue; }
            const per = periodSeconds(candidate.uses.per);
            const start = Number.isFinite(per) ? Math.floor(nowSeconds / per) * per : 0;
            const key = `usage:${counter}:${start}`;
            const used = (await tx.get(key)) || 0;
            if (used >= candidate.uses.count) { reasons.push('usage_limit_reached'); continue; }
            usage = { key, used };
          }
          if (candidate.step_up) {
            const approval = await findApproval(tx, { cid, action, resource, audience }, now);
            if (!approval) { stepUpNeeded ||= candidate; reasons.push('step_up_required'); continue; }
            // Spent: deleting it is the same single write as marking it used, and leaves the
            // pruning pass nothing to delete later.
            await tx.delete(`stepup:${approval.id}`);
          }
          if (usage) await tx.put(usage.key, usage.used + 1);
          chosen = candidate; break;
        }
        if (chosen) decision = { allow: true, code: 'ok', grant_index: chosen.index, reasons: [] };
        else if (stepUpNeeded) {
          // Asking again while a request is still waiting reuses it: one request (and one notice)
          // per thing to approve, however often the site retries. A denial stands until the
          // request would have expired.
          let pending = await findPending(tx, { cid, action, resource, audience }, now);
          if (pending?.denied_at) decision = { allow: false, code: 'step_up_denied', reasons: reasons.map(r => r === 'step_up_required' ? 'step_up_denied' : r) };
          else if (!pending) {
            pending = { id: randomId('stp', 12), cid, device_id: cred.device_id, device_name: cred.device?.name, action, resource: resource ?? null, audience, requested_at: now, expires_at: now + STEP_UP_TTL_MS };
            await tx.put(`stepup:${pending.id}`, pending);
            asked = pending;
          }
          if (!decision) decision = { allow: false, code: 'step_up_required', reasons, step_up: { id: pending.id, expires_in: Math.max(1, Math.ceil((pending.expires_at - now) / 1000)) } };
        } else decision = { allow: false, code: candidates.length ? 'forbidden' : 'forbidden', reasons: reasons.length ? reasons : ['no_grant_matched'] };
      }
      if (cred) await tx.put(`decision:${cid}:${pad(now)}:${randomId('d', 6)}`, { at: now, audience, action, resource: resource ?? null, country: country ?? null, allow: decision.allow, code: decision.code, grant_index: decision.grant_index ?? null, caller, jti });
      const alarm = await tx.getAlarm();
      if (!alarm) await tx.setAlarm(now + 86400000);
      return decision;
    });
    if (asked) this.notify({ title: 'Approval needed', body: `${noticeText(asked.device_name) || 'A device'} asks to ${noticeText(asked.action, 120)}${asked.resource ? ` on ${noticeText(asked.resource, 120)}` : ''} at ${noticeText(asked.audience)}. Approve or deny within ${STEP_UP_TTL_MS / 60000} minutes.`, path: '#approvals', tag: `stepup-${asked.id}` }, now);
    return decision;
  }

  async op_decisions({ cid, limit = PAGE }) {
    const rows = await this.storage.list({ prefix: `decision:${cid}:`, reverse: true, limit: Math.min(limit, 200) });
    return { items: [...rows.values()] };
  }

  async op_list_step_ups(_args, now) {
    const rows = await this.storage.list({ prefix: 'stepup:' });
    return { items: [...rows.values()].filter(s => !s.denied_at && (s.approved_at ? s.approved_until > now : s.expires_at > now)) };
  }

  async op_decide_step_up({ id, approve }, now) {
    return this.tx(async tx => {
      const item = await tx.get(`stepup:${id}`);
      assert(item && !item.approved_at && !item.denied_at && item.expires_at > now, 'not_found', 'Approval request not found or expired', 404);
      if (approve) { item.approved_at = now; item.approved_until = now + STEP_UP_APPROVED_TTL_MS; } else item.denied_at = now;
      await tx.put(`stepup:${id}`, item);
      await this.audit(tx, now, approve ? 'step_up.approved' : 'step_up.denied', { id, cid: item.cid, action: item.action });
      return item;
    });
  }

  // ---- OpenID Connect authorization codes ------------------------------------

  async op_put_code({ id, code }, now) {
    await this.storage.put(`code:${id}`, { ...code, created_at: now });
    const alarm = await this.storage.getAlarm();
    if (!alarm || alarm > now + 600000) await this.storage.setAlarm(now + 600000);
    return { ok: true };
  }

  async op_take_code({ id }, now) {
    return this.tx(async tx => {
      const code = await tx.get(`code:${id}`);
      assert(code && code.expires_at > now && !code.used_at, 'invalid_grant', 'Authorization code is invalid or expired', 400);
      code.used_at = now; await tx.put(`code:${id}`, code);
      return code;
    });
  }

  // ---- Maintenance ------------------------------------------------------------

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

  async alarm() {
    const now = Date.now();
    const compactAt = await this.compact(now);
    const { next_at: outboxAt } = await this.deliverOutbox(now);
    let more = false;
    // Prune expired decisions, usage windows, step-ups and authorization codes.
    for (const [key, value] of await this.storage.list({ prefix: 'decision:', limit: 500 })) {
      if (value.at < now - DECISION_RETENTION_MS) await this.storage.delete(key);
    }
    // Step-up requests and authorization codes are useless once they expire; the next wake-up is
    // set for the first one still waiting, so none outlives its expiry for long on an account that
    // has nothing else to do.
    let shortLived = null;
    for (const prefix of ['stepup:', 'code:']) for (const [key, value] of await this.storage.list({ prefix })) {
      const until = Math.max(value.expires_at, value.approved_until || 0);
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
    const next = [hasWork || more ? now + (more ? 60000 : 86400000) : null, outboxAt, compactAt, shortLived === null ? null : Math.max(shortLived, now + 60000)].filter(t => t !== null);
    if (next.length) await this.storage.setAlarm(Math.min(...next));
  }
}

/** Drop a revoked app connection's refresh state from the balance row. */
async function forgetRefresh(tx, id, now) {
  const state = await readBalance(tx, now, { flush: true });
  if (!state.refresh?.[id]) return;
  delete state.refresh[id];
  await tx.put('balance', state);
}

/** Make sure compaction will look at this account once the rows written now age out. */
async function scheduleCompaction(tx, now) {
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

function visibleToken({ hash: _hash, ...token }, now) { return { ...token, state: enrollmentTokenState(token, now) }; }

/** active | expired | revoked */
/** What the dashboard sees of an API key or connected app: never the hash. */
function visibleKey({ hash: _hash, oauth, ...key }) {
  return oauth ? { ...key, resource: oauth.resource } : key;
}

/**
 * The usage counter ("<cid>:<grant index>") a grant of this credential spends, for online
 * decisions. Two things keep a `limits.uses` from multiplying (STATUS L12):
 * - An access token carries only the grants in its audience's namespace (exchangeToken), so its
 *   grant indexes are mapped back to the credential's; otherwise a token's uses would land on
 *   another grant's counter, or a fresh one.
 * - A delegated grant whose limit came from its parent (`usage_from`, set at issuance) spends the
 *   parent's counter, so a device limited to 3 uses a day cannot delegate itself more.
 * Returns null when the index does not name a grant of the credential.
 * @param {object} cred stored credential record
 * @param {number} index grant index in the presented credential or access token
 * @param {string|null} tokenNamespace the audience namespace when an access token was presented
 * @returns {string|null}
 */
export function usageCounter(cred, index, tokenNamespace = null) {
  const grants = Array.isArray(cred.grants) ? cred.grants : [];
  const own = tokenNamespace === null ? index
    : grants.map((grant, i) => grant.actions.some(a => actionNamespace(a) === tokenNamespace) ? i : -1).filter(i => i >= 0)[index];
  if (!Number.isSafeInteger(own) || own < 0 || own >= grants.length) return null;
  const parentIndex = cred.parent_cid ? cred.usage_from?.[own] : null;
  return Number.isSafeInteger(parentIndex) ? `${cred.parent_cid}:${parentIndex}` : `${cred.cid}:${own}`;
}

export function credentialState(cred, now = Date.now()) {
  if (cred.revoked_at) return 'revoked';
  if (cred.exp * 1000 <= now) return 'expired';
  return 'active';
}

async function findApproval(tx, { cid, action, resource, audience }, now) {
  for (const item of (await tx.list({ prefix: 'stepup:' })).values()) {
    if (item.cid === cid && item.action === action && (item.resource ?? null) === (resource ?? null) && item.audience === audience && item.approved_at && item.approved_until > now) return item;
  }
  return null;
}

/** An unexpired step-up request for the same thing that was not approved: waiting, or denied. */
async function findPending(tx, { cid, action, resource, audience }, now) {
  for (const item of (await tx.list({ prefix: 'stepup:' })).values()) {
    if (item.cid === cid && item.action === action && (item.resource ?? null) === (resource ?? null) && item.audience === audience && !item.approved_at && item.expires_at > now) return item;
  }
  return null;
}

export { money, ApiError };

/**
 * Does a credential's status_list claim name the record's current entry? Indexes are per shard,
 * so the list URI must match too: a rotated credential can land on the same index in another shard.
 * @param {{ idx: number, uri: string } | undefined} current the record's status
 * @param {{ idx: number, uri: string }} claimed payload.status.status_list
 * @returns {boolean}
 */
export function sameStatusEntry(current, claimed) {
  return !!current && current.idx === claimed?.idx && current.uri === claimed?.uri;
}

/** A push subscription without its endpoint and keys (only the browser's push service host). */
function visibleSubscription(s) {
  let host = ''; try { host = new URL(s.endpoint).hostname; } catch { /* ignore */ }
  return { id: s.id, name: s.name, push_service: host, created_at: s.created_at };
}
