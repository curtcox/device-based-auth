import { assert, errorResponse, ApiError } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { charge, deposit, readBalance, money } from './ledger.js';
import { periodSeconds } from '../../packages/verify/src/grants.js';
import { randomId } from '../utils/ids.js';
import { signEvent, postEvent, WEBHOOK_ATTEMPTS, WEBHOOK_BACKOFF_MS } from '../services/webhooks.js';

const PAGE = 50;
const EVENTS_KEPT = 50;
const DECISION_RETENTION_MS = 90 * 86400000;
const STEP_UP_TTL_MS = 10 * 60000;
const STEP_UP_APPROVED_TTL_MS = 5 * 60000;
const OUTBOX_RETRY_MS = 60000;
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

  async op_init({ account }, now) {
    return this.tx(async tx => {
      const profile = await tx.get('profile');
      if (profile) return profile;
      const created = { account, created_at: now };
      await tx.put('profile', created);
      return created;
    });
  }

  async op_account(_args, now) {
    return this.tx(async tx => {
      const profile = (await tx.get('profile')) || {};
      const state = await readBalance(tx, now);
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

  async op_charge({ id, kind, amount, aggregate, detail }, now) { return this.tx(tx => charge(tx, { id, kind, amount, aggregate, detail }, now)); }

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
    });
  }

  async op_list_keys() {
    const keys = await this.storage.list({ prefix: 'key:' });
    return { items: [...keys.values()].map(visibleKey) };
  }

  /** A connected app's access token: the record must exist, be an app, and not be revoked. */
  async op_authenticate_oauth_key({ id }, now) {
    const key = await this.storage.get(`key:${id}`);
    assert(key && key.kind === 'oauth' && !key.revoked_at, 'invalid_token', 'This app connection was revoked', 401);
    if (!key.used_at || now - key.used_at > 3600000) { key.used_at = now; await this.storage.put(`key:${id}`, key); }
    return { scopes: key.scopes };
  }

  /**
   * Rotate a connected app's refresh token. Presenting an old one means a copy leaked (or the app
   * raced itself): the connection is revoked (OAuth 2.1 §4.3.1) and the caller refused.
   */
  async op_rotate_oauth_key({ id, hash, client, new_hash }, now) {
    const outcome = await this.tx(async tx => {
      const key = await tx.get(`key:${id}`);
      if (!key || key.kind !== 'oauth' || key.revoked_at || key.oauth.client !== client) return { refused: true };
      if (key.hash !== hash) {
        key.revoked_at = now; key.revoked_reason = 'refresh token reused';
        await tx.put(`key:${id}`, key); await this.audit(tx, now, 'key.revoked', { key_id: id, reason: key.revoked_reason });
        return { refused: true };
      }
      key.hash = new_hash; key.refreshed_at = now;
      await tx.put(`key:${id}`, key);
      return { scopes: key.scopes };
    });
    assert(!outcome.refused, 'invalid_grant', 'Refresh token is invalid, used or revoked', 400);
    return outcome;
  }

  async op_revoke_key({ id }, now) {
    return this.tx(async tx => {
      const key = await tx.get(`key:${id}`); assert(key, 'not_found', 'API key not found', 404);
      if (!key.revoked_at) { key.revoked_at = now; await tx.put(`key:${id}`, key); await this.audit(tx, now, 'key.revoked', { key_id: id }); }
      return visibleKey(key);
    });
  }

  async op_authenticate_key({ id, hash }) {
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
      return visibleToken(token, now);
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
  async op_store_credential({ record, device, price, charge_id, source, enrollment_token }, now) {
    return this.tx(async tx => {
      const settings = await this.settings(tx);
      if (enrollment_token) {
        // Count the use in the same transaction that stores the credential, so a token can never
        // issue more than max_uses even under concurrent redemptions.
        const token = await tx.get(`etok:${enrollment_token.id}`);
        assert(token && token.hash === enrollment_token.hash, 'invalid_enrollment_token', 'Enrollment token is invalid', 401);
        assert(enrollmentTokenState(token, now) === 'active', 'enrollment_token_inactive', `Enrollment token is ${enrollmentTokenState(token, now)}`, 403);
        token.uses += 1; token.last_used_at = now;
        await tx.put(`etok:${token.id}`, token);
        record = { ...record, enrollment_token: token.id };
      }
      const today = (await readBalance(tx, now)).day;
      assert((today.counts?.issue || 0) < settings.max_issues_per_day, 'issuance_limit', `This account may issue ${settings.max_issues_per_day} credentials a day (UTC); the owner can raise the limit in the dashboard`, 429, { limit: settings.max_issues_per_day });
      const paid = await charge(tx, { id: charge_id, kind: 'issue', amount: price, detail: { cid: record.cid } }, now);
      const existing = await tx.get(`device:${device.id}`);
      const stored = existing ? { ...existing, name: device.name || existing.name, ...(device.attestation ? { attestation: device.attestation, key_protection: device.key_protection } : {}), last_issued_at: now } : { ...device, created_at: now, last_issued_at: now };
      if (stored.revoked_at) { delete stored.revoked_at; stored.reinstated_at = now; }
      await tx.put(`device:${device.id}`, stored);
      const cred = { ...record, created_at: now, events: [{ at: now, type: 'issued', jti: record.jti, source }] };
      await tx.put(`cred:${record.cid}`, cred);
      await this.audit(tx, now, 'credential.issued', { cid: record.cid, device_id: device.id, aud: record.aud, source, ...(record.enrollment_token ? { token_id: record.enrollment_token } : {}) });
      return { cid: record.cid, charged: price, balance_microdollars: paid.balance_microdollars };
    });
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
  async op_credential_status({ cid, with_jws = false }, now) {
    const cred = await this.storage.get(`cred:${cid}`);
    if (!cred) return { exists: false, revoked: true };
    return { exists: true, ...(with_jws ? { jws: cred.jws } : {}), revoked: !!cred.revoked_at, state: credentialState(cred, now), jti: cred.jti, exp: cred.exp, grants: cred.grants, aud: cred.aud, device_id: cred.device_id, jkt: cred.jkt, lifetime: cred.lifetime, max_exp: cred.max_exp, status: cred.status, device: cred.device };
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
    const result = await this.tx(async tx => {
      const cred = await tx.get(`cred:${cid}`);
      assert(cred, 'not_found', 'Credential not found', 404);
      assert(!cred.revoked_at, 'revoked', 'Credential has been revoked', 403);
      assert(cred.jti === from_jti, 'superseded', 'Only the current version of a credential can be renewed', 409);
      const cap = (await this.settings(tx)).max_renewals_per_credential_per_month;
      const used = cred.renewals?.period === monthOf(now) ? cred.renewals.count : 0;
      // A recovery renewal (issuer key withdrawn) is DBA's doing, not the device's: it neither
      // counts against the renewal cap nor costs anything unless it also rotates. It can happen
      // once per credential per withdrawn key, since the result is signed by the active key.
      const free = recovery && !rotation;
      assert(free || cap === null || used < cap, 'renewal_limit', `This credential has been renewed ${used} times this month, the account's limit; the owner can raise it in the dashboard`, 429, { limit: cap });
      const paid = free ? null : await charge(tx, { id: charge_id, kind: rotation ? 'rotate' : 'renew', amount: price, detail: { cid } }, now);
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
    if (rotation) await this.deliverOutbox(now);
    return result;
  }

  // ---- Online authorization ---------------------------------------------------

  /**
   * Final online checks for one decision: revocation, proof replay, step-up and usage counters.
   * candidates: grant indexes that passed every static check, in order, with their online needs.
   */
  async op_authorize({ cid, jti, proof_jti, proof_exp, candidates, action, resource, audience, caller, country }, now) {
    const nowSeconds = Math.floor(now / 1000);
    for (const [key, exp] of this.proofs) { if (exp > nowSeconds) break; this.proofs.delete(key); }
    return this.tx(async tx => {
      const cred = await tx.get(`cred:${cid}`);
      let decision;
      if (!cred) decision = { allow: false, code: 'unknown_credential', reasons: ['unknown_credential'] };
      else if (cred.revoked_at) decision = { allow: false, code: 'revoked', reasons: ['revoked'] };
      else if (proof_jti && this.proofs.has(proof_jti)) decision = { allow: false, code: 'replayed_proof', reasons: ['replayed_proof'] };
      else {
        if (proof_jti) this.proofs.set(proof_jti, proof_exp);
        const reasons = []; let chosen = null; let stepUpNeeded = null;
        for (const candidate of candidates) {
          if (candidate.step_up) {
            const approval = await findApproval(tx, { cid, action, resource, audience }, now);
            if (!approval) { stepUpNeeded ||= candidate; reasons.push('step_up_required'); continue; }
            approval.used_at = now; await tx.put(`stepup:${approval.id}`, approval);
          }
          if (candidate.uses) {
            const per = periodSeconds(candidate.uses.per);
            const start = Number.isFinite(per) ? Math.floor(nowSeconds / per) * per : 0;
            const key = `usage:${cid}:${candidate.index}:${start}`;
            const used = (await tx.get(key)) || 0;
            if (used >= candidate.uses.count) { reasons.push('usage_limit_reached'); continue; }
            await tx.put(key, used + 1);
          }
          chosen = candidate; break;
        }
        if (chosen) decision = { allow: true, code: 'ok', grant_index: chosen.index, reasons: [] };
        else if (stepUpNeeded) {
          const id = randomId('stp', 12);
          await tx.put(`stepup:${id}`, { id, cid, device_id: cred.device_id, device_name: cred.device?.name, action, resource: resource ?? null, audience, requested_at: now, expires_at: now + STEP_UP_TTL_MS });
          decision = { allow: false, code: 'step_up_required', reasons, step_up: { id, expires_in: STEP_UP_TTL_MS / 1000 } };
        } else decision = { allow: false, code: candidates.length ? 'forbidden' : 'forbidden', reasons: reasons.length ? reasons : ['no_grant_matched'] };
      }
      if (cred) await tx.put(`decision:${cid}:${pad(now)}:${randomId('d', 6)}`, { at: now, audience, action, resource: resource ?? null, country: country ?? null, allow: decision.allow, code: decision.code, grant_index: decision.grant_index ?? null, caller, jti });
      const alarm = await tx.getAlarm();
      if (!alarm) await tx.setAlarm(now + 86400000);
      return decision;
    });
  }

  async op_decisions({ cid, limit = PAGE }) {
    const rows = await this.storage.list({ prefix: `decision:${cid}:`, reverse: true, limit: Math.min(limit, 200) });
    return { items: [...rows.values()] };
  }

  async op_list_step_ups(_args, now) {
    const rows = await this.storage.list({ prefix: 'stepup:' });
    return { items: [...rows.values()].filter(s => !s.used_at && !s.denied_at && (s.approved_at ? s.approved_until > now : s.expires_at > now)) };
  }

  async op_decide_step_up({ id, approve }, now) {
    return this.tx(async tx => {
      const item = await tx.get(`stepup:${id}`);
      assert(item && !item.used_at && item.expires_at > now, 'not_found', 'Approval request not found or expired', 404);
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

  async alarm() {
    const now = Date.now();
    const { next_at: outboxAt } = await this.deliverOutbox(now);
    let more = false;
    // Prune expired decisions, usage windows, step-ups and authorization codes.
    for (const [key, value] of await this.storage.list({ prefix: 'decision:', limit: 500 })) {
      if (value.at < now - DECISION_RETENTION_MS) await this.storage.delete(key);
    }
    for (const [key, value] of await this.storage.list({ prefix: 'stepup:' })) if (value.expires_at < now - 86400000) await this.storage.delete(key);
    for (const [key, value] of await this.storage.list({ prefix: 'code:' })) if (value.expires_at < now - 600000) await this.storage.delete(key);
    const usage = await this.storage.list({ prefix: 'usage:', limit: 1000 });
    for (const key of usage.keys()) {
      const [, cid, , start] = key.split(':');
      const cred = await this.storage.get(`cred:${cid}`);
      if (!cred || (cred.exp * 1000 < now) || (Number(start) > 0 && Number(start) * 1000 < now - 31 * 86400000)) await this.storage.delete(key);
    }
    more = usage.size === 1000;
    const hasWork = (await this.storage.list({ prefix: 'decision:', limit: 1 })).size || (await this.storage.list({ prefix: 'outbox:', limit: 1 })).size;
    // The outbox's retry time wins over the daily pruning pass.
    const next = [hasWork || more ? now + (more ? 60000 : 86400000) : null, outboxAt].filter(t => t !== null);
    if (next.length) await this.storage.setAlarm(Math.min(...next));
  }
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

export function credentialState(cred, now = Date.now()) {
  if (cred.revoked_at) return 'revoked';
  if (cred.exp * 1000 <= now) return 'expired';
  return 'active';
}

async function findApproval(tx, { cid, action, resource, audience }, now) {
  for (const item of (await tx.list({ prefix: 'stepup:' })).values()) {
    if (item.cid === cid && item.action === action && (item.resource ?? null) === (resource ?? null) && item.audience === audience && item.approved_at && !item.used_at && item.approved_until > now) return item;
  }
  return null;
}

export { money, ApiError };
