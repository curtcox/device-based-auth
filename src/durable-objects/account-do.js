import { assert, errorResponse, ApiError } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { charge, deposit, readBalance, money } from './ledger.js';
import { periodSeconds, actionNamespace } from '../../packages/verify/src/grants.js';
import { randomId } from '../utils/ids.js';
import { price } from '../utils/pricing.js';
import { signEvent, postEvent, WEBHOOK_ATTEMPTS, WEBHOOK_BACKOFF_MS } from '../services/webhooks.js';
import { MAX_SUBSCRIPTIONS, broadcast, nextNotice, noticeText } from '../services/push.js';
import { hasDbaAction } from '../auth/reverify.js';
import { GATE_REQUESTS_PER_HOUR, RETRY_AFTER_S, OWNER_GATE, FACTOR_KINDS, activateGate, approvalLink, callbackUrl, postGateEvent, signGateEvent, verifyGateAnswer, webhookTargets, factorView, hasFactorGates, answerRequest, checkGatesForIssue, contactedGates, createGate, findRequest, gateKey, meetsPolicy, ACR, meetsAcr, signInClaims, gateSignature, howPassed, loadGates, newRequest, refreshRequest, requestKey, requestUntil, visibleGate, visibleRequest } from './gates.js';

const PAGE = 50;
const EVENTS_KEPT = 50;
const DECISION_RETENTION_MS = 90 * 86400000;
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
    // New gate requests per (device, gate) in the last hour (in memory, like the request limit).
    this.gateRates = new Map();
    // Wrong TOTP codes and security-key answers per gate (in memory; a guessing limit).
    this.factorFailures = new Map();
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
  async op_store_credential({ record, gate_policies = [], device, price, charge_id, fingerprint, reinstate = false, source, enrollment_token }, now) {
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
      await checkGatesForIssue(tx, record.grants, record.device_id, gate_policies);
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
  notify({ title, body, path, url, tag }, now) {
    this.background((async () => {
      const subs = (await this.storage.get('push:subs')) || [];
      if (!subs.length) return;
      const results = await broadcast(this.env, subs, { title, body, url: url || `${this.env.APP_ORIGIN || ''}/app.html${path || ''}`, tag }, now);
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
   * Final online checks for one decision: revocation, proof replay, gates (step-up is the owner
   * gate) and usage counters. candidates: grant indexes that passed every static check, in order,
   * with their online needs ({ index, uses, step_up, gates, gates_reuse_s, fail_open }).
   */
  async op_authorize({ account = null, cid, jti, status_list, proof_jti, proof_exp, candidates, action, resource, audience, caller, country, token_namespace = null, gate_policy = null }, now) {
    const nowSeconds = Math.floor(now / 1000);
    for (const [key, exp] of this.proofs) { if (exp > nowSeconds) break; this.proofs.delete(key); }
    let asked = null; let byTimeout = [];
    const decision = await this.tx(async tx => {
      asked = null; byTimeout = [];
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
        const reasons = []; let chosen = null; let needed = null; let denied = null;
        const subject = { cid, action, resource, audience };
        for (const candidate of candidates) {
          // Check both before spending either, so a grant that is out of uses does not burn the
          // owner's approval (nor a refusal count as a use).
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
          // The audience's policy for this action (spec/evaluation.md §3.8), checked here because
          // only the account knows its gates' kinds; it applies to credentials issued before it.
          if (gate_policy?.require && !meetsPolicy(candidate.gates, gate_policy.kinds ?? null, await loadGates(tx, (candidate.gates || []).flatMap(e => e.any)))) { reasons.push('gate_required'); continue; }
          let approval = null;
          if (candidate.gates) {
            const signature = gateSignature(candidate);
            const req = await findRequest(tx, { purpose: 'authorize', ...subject, signature }, now);
            if (req) await this.refreshed(tx, req, now, byTimeout);
            const [waiting, refused] = candidate.step_up ? ['step_up_required', 'step_up_denied'] : ['gate_pending', 'gate_denied'];
            if (req?.outcome === 'deny') { reasons.push(req.entries.some(e => e.by === 'by_timeout_refused') ? 'by_timeout_refused' : refused); denied ||= { candidate, req }; continue; }
            if (req?.outcome !== 'allow') { reasons.push(waiting); needed ||= { candidate, req, signature }; continue; }
            approval = req;
          }
          if (approval) {
            // A spent approval is deleted (the same single write as marking it used); one that
            // covers repeated uses (gates_reuse_s) stays until it runs out.
            if (!approval.reuse_s) await tx.delete(requestKey(approval.id));
          }
          if (usage) await tx.put(usage.key, usage.used + 1);
          chosen = { candidate, approval }; break;
        }
        if (chosen) decision = { allow: true, code: 'ok', grant_index: chosen.candidate.index, reasons: [], ...(chosen.approval ? { gates: howPassed(chosen.approval), by_timeout: chosen.approval.by_timeout } : {}) };
        else if (needed) {
          // Asking again while a request waits reuses it: one request (and one notice) per thing
          // to approve, however often the site retries.
          let req = needed.req;
          if (!req) {
            req = await this.openGateRequest(tx, cred, subject, needed.candidate, now);
            if (req.rate_limited) decision = { allow: false, code: 'gate_rate_limited', reasons: ['gate_rate_limited'] };
            else {
              // A request with no gate left to answer (all deleted) denies at once.
              await this.refreshed(tx, req, now, byTimeout);
              if (req.outcome === 'deny') decision = { allow: false, code: needed.candidate.step_up ? 'step_up_denied' : 'gate_denied', reasons: reasons.map(r => r === 'gate_pending' ? 'gate_denied' : r === 'step_up_required' ? 'step_up_denied' : r), gate_request: { id: req.id } };
              else asked = req;
            }
          }
          if (!decision) {
            const deadline = Math.max(...req.entries.map(e => e.deadline));
            decision = { allow: false, code: needed.candidate.step_up ? 'step_up_required' : 'gate_pending', reasons, gate_request: { id: req.id, retry_after: RETRY_AFTER_S, deadline: Math.ceil(deadline / 1000), ...(account && hasFactorGates(req) ? { approve_url: await approvalLink(this.env, account, req) } : {}) } };
            if (needed.candidate.step_up) decision.step_up = { id: req.id, expires_in: Math.max(1, Math.ceil((deadline - now) / 1000)) };
          }
        } else if (denied) {
          decision = { allow: false, code: reasons.includes('by_timeout_refused') ? 'by_timeout_refused' : denied.candidate.step_up ? 'step_up_denied' : 'gate_denied', reasons, gate_request: { id: denied.req.id } };
        } else decision = { allow: false, code: 'forbidden', reasons: reasons.length ? reasons : ['no_grant_matched'] };
      }
      if (cred) await tx.put(`decision:${cid}:${pad(now)}:${randomId('d', 6)}`, { at: now, audience, action, resource: resource ?? null, country: country ?? null, allow: decision.allow, code: decision.code, grant_index: decision.grant_index ?? null, caller, jti, ...(decision.by_timeout ? { by_timeout: true } : {}) });
      const alarm = await tx.getAlarm();
      const wake = asked ? Math.max(...asked.entries.map(e => e.deadline)) + 60000 : now + 86400000;
      if (!alarm || alarm > wake) await tx.setAlarm(wake);
      return decision;
    });
    if (asked) await this.announceGateRequest(asked, now, account);
    if (asked && account && webhookTargets(asked).length) this.background(this.deliverWebhooks(asked.id, account));
    this.announceTimeouts(byTimeout, now);
    return decision;
  }

  /**
   * Post a new request to its webhook gates (after the decision has answered gate_pending). A
   * service that answers at once settles its entry; one that cannot be reached is marked
   * "failed" and its entry waits for its timeout (plan §2).
   */
  async deliverWebhooks(id, account) {
    const req = await this.storage.get(requestKey(id));
    if (!req) return;
    const callback = await callbackUrl(this.env, account, req);
    const results = await Promise.all(webhookTargets(req).map(async ({ entry, gate: gateId }) => {
      const gate = await this.storage.get(gateKey(gateId));
      if (!gate) return null;
      const jws = await signGateEvent(this.env, { req, entryIndex: entry, gate, account, callback });
      return { entry, gate: gateId, result: await postGateEvent(this.env, gate.url, jws) };
    }));
    const now = Date.now();
    const byTimeout = [];
    await this.tx(async tx => {
      byTimeout.length = 0;
      const fresh = await tx.get(requestKey(id));
      if (!fresh) return;
      for (const r of results.filter(Boolean)) {
        if (!r.result.delivered) {
          const g = fresh.entries[r.entry].gates.find(x => x.id === r.gate);
          if (g && g.state === 'sent') g.state = 'failed';
        } else if (r.result.decision) {
          try {
            await answerRequest(tx, fresh, { entry: r.entry, gate: r.gate, decision: r.result.decision, answerer: { kind: 'webhook', gate: r.gate } }, now);
            await this.audit(tx, now, r.result.decision === 'allow' ? 'gate.approved' : 'gate.refused', { id, gate: r.gate, cid: fresh.cid, action: fresh.action, audience: fresh.audience, by: 'webhook' });
          } catch { /* settled or past its deadline meanwhile */ }
        }
      }
      await this.refreshed(tx, fresh, now, byTimeout);
      await tx.put(requestKey(id), fresh);
    });
    this.announceTimeouts(byTimeout, now);
  }

  /** A webhook gate's late answer (POST …/gate-links/<link>/callback). */
  async op_webhook_gate_answer({ id, jws }, now) {
    const byTimeout = [];
    const req = await this.tx(async tx => {
      byTimeout.length = 0;
      const found = await tx.get(requestKey(id));
      assert(found && requestUntil(found) > now, 'not_found', 'Gate request not found or expired', 404);
      const answer = await verifyGateAnswer(tx, jws, id, now);
      await answerRequest(tx, found, { ...answer, answerer: { kind: 'webhook', gate: answer.gate } }, now);
      await this.audit(tx, now, answer.decision === 'allow' ? 'gate.approved' : 'gate.refused', { id, gate: answer.gate, cid: found.cid, action: found.action, audience: found.audience, by: 'webhook' });
      if (found.outcome === 'allow' && found.by_timeout) await this.auditSettled(tx, found, now, byTimeout);
      return found;
    });
    this.announceTimeouts(byTimeout, now);
    return { id, status: visibleRequest(req, now).status };
  }

  /** Bring a request up to date in a transaction: store what changed, audit it if it settled. */
  async refreshed(tx, req, now, byTimeout) {
    const { changed, settled } = await refreshRequest(tx, req, now);
    if (changed) await tx.put(requestKey(req.id), req);
    if (settled) await this.auditSettled(tx, req, now, byTimeout);
    return req;
  }

  /** Every allow by timeout is announced to the owner's browsers (plan §8). */
  announceTimeouts(requests, now) {
    for (const req of requests) this.notify({ title: 'Allowed because nobody answered', body: `${noticeText(req.action, 120)}${req.resource ? ` on ${noticeText(req.resource, 120)}` : ''} at ${noticeText(req.audience)} by ${noticeText(req.device_name) || 'a device'} was allowed because nobody answered in time.`, path: '#approvals', tag: `gate-timeout-${req.id}` }, now);
  }

  /**
   * Open a gate request: rate limit, charge the account (whose gates they are) for each gate
   * contacted, and record it. A request the balance cannot pay for is recorded but not sent, so
   * its entries wait for their timeouts (plan §2, STATUS D13).
   */
  async openGateRequest(tx, cred, subject, candidate, now, rateKey = cred.device_id) {
    const gates = await loadGates(tx, candidate.gates.flatMap(e => e.any));
    const ids = [...gates.keys()];
    // Push fatigue: a device that keeps asking is refused, not left to time out, so flooding
    // cannot be used to force an allow-on-timeout (plan §8).
    const hour = now - 3600000;
    for (const id of ids) {
      const recent = (this.gateRates.get(`${rateKey}:${id}`) || []).filter(at => at > hour);
      if (recent.length >= GATE_REQUESTS_PER_HOUR) return { rate_limited: true };
    }
    for (const id of ids) this.gateRates.set(`${rateKey}:${id}`, [...(this.gateRates.get(`${rateKey}:${id}`) || []).filter(at => at > hour), now]);
    const subscribed = ((await tx.get('push:subs')) || []).length > 0;
    const devices = new Map();
    for (const gate of gates.values()) if (gate.kind === 'dba-device') devices.set(gate.device_id, await tx.get(`device:${gate.device_id}`));
    // Owner, TOTP and security-key gates are reached through the owner's browsers (the notice links
    // to the approval page); a dba-device gate polls, so it is reached unless revoked; a webhook
    // gate is posted to after the decision answers ("sent" until that POST fails).
    const delivery = gate => gate.kind === 'webhook' ? 'sent' : gate.kind === 'dba-device' ? (devices.get(gate.device_id) && !devices.get(gate.device_id).revoked_at ? 'sent' : 'failed') : (subscribed ? 'sent' : 'failed');
    const req = newRequest({ cred, ...subject, candidate, gates, now, delivery });
    const contacted = contactedGates(req);
    if (contacted.length) {
      // Webhook gates cost more (a signed subrequest; plan §9), so each gate is priced by its kind.
      const amount = contacted.reduce((sum, id) => sum + price(gates.get(id)?.kind === 'webhook' ? 'gate_webhook' : 'gate'), 0);
      try { await charge(tx, { kind: 'gate', amount, aggregate: true }, now); }
      catch (error) {
        if (error.code !== 'insufficient_balance') throw error;
        for (const entry of req.entries) for (const g of entry.gates) if (g.state === 'sent' || g.state === 'failed') g.state = 'unpaid';
        req.unpaid = true;
      }
    }
    await tx.put(requestKey(req.id), req);
    return req;
  }

  /** Audit a request that just settled; allows by timeout are also announced (after the response). */
  async auditSettled(tx, req, now, byTimeout) {
    if (req.outcome === 'allow' && req.by_timeout) {
      await this.audit(tx, now, 'gate.allowed_by_timeout', { id: req.id, cid: req.cid, action: req.action, audience: req.audience });
      byTimeout.push(req);
    } else if (req.entries.every(e => e.by !== 'answer')) {
      // Answers are audited when given; a request that settled without one (timeout, deleted gate) here.
      await this.audit(tx, now, req.outcome === 'allow' ? 'gate.allowed' : 'gate.denied', { id: req.id, cid: req.cid, action: req.action, audience: req.audience, by: req.entries.map(e => e.by) });
    }
  }

  /**
   * Tell the gates about a new request: owner, TOTP and security-key gates by Web Push to the
   * owner's browsers (factor gates with a link to the approval page); dba-device gates poll.
   */
  async announceGateRequest(req, now, account) {
    const pushed = req.entries.filter(e => e.gates.some(g => g.state === 'sent' && (g.id === 'owner' || FACTOR_KINDS.includes(g.kind))));
    if (req.unpaid || !pushed.length) return;
    const wait = Math.max(...pushed.map(e => e.timeout_s));
    const minutes = Math.round(wait / 60);
    const link = account && hasFactorGates(req) ? await approvalLink(this.env, account, req) : null;
    this.notify({ title: 'Approval needed', body: `${noticeText(req.device_name) || 'A device'} asks to ${noticeText(req.action, 120)}${req.resource ? ` on ${noticeText(req.resource, 120)}` : ''} at ${noticeText(req.audience)}. Approve or deny within ${minutes >= 1 ? `${minutes} minute${minutes === 1 ? '' : 's'}` : `${wait} seconds`}.`, ...(link ? { url: link } : { path: '#approvals' }), tag: `gate-${req.id}` }, now);
  }

  async op_decisions({ cid, limit = PAGE }) {
    const rows = await this.storage.list({ prefix: `decision:${cid}:`, reverse: true, limit: Math.min(limit, 200) });
    return { items: [...rows.values()] };
  }

  /** Step-up requests: gate requests the owner gate can still answer (or approved), in the old shape. */
  async op_list_step_ups(_args, now) {
    const items = [];
    for (const req of await this.liveRequests(now)) {
      const owner = req.entries.find(e => e.gates.some(g => g.id === 'owner'));
      if (!owner || req.outcome === 'deny' || (!req.outcome && owner.outcome)) continue;
      items.push({ id: req.id, cid: req.cid, device_id: req.device_id, device_name: req.device_name, action: req.action, resource: req.resource, audience: req.audience, requested_at: req.created_at, expires_at: owner.deadline, ...(req.outcome === 'allow' ? { approved_at: req.settled_at, approved_until: req.approved_until } : {}) });
    }
    return { items };
  }

  /** Every gate request whose time is not over, brought up to date (deadlines, deleted gates). */
  async liveRequests(now) {
    const byTimeout = [];
    const live = await this.tx(async tx => {
      byTimeout.length = 0;
      const rows = [];
      for (const req of (await tx.list({ prefix: 'gatereq:' })).values()) {
        if (requestUntil(req) <= now) continue;
        rows.push(await this.refreshed(tx, req, now, byTimeout));
      }
      return rows;
    });
    this.announceTimeouts(byTimeout, now);
    return live;
  }

  /** Approve or deny a step-up request: an answer from the owner gate (404 once it is not waiting). */
  async op_decide_step_up({ id, approve, approver_device }, now) {
    try {
      const req = await this.op_answer_gate_request({ id, gate: 'owner', decision: approve ? 'allow' : 'deny', answerer: { kind: 'owner', device_id: approver_device ?? null } }, now);
      return { id, approved_at: approve ? now : undefined, denied_at: approve ? undefined : now, status: req.status };
    } catch (error) {
      if (['request_settled', 'expired', 'not_a_gate'].includes(error.code)) throw new ApiError(404, 'not_found', 'Approval request not found or expired');
      throw error;
    }
  }

  // ---- Gates (STATUS B7) -------------------------------------------------------

  async op_get_sign_in_gates() {
    return (await this.storage.get('signin_gates')) || { default: null, audiences: {}, dashboard: null };
  }

  /** Store sign-in gate settings (cleaned by the Worker); every gate must exist and be set up. */
  async op_put_sign_in_gates({ settings }, now) {
    const next = await this.tx(async tx => {
      const current = (await tx.get('signin_gates')) || { default: null, audiences: {}, dashboard: null };
      const merged = { ...current, ...settings, audiences: settings.audiences ?? current.audiences ?? {} };
      const lists = [merged.default, merged.dashboard, ...Object.values(merged.audiences)].filter(Boolean);
      const gates = await loadGates(tx, lists.flatMap(entries => entries.flatMap(e => e.any)));
      for (const id of new Set(lists.flatMap(entries => entries.flatMap(e => e.any)))) assert(gates.get(id) && (gates.get(id).state ?? 'active') === 'active', 'unknown_gate', `Gate ${id} does not exist or is not set up yet`, 400);
      await tx.put('signin_gates', merged);
      await this.audit(tx, now, 'sign_in_gates.changed', { before: current, after: merged });
      return merged;
    });
    this.notify({ title: 'Sign-in gates changed', body: 'The gates that confirm sign-ins to your account were changed. If that was not you, sign in and check your account.', path: '#gates', tag: 'sign-in-gates' }, now);
    return next;
  }

  /**
   * A sign-in through Sign in with devicebasedauth.org (todo/additional_gates.md §5.1): resolve its
   * gates (the account's for this site, or its default; and the site's policy), open or read their
   * request, and once they pass (or when there are none) store the authorization code with the
   * claims to put in the ID token. One account request either way, as before gates.
   * Returns { status: 'stored' | 'pending' | 'denied', … }.
   */
  async op_sign_in({ account, client_id, policy = null, acr_values = '', requester, device_id = null, device_name = null, code }, now) {
    let asked = null; const byTimeout = [];
    const wanted = acr_values.split(' ').filter(Boolean);
    const result = await this.tx(async tx => {
      asked = null; byTimeout.length = 0;
      const settings = (await tx.get('signin_gates')) || {};
      const entries = settings.audiences?.[client_id] ?? settings.default ?? null;
      const store = async claims => {
        await tx.put(`code:${code.id}`, { ...code, ...claims, amr: [...new Set([...code.amr, ...(claims.amr || [])])], created_at: now });
        const alarm = await tx.getAlarm();
        if (!alarm || alarm > now + 600000) await tx.setAlarm(now + 600000);
        return { status: 'stored' };
      };
      if (!entries) {
        if (policy?.require) return { status: 'denied', code: 'gate_required', message: `${client_id} requires a sign-in gate; add one for it in your devicebasedauth.org dashboard` };
        if (!meetsAcr(ACR.session, wanted)) return { status: 'denied', code: 'acr_not_met', message: `${client_id} asked for a gated sign-in (acr_not_met); add a sign-in gate in your devicebasedauth.org dashboard` };
        return store({ acr: ACR.session });
      }
      const candidate = { gates: entries, fail_open: policy?.fail_open !== false };
      if (policy?.require && !meetsPolicy(entries, policy.kinds ?? null, await loadGates(tx, entries.flatMap(e => e.any)))) return { status: 'denied', code: 'gate_required', message: `${client_id} requires sign-in gates of other kinds (${policy.kinds?.join(', ')})` };
      const subject = { purpose: 'sign_in', action: 'sign_in', audience: client_id, requester, signature: gateSignature(candidate) };
      let req = await findRequest(tx, subject, now);
      if (req) await this.refreshed(tx, req, now, byTimeout);
      else {
        req = await this.openGateRequest(tx, { device_id, device: { name: device_name } }, subject, candidate, now, requester);
        if (req.rate_limited) return { status: 'denied', code: 'gate_rate_limited', message: 'Too many sign-in approvals were asked for; wait and try again' };
        await this.refreshed(tx, req, now, byTimeout);
        if (!req.outcome) asked = req;
      }
      if (req.outcome === 'deny') {
        const refused = req.entries.some(e => e.by === 'by_timeout_refused');
        return { status: 'denied', code: refused ? 'by_timeout_refused' : 'gate_denied', message: refused ? `Nobody answered in time, and ${client_id} does not accept sign-ins allowed by silence` : 'The sign-in was not approved' };
      }
      if (req.outcome === 'allow') {
        const claims = signInClaims(howPassed(req), !!req.by_timeout);
        if (!meetsAcr(claims.acr, wanted)) return { status: 'denied', code: 'acr_not_met', message: `${client_id} asked for a sign-in approved by an answer (acr_not_met), but nobody answered in time` };
        await tx.delete(requestKey(req.id));
        return store(claims);
      }
      return { status: 'pending', gate_request: { ...visibleRequest(req, now), number: req.number, retry_after: RETRY_AFTER_S, ...(hasFactorGates(req) ? { approve_url: await approvalLink(this.env, account, req), factors: await factorView(tx, req, this.env) } : {}) } };
    });
    if (asked) {
      await this.announceGateRequest(asked, now, account);
      if (webhookTargets(asked).length) this.background(this.deliverWebhooks(asked.id, account));
    }
    this.announceTimeouts(byTimeout, now);
    return result;
  }

  async op_list_gates() {
    const rows = await this.storage.list({ prefix: 'gate:' });
    return { items: [OWNER_GATE, ...[...rows.values()].map(visibleGate)] };
  }

  async op_create_gate({ input, account }, now) {
    const { gate, setup } = await this.tx(async tx => {
      const created = await createGate(tx, input, now, { env: this.env, account });
      await this.audit(tx, now, 'gate.created', { id: created.gate.id, kind: created.gate.kind, ...(created.gate.device_id ? { device_id: created.gate.device_id } : {}), ...(created.gate.url ? { url: created.gate.url } : {}) });
      return created;
    });
    if (gate.state === 'active') this.announceGate(gate, now);
    return { ...visibleGate(gate), ...(setup ? { setup } : {}) };
  }

  /** Finish setting up a TOTP or security-key gate. */
  async op_activate_gate({ id, body, account }, now) {
    const gate = await this.tx(async tx => {
      const done = await activateGate(tx, id, body, now, { env: this.env, account });
      await this.audit(tx, now, 'gate.activated', { id, kind: done.kind });
      return done;
    });
    this.announceGate(gate, now);
    return visibleGate(gate);
  }

  /** Gate changes are announced at once, like dba:* issuance (plan §8). */
  announceGate(gate, now) {
    this.notify({ title: 'Gate added', body: `“${noticeText(gate.label)}” (${gate.kind}) can now approve or refuse requests for your account.`, path: '#gates', tag: `gate-added-${gate.id}` }, now);
  }

  /** A request as the approval page shows it, with what it needs to offer factors. */
  async op_link_gate_request({ id }, now) {
    const byTimeout = [];
    const view = await this.tx(async tx => {
      byTimeout.length = 0;
      const req = await tx.get(requestKey(id));
      assert(req && requestUntil(req) > now, 'not_found', 'This request is over (answered, or its time ran out)', 404);
      await this.refreshed(tx, req, now, byTimeout);
      return { ...visibleRequest(req, now), factors: await factorView(tx, req, this.env) };
    });
    this.announceTimeouts(byTimeout, now);
    return view;
  }

  /** Delete a gate. Requests waiting on it can no longer pass through it (nothing to time out). */
  async op_delete_gate({ id }, now) {
    const gate = await this.tx(async tx => {
      const found = await tx.get(gateKey(id));
      assert(found, 'not_found', 'Gate not found', 404);
      await tx.delete(gateKey(id));
      await this.audit(tx, now, 'gate.deleted', { id, kind: found.kind });
      return found;
    });
    this.notify({ title: 'Gate removed', body: `“${noticeText(gate.label)}” no longer approves requests. Grants that named only this gate now deny.`, path: '#gates', tag: `gate-removed-${id}` }, now);
    return { ...visibleGate(gate), deleted: true };
  }

  /**
   * Gate requests still waiting or approved. `device_id` limits the list to requests one of that
   * device's dba-device gates can answer (what the device itself may see).
   */
  async op_list_gate_requests({ device_id }, now) {
    const gates = device_id ? new Set([...(await this.storage.list({ prefix: 'gate:' })).values()].filter(g => g.kind === 'dba-device' && g.device_id === device_id).map(g => g.id)) : null;
    const live = await this.liveRequests(now);
    return { items: live.filter(req => !gates || req.entries.some(e => e.gates.some(g => gates.has(g.id)))).map(req => visibleRequest(req, now)) };
  }

  async op_get_gate_request({ id, device_id }, now) {
    const byTimeout = [];
    const found = await this.tx(async tx => {
      byTimeout.length = 0;
      const req = await tx.get(requestKey(id));
      assert(req && requestUntil(req) > now, 'not_found', 'Gate request not found or expired', 404);
      if (device_id) {
        const ids = req.entries.flatMap(e => e.gates.map(g => g.id)).filter(g => g !== 'owner');
        const mine = [...(await loadGates(tx, ids)).values()].some(g => g.device_id === device_id);
        assert(mine || req.device_id === device_id, 'not_found', 'Gate request not found or expired', 404);
      }
      return visibleRequest(await this.refreshed(tx, req, now, byTimeout), now);
    });
    this.announceTimeouts(byTimeout, now);
    return found;
  }

  async op_answer_gate_request({ id, entry, gate, decision, answerer, proof, account }, now) {
    const byTimeout = [];
    const req = await this.tx(async tx => {
      byTimeout.length = 0;
      const found = await tx.get(requestKey(id));
      assert(found && requestUntil(found) > now, 'not_found', 'Gate request not found or expired', 404);
      await answerRequest(tx, found, { entry, gate, decision, answerer, proof }, now, { env: this.env, account, failures: this.factorFailures });
      await this.audit(tx, now, decision === 'allow' ? 'gate.approved' : 'gate.refused', { id, gate, cid: found.cid, action: found.action, audience: found.audience, by: answerer.device_id ?? 'session' });
      // This answer may finish a request whose other entries passed by timeout.
      if (found.outcome === 'allow' && found.by_timeout) await this.auditSettled(tx, found, now, byTimeout);
      return found;
    });
    this.announceTimeouts(byTimeout, now);
    return visibleRequest(req, now);
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
    // Gate requests and authorization codes are useless once their time is over; the next wake-up
    // is set for the first one still live, so none outlives it for long on an account that has
    // nothing else to do.
    let shortLived = null;
    for (const prefix of ['gatereq:', 'code:']) for (const [key, value] of await this.storage.list({ prefix })) {
      const until = prefix === 'gatereq:' ? requestUntil(value) : value.expires_at;
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
