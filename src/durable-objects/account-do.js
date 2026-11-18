import { assert, errorResponse, ApiError } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { charge, deposit, readBalance, money } from './ledger.js';
import { periodSeconds } from '../../packages/verify/src/grants.js';
import { randomId } from '../utils/ids.js';

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

  async op_create_key({ id, name, scopes, hash }, now) {
    return this.tx(async tx => {
      const keys = await tx.list({ prefix: 'key:' });
      assert([...keys.values()].filter(k => !k.revoked_at).length < 25, 'too_many_keys', 'At most 25 active API keys');
      const key = { id, name, scopes, hash, created_at: now };
      await tx.put(`key:${id}`, key); await this.audit(tx, now, 'key.created', { key_id: id, name, scopes });
      const { hash: _hash, ...visible } = key; return visible;
    });
  }

  async op_list_keys() {
    const keys = await this.storage.list({ prefix: 'key:' });
    return { items: [...keys.values()].map(({ hash: _hash, ...k }) => k) };
  }

  async op_revoke_key({ id }, now) {
    return this.tx(async tx => {
      const key = await tx.get(`key:${id}`); assert(key, 'not_found', 'API key not found', 404);
      if (!key.revoked_at) { key.revoked_at = now; await tx.put(`key:${id}`, key); await this.audit(tx, now, 'key.revoked', { key_id: id }); }
      const { hash: _hash, ...visible } = key; return visible;
    });
  }

  async op_authenticate_key({ id, hash }) {
    const key = await this.storage.get(`key:${id}`);
    assert(key && !key.revoked_at && key.hash === hash, 'invalid_auth', 'Invalid API key', 401);
    return { scopes: key.scopes };
  }

  // ---- Credentials ------------------------------------------------------------

  /**
   * Charge and store a newly signed credential (and its device). The Worker signs first so the
   * stored JWS is exactly what the device receives; if the charge fails nothing is kept.
   */
  async op_store_credential({ record, device, price, charge_id, source }, now) {
    return this.tx(async tx => {
      await charge(tx, { id: charge_id, kind: 'issue', amount: price, detail: { cid: record.cid } }, now);
      const existing = await tx.get(`device:${device.id}`);
      const stored = existing ? { ...existing, name: device.name || existing.name, last_issued_at: now } : { ...device, created_at: now, last_issued_at: now };
      if (stored.revoked_at) { delete stored.revoked_at; stored.reinstated_at = now; }
      await tx.put(`device:${device.id}`, stored);
      const cred = { ...record, created_at: now, events: [{ at: now, type: 'issued', jti: record.jti, source }] };
      await tx.put(`cred:${record.cid}`, cred);
      await this.audit(tx, now, 'credential.issued', { cid: record.cid, device_id: device.id, aud: record.aud, source });
      return { cid: record.cid, charged: price };
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
  async op_credential_status({ cid }, now) {
    const cred = await this.storage.get(`cred:${cid}`);
    if (!cred) return { exists: false, revoked: true };
    return { exists: true, revoked: !!cred.revoked_at, state: credentialState(cred, now), jti: cred.jti, exp: cred.exp, grants: cred.grants, aud: cred.aud, device_id: cred.device_id, jkt: cred.jkt, lifetime: cred.lifetime, max_exp: cred.max_exp, status: cred.status, device: cred.device };
  }

  async revokeOne(tx, cred, now, reason) {
    if (cred.revoked_at) return false;
    cred.revoked_at = now; cred.revoked_reason = reason;
    cred.events = [...cred.events, { at: now, type: 'revoked', reason }].slice(-EVENTS_KEPT);
    await tx.put(`cred:${cred.cid}`, cred);
    await tx.put(`outbox:${cred.cid}`, { shard: cred.status.shard, idx: cred.status.idx, at: now });
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
    await this.deliverOutbox(now);
    return { revoked, count: revoked.length };
  }

  /** Push revocations to the status-list shards; retried by alarm until delivered. */
  async deliverOutbox(now = Date.now()) {
    const pending = await this.storage.list({ prefix: 'outbox:', limit: 100 });
    let failed = false;
    const byShard = new Map();
    for (const [key, item] of pending) (byShard.get(item.shard) || byShard.set(item.shard, []).get(item.shard)).push([key, item]);
    for (const [shard, items] of byShard) {
      try {
        await rpc(this.env.STATUS, `shard-${shard}`, 'revoke', { indexes: items.map(([, i]) => i.idx) });
        for (const [key] of items) await this.storage.delete(key);
      } catch { failed = true; }
    }
    if (failed || pending.size === 100) await this.storage.setAlarm(now + OUTBOX_RETRY_MS);
    return { delivered: !failed };
  }

  /**
   * Store a renewed (or rotated) version. Rotation keeps the credential id but moves it to a new
   * key and status index, and revokes the old index so old copies stop working everywhere.
   */
  async op_renew({ cid, from_jti, update, price, charge_id, rotation }, now) {
    const result = await this.tx(async tx => {
      const cred = await tx.get(`cred:${cid}`);
      assert(cred, 'not_found', 'Credential not found', 404);
      assert(!cred.revoked_at, 'revoked', 'Credential has been revoked', 403);
      assert(cred.jti === from_jti, 'superseded', 'Only the current version of a credential can be renewed', 409);
      await charge(tx, { id: charge_id, kind: rotation ? 'rotate' : 'renew', amount: price, detail: { cid } }, now);
      if (rotation) await tx.put(`outbox:${cid}:${cred.status.idx}`, { shard: cred.status.shard, idx: cred.status.idx, at: now });
      const next = { ...cred, ...update, renewed_at: now, events: [...cred.events, { at: now, type: rotation ? 'rotated' : 'renewed', jti: update.jti }].slice(-EVENTS_KEPT) };
      await tx.put(`cred:${cid}`, next);
      if (rotation) {
        const device = await tx.get(`device:${cred.device_id}`);
        await tx.put(`device:${rotation.device.id}`, { ...rotation.device, created_at: now, last_issued_at: now, rotated_from: device?.id });
      }
      await this.audit(tx, now, rotation ? 'credential.rotated' : 'credential.renewed', { cid, jti: update.jti });
      return { cid, jti: update.jti, charged: price };
    });
    if (rotation) await this.deliverOutbox(now);
    return result;
  }

  // ---- Online authorization ---------------------------------------------------

  /**
   * Final online checks for one decision: revocation, proof replay, step-up and usage counters.
   * candidates: grant indexes that passed every static check, in order, with their online needs.
   */
  async op_authorize({ cid, jti, proof_jti, proof_exp, candidates, action, resource, audience, caller }, now) {
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
      if (cred) await tx.put(`decision:${cid}:${pad(now)}:${randomId('d', 6)}`, { at: now, audience, action, resource: resource ?? null, allow: decision.allow, code: decision.code, grant_index: decision.grant_index ?? null, caller, jti });
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
    await this.deliverOutbox(now);
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
    if (hasWork || more) await this.storage.setAlarm(now + (more ? 60000 : 86400000));
  }
}

/** active | expired | revoked */
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
