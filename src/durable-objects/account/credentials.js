import { assert } from '../../utils/errors.js';
import { rpc } from '../../utils/rpc.js';
import { charge, readBalance } from '../ledger.js';
import { signEvent, postEvent, WEBHOOK_ATTEMPTS, WEBHOOK_BACKOFF_MS } from '../../services/webhooks.js';
import { nextNotice, noticeText } from '../../services/push.js';
import { hasDbaAction } from '../../auth/reverify.js';
import { checkGatesForIssue } from '../gates.js';
import { PAGE, scheduleCompaction, enrollmentTokenState, dashboardState } from './shared.js';

const EVENTS_KEPT = 50;
const OUTBOX_RETRY_MS = 60000;
const monthOf = now => new Date(now).toISOString().slice(0, 7);

/**
 * Credentials and devices: issuing, reading, renewing and rotating, revoking, and delivering
 * revocations (status lists and audiences' webhooks) from the outbox. Mixed into AccountDO
 * (account-do.js): `this` is the account's Durable Object.
 */
export class AccountCredentials {
  // ---- Credentials ------------------------------------------------------------

  /**
   * Charge and store a newly signed credential (and its device). The Worker signs first so the
   * stored JWS is exactly what the device receives; if the charge fails nothing is kept.
   */
  async op_store_credential({ record, gate_policies = [], extra_gates = [], device, price, charge_id, fingerprint, reinstate = false, source, enrollment_token }, now) {
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
      await checkGatesForIssue(tx, [...record.grants, ...(extra_gates.length ? [{ require: { gates: [{ any: extra_gates }] } }] : [])], record.device_id, gate_policies);
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
  async op_credential_status({ cid, with_jws = false, proof_key, proof_exp, rate, session }, now) {
    if (rate) await this.op_rate_limit(rate, now);
    const cred = await this.storage.get(`cred:${cid}`);
    // A dashboard device (dba:session) is a sign-in too: report whether the dashboard gate holds it.
    const dashboard = session ? await dashboardState(this.storage, session, now) : undefined;
    if (!cred) return { exists: false, revoked: true };
    if (proof_key) {
      const nowSeconds = Math.floor(now / 1000);
      for (const [key, exp] of this.proofs) { if (exp > nowSeconds) break; this.proofs.delete(key); }
      if (this.proofs.has(proof_key)) return { exists: true, replayed: true };
      this.proofs.set(proof_key, proof_exp);
    }
    return { exists: true, ...(dashboard ? { dashboard } : {}), ...(cred.confirm ? { confirm: cred.confirm, confirmed_until: cred.confirmed_until ?? 0 } : {}), ...(with_jws ? { jws: cred.jws } : {}), revoked: !!cred.revoked_at, state: credentialState(cred, now), jti: cred.jti, exp: cred.exp, grants: cred.grants, aud: cred.aud, device_id: cred.device_id, jkt: cred.jkt, lifetime: cred.lifetime, max_exp: cred.max_exp, status: cred.status, device: cred.device, ...(cred.parent_cid ? { parent_cid: cred.parent_cid } : {}) };
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
}

/** active | expired | revoked */
export function credentialState(cred, now = Date.now()) {
  if (cred.revoked_at) return 'revoked';
  if (cred.exp * 1000 <= now) return 'expired';
  return 'active';
}
