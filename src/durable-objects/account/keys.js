import { assert } from '../../utils/errors.js';
import { charge, readBalance } from '../ledger.js';
import { noticeText } from '../../services/push.js';
import { scheduleCompaction, enrollmentTokenState } from './shared.js';

/**
 * API keys, connected apps (MCP OAuth) and enrollment tokens. Mixed into AccountDO
 * (account-do.js): `this` is the account's Durable Object.
 */
export class AccountKeys {
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
      await this.alert({ title: oauth ? 'App connected to your account' : 'API key created', body: `${oauth ? 'An app' : 'An API key'} “${noticeText(name)}” can now act for your devicebasedauth.org account (${scopes.join(', ')}).`, path: '#keys', tag: `key-${id}` }, now);
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
    }).then(async token => {
      await this.alert({ title: 'Enrollment token created', body: `“${noticeText(name)}” lets up to ${max_uses} devices enroll for ${noticeText(template.aud.join(', '), 120)} without approval.`, path: '#tokens', tag: `etok-${id}` }, now);
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
}

/** Drop a revoked app connection's refresh state from the balance row. */
async function forgetRefresh(tx, id, now) {
  const state = await readBalance(tx, now, { flush: true });
  if (!state.refresh?.[id]) return;
  delete state.refresh[id];
  await tx.put('balance', state);
}

function visibleToken({ hash: _hash, ...token }, now) { return { ...token, state: enrollmentTokenState(token, now) }; }

/** What the dashboard sees of an API key or connected app: never the hash. */
function visibleKey({ hash: _hash, oauth, ...key }) {
  return oauth ? { ...key, resource: oauth.resource } : key;
}
