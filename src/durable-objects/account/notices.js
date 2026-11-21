import { assert } from '../../utils/errors.js';
import { MAX_SUBSCRIPTIONS, broadcast, noticeText } from '../../services/push.js';

/**
 * Security notices by Web Push (master plan §10). Mixed into AccountDO (account-do.js): `this` is
 * the account's Durable Object.
 */
export class AccountNotices {
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
}

/** A push subscription without its endpoint and keys (only the browser's push service host). */
function visibleSubscription(s) {
  let host = ''; try { host = new URL(s.endpoint).hostname; } catch { /* ignore */ }
  return { id: s.id, name: s.name, push_service: host, created_at: s.created_at };
}
