import { assert } from '../../utils/errors.js';
import { randomId } from '../../utils/ids.js';
import { charge } from '../ledger.js';
import { price } from '../../utils/pricing.js';
import { RECORD_RETENTION_MS } from './shared.js';
import { ADDRESS_LIST_LIMITS, PUBLISH_INTERVAL_MS, REPUBLISH_AFTER_MS, ADDRESS_LIST_LIFETIME_S, addressListUri, addressListKey, addressListUnits, extensionDays, publishAddressList } from '../../services/address-lists.js';

const metaKey = id => `adl:${id}`;
const chunkKey = (id, n) => `adlc:${id}:${String(n).padStart(2, '0')}`;
// A deleted list's tombstone outlives every copy a verifier could still hold; then it is removed.
const PURGE_AFTER_MS = ADDRESS_LIST_LIFETIME_S * 1000 + 86400000;

/**
 * What a create or replace costs (STATUS D17, proposed): one `address_list` per started 1,000
 * ranges, and one `address_list_day` for each day it extends the list's prepaid published life
 * (re-signed about daily until 13 months after its last change; plan §11).
 */
export function addressListPrice(count, paidUntil, now) {
  const days = extensionDays(Math.max(paidUntil || 0, now), now + RECORD_RETENTION_MS);
  return { units: addressListUnits(count), days, amount: addressListUnits(count) * price('address_list') + days * price('address_list_day') };
}

/**
 * Issuance: every list the grants name must be one of this account's live lists (named lists
 * other accounts publish for this purpose, plan §4 "kind: audience", are not offered yet).
 */
export async function checkListsForIssue(tx, grants, now) {
  for (const [i, grant] of grants.entries()) {
    for (const l of grant?.net?.client?.addresses?.lists || []) {
      const meta = await tx.get(metaKey(l.id));
      assert(meta && !meta.deleted_at && meta.paid_until > now, 'unknown_address_list', `grants[${i}]: address list ${l.id} is not one of this account's lists (GET /api/v1/address-lists lists them)`, 400);
    }
  }
}

/**
 * Named address lists (STATUS B10 N3): the account's lists, their entries in chunks of 1,000, and
 * their publishing to R2. Mixed into AccountDO (account-do.js): `this` is the account's object.
 */
export class AccountAddressLists {
  visibleList(meta) {
    return { id: meta.id, name: meta.name, uri: addressListUri(this.env, meta.id), count: meta.count, ver: meta.ver, created_at: meta.created_at, updated_at: meta.updated_at, published_at: meta.published_at ?? null, published_until: meta.paid_until };
  }

  async loadCidrs(tx, meta) {
    const rows = await tx.list({ prefix: `adlc:${meta.id}:` });
    return [...rows.values()].flat();
  }

  async liveList(tx, id) {
    const meta = await tx.get(metaKey(id));
    assert(meta && !meta.deleted_at, 'not_found', 'Address list not found', 404);
    return meta;
  }

  async op_list_address_lists() {
    const rows = await this.storage.list({ prefix: 'adl:' });
    return { items: [...rows.values()].filter(m => !m.deleted_at).map(m => this.visibleList(m)) };
  }

  async op_get_address_list({ id }) {
    return this.tx(async tx => { const meta = await this.liveList(tx, id); return { ...this.visibleList(meta), cidrs: await this.loadCidrs(tx, meta) }; });
  }

  /** Store the entries, replacing any earlier chunks. */
  async writeChunks(tx, meta, cidrs, before = 0) {
    const chunks = Math.ceil(cidrs.length / ADDRESS_LIST_LIMITS.chunk);
    for (let n = 0; n < chunks; n++) await tx.put(chunkKey(meta.id, n), cidrs.slice(n * ADDRESS_LIST_LIMITS.chunk, (n + 1) * ADDRESS_LIST_LIMITS.chunk));
    for (let n = chunks; n < before; n++) await tx.delete(chunkKey(meta.id, n));
    meta.chunks = chunks;
  }

  /**
   * When to publish a change: now, unless the list was published in the last minute (then once
   * that minute is over, from the alarm), so a list is published at most once a minute.
   */
  async publishAt(tx, meta, now) {
    meta.publish_due = meta.published_at && meta.published_at > now - PUBLISH_INTERVAL_MS ? meta.published_at + PUBLISH_INTERVAL_MS : now;
    if (meta.publish_due > now) await this.scheduleWake(tx, meta.publish_due);
  }

  async op_create_address_list({ input }, now) {
    const meta = await this.tx(async tx => {
      const live = [...(await tx.list({ prefix: 'adl:' })).values()].filter(m => !m.deleted_at).length;
      assert(live < ADDRESS_LIST_LIMITS.perAccount, 'too_many_address_lists', `An account can have up to ${ADDRESS_LIST_LIMITS.perAccount} address lists; delete one first`, 409);
      const id = randomId('adl', 26); // 130 random bits
      const cost = addressListPrice(input.cidrs.length, 0, now);
      await charge(tx, { kind: 'address_list', amount: cost.amount, detail: { list: id, units: cost.units, days: cost.days } }, now);
      const created = { id, name: input.name, ver: 1, count: input.cidrs.length, created_at: now, updated_at: now, published_at: null, paid_until: now + RECORD_RETENTION_MS, cost_microdollars: cost.amount };
      await this.writeChunks(tx, created, input.cidrs);
      await this.publishAt(tx, created, now);
      await tx.put(metaKey(id), created);
      await this.audit(tx, now, 'address_list.created', { id, count: created.count });
      return created;
    });
    await this.publishDueLists(now);
    return { ...this.visibleList(await this.storage.get(metaKey(meta.id))), cost_microdollars: meta.cost_microdollars };
  }

  /** Replace the entries (and the name, if sent). Widening a list widens every grant naming it. */
  async op_replace_address_list({ id, input }, now) {
    const cost = await this.tx(async tx => {
      const meta = await this.liveList(tx, id);
      const priced = addressListPrice(input.cidrs.length, meta.paid_until, now);
      await charge(tx, { kind: 'address_list', amount: priced.amount, detail: { list: id, units: priced.units, days: priced.days } }, now);
      const before = meta.count;
      Object.assign(meta, { ...(input.name ? { name: input.name } : {}), ver: meta.ver + 1, count: input.cidrs.length, updated_at: now, paid_until: Math.max(meta.paid_until, now + RECORD_RETENTION_MS) });
      await this.writeChunks(tx, meta, input.cidrs, meta.chunks);
      await this.publishAt(tx, meta, now);
      await tx.put(metaKey(id), meta);
      await this.audit(tx, now, 'address_list.replaced', { id, ver: meta.ver, count_before: before, count: meta.count });
      return priced.amount;
    });
    await this.publishDueLists(now);
    return { ...this.visibleList(await this.storage.get(metaKey(id))), cost_microdollars: cost };
  }

  /** Delete: a signed tombstone replaces the list, so every grant naming it stops matching. */
  async op_delete_address_list({ id }, now) {
    await this.tx(async tx => {
      const meta = await this.liveList(tx, id);
      for (let n = 0; n < (meta.chunks || 0); n++) await tx.delete(chunkKey(id, n));
      Object.assign(meta, { ver: meta.ver + 1, count: 0, chunks: 0, deleted_at: now, updated_at: now });
      await this.publishAt(tx, meta, now);
      await tx.put(metaKey(id), meta);
      await this.audit(tx, now, 'address_list.deleted', { id });
    });
    await this.publishDueLists(now);
    return { id, deleted: true };
  }

  /**
   * Publish what is due (changes, tombstones, and the re-signing of lists whose copy is getting
   * old while their prepaid life lasts), purge long-deleted lists, and return when to look again.
   * Called after each change and from the account's alarm; a failed R2 put is retried then.
   * Runs one at a time, so an older version can never be put after a newer one.
   */
  publishDueLists(now) {
    const run = (this.listPublishing || Promise.resolve()).catch(() => {}).then(() => this.publishDueListsNow(now));
    this.listPublishing = run;
    return run;
  }

  async publishDueListsNow(now) {
    let next = null;
    const later = at => { next = Math.min(next ?? Infinity, at); };
    for (let meta of (await this.storage.list({ prefix: 'adl:' })).values()) {
      if (meta.deleted_at && meta.publish_due === null && meta.deleted_at + PURGE_AFTER_MS <= now) {
        await this.env.STATUS_BUCKET.delete(addressListKey(meta.id));
        await this.storage.delete(metaKey(meta.id));
        continue;
      }
      const resign = !meta.deleted_at && meta.published_at !== null && meta.published_at <= now - REPUBLISH_AFTER_MS && meta.paid_until > now;
      if ((meta.publish_due !== null && meta.publish_due <= now) || resign) {
        try {
          const cidrs = meta.deleted_at ? [] : await this.loadCidrs(this.storage, meta);
          await publishAddressList(this.env, { id: meta.id, ver: meta.ver, cidrs, deleted: !!meta.deleted_at }, now);
        } catch (error) {
          console.error('address list publish failed', meta.id, error?.message);
          later(now + 60000);
          continue;
        }
        // A change made while the put was in flight keeps its own publish_due.
        meta = await this.tx(async tx => {
          const current = await tx.get(metaKey(meta.id));
          if (!current) return meta;
          current.published_at = now;
          if (current.ver === meta.ver) current.publish_due = null;
          await tx.put(metaKey(meta.id), current);
          return current;
        });
      }
      if (meta.publish_due !== null) later(Math.max(meta.publish_due, now + 1000));
      else if (meta.deleted_at) later(meta.deleted_at + PURGE_AFTER_MS);
      else if (meta.paid_until > meta.published_at + REPUBLISH_AFTER_MS) later(meta.published_at + REPUBLISH_AFTER_MS);
    }
    if (next !== null) await this.alarmBy(next);
    return next;
  }
}
