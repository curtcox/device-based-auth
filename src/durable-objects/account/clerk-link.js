import { assert } from '../../utils/errors.js';
import { gateActive } from '../gates.js';
import { RECOVERY_KINDS } from './recovery.js';

/**
 * A Clerk sign-in linked to an account made without Clerk, and an account that stops using Clerk
 * (todo/clerk_free_accounts.md §3.6, STATUS B9). `clerk_sub` in the profile is the Clerk user
 * whose sessions may act as this account; the middleware checks it on every such session, so a
 * stale or forged `dba_account` claim is refused. A Clerk user's own (empty) account remembers
 * `linked_to`, so deleting the Clerk user reaches the account it was linked to. Mixed into
 * AccountDO (account-do.js): `this` is the account's Durable Object.
 */
export class AccountClerkLink {
  /**
   * Does this (Clerk user's own) account hold anything: money, credentials, or a link to an
   * account other than `for_account` (a link to it is a retry after Clerk failed)?
   */
  async op_clerk_history({ for_account }) {
    const profile = await this.storage.get('profile');
    if (!profile) return { has_history: false };
    const balance = (await this.storage.get('balance'))?.balance_microdollars ?? 0;
    const any = async prefix => (await this.storage.list({ prefix, limit: 1 })).size > 0;
    return { has_history: balance > 0 || (!!profile.linked_to && profile.linked_to !== for_account) || await any('ledger:') || await any('cred:') || await any('key:') };
  }

  /** Let Clerk user `sub` sign in to this account. */
  async op_clerk_link({ sub }, now) {
    await this.tx(async tx => {
      const profile = await tx.get('profile');
      assert(profile, 'not_found', 'Account not found', 404);
      assert(!profile.clerk_sub || profile.clerk_sub === sub, 'already_linked', 'This account already has a linked sign-in; unlink it first', 409);
      if (profile.clerk_sub === sub) return;
      await tx.put('profile', { ...profile, clerk_sub: sub });
      await this.audit(tx, now, 'account.clerk_linked', {});
    });
    await this.alert({ title: 'A sign-in was linked to your account', body: 'A password (Clerk) sign-in can now open your account. If that was not you, unlink it on the Account page.', path: '#account', tag: `clerk-linked-${now}` }, now);
    return { linked: true };
  }

  /** On a Clerk user's own account: remember which account its sign-in opens. */
  async op_clerk_mark_linked({ account, linked_to }, now) {
    await this.tx(async tx => {
      const profile = (await tx.get('profile')) || { account, created_at: now };
      await tx.put('profile', { ...profile, linked_to });
    });
    return { ok: true };
  }

  /**
   * Stop letting the linked Clerk user sign in. Refused unless the owner keeps another way in: a
   * live dashboard device, recovery codes, a passkey or device gate, or an address verified here.
   */
  async op_clerk_unlink(_args, now) {
    const sub = await this.tx(async tx => {
      const profile = await tx.get('profile');
      assert(profile?.clerk_sub, 'not_linked', 'This account has no linked sign-in', 409);
      assert(await this.otherWayIn(tx, profile, now), 'no_other_way_in', 'Unlinking would leave no way into this account: add a dashboard device, recovery codes, a passkey or a verified email address first', 409);
      const { clerk_sub: gone, ...rest } = profile;
      const next = rest.email_source === 'clerk' ? (({ email: _e, email_source: _s, ...r }) => r)(rest) : rest;
      await tx.put('profile', next);
      await this.audit(tx, now, 'account.clerk_unlinked', {});
      return gone;
    });
    await this.alert({ title: 'A sign-in was unlinked from your account', body: 'The password (Clerk) sign-in no longer opens your account.', path: '#account', tag: `clerk-unlinked-${now}` }, now);
    return { sub };
  }

  async otherWayIn(tx, profile, now) {
    if (((await tx.get('recovery'))?.hashes?.length ?? 0) > 0) return true;
    if (profile.email_source === 'verified' && profile.email) return true;
    if ([...(await tx.list({ prefix: 'gate:' })).values()].some(g => gateActive(g) && RECOVERY_KINDS.includes(g.kind))) return true;
    return [...(await tx.list({ prefix: 'cred:' })).values()].some(c => !c.revoked_at && c.exp * 1000 > now && c.grants?.some(g => g.actions?.includes('dba:session')));
  }

  /**
   * Clerk deleted user `sub`: never close the account; forget the link and an address that came
   * from Clerk. Returns the account its sign-in was linked to, if any, to tell it too.
   */
  async op_clerk_gone({ sub }, now) {
    return this.tx(async tx => {
      const profile = await tx.get('profile');
      if (!profile || (profile.account !== sub && profile.clerk_sub !== sub)) return { linked_to: null };
      let next = { ...profile };
      if (next.clerk_sub === sub) delete next.clerk_sub;
      if (next.email_source !== 'verified') { delete next.email; delete next.email_source; }
      await tx.put('profile', next);
      await this.audit(tx, now, 'account.clerk_removed', {});
      return { linked_to: profile.account === sub ? profile.linked_to ?? null : null };
    });
  }
}
