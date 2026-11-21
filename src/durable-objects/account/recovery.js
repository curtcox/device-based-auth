import { assert } from '../../utils/errors.js';
import { recoveryHash } from './sign-in.js';

// Wrong recovery codes allowed per account in RECOVERY_WINDOW_MS (like gate factors: in memory).
const RECOVERY_TRIES = 5;
const RECOVERY_WINDOW_MS = 15 * 60000;

/**
 * Getting back into an account after losing every device (todo/clerk_free_accounts.md §3.5,
 * STATUS B9): a recovery code puts a new dashboard device on the account, and the owner can see
 * how they could recover, or say they accept that they cannot. Mixed into AccountDO
 * (account-do.js): `this` is the account's Durable Object.
 */
export class AccountRecovery {
  /**
   * Use up one recovery code for a new device (the Worker then issues its dashboard credential).
   * Answers the same for an unknown account as for a wrong code, and stores nothing then, so
   * guessing at accounts creates none. Every use is audited, pushed and emailed.
   */
  async op_recover_with_code({ code, jkt, device_name = null }, now) {
    this.recoveryFailures = (this.recoveryFailures || []).filter(at => at > now - RECOVERY_WINDOW_MS);
    assert(this.recoveryFailures.length < RECOVERY_TRIES, 'too_many_attempts', 'Too many wrong recovery codes for this account; wait 15 minutes', 429);
    const hash = await recoveryHash(code);
    const left = await this.tx(async tx => {
      const profile = await tx.get('profile');
      const recovery = profile ? await tx.get('recovery') : null;
      const i = recovery?.hashes?.indexOf(hash) ?? -1;
      if (i < 0) { this.recoveryFailures.push(now); assert(false, 'invalid_recovery_code', 'That account id and recovery code do not match (or the code was used already)', 403); }
      recovery.hashes.splice(i, 1);
      await tx.put('recovery', recovery);
      await this.audit(tx, now, 'recovery_code.used', { session_kind: 'new_device', jkt, left: recovery.hashes.length });
      return recovery.hashes.length;
    });
    await this.alert({ title: 'Account recovered onto a new device', body: `A recovery code put a new device${device_name ? ` (“${String(device_name).slice(0, 80)}”)` : ''} on your account (${left} code${left === 1 ? '' : 's'} left). If that was not you, revoke it and make new recovery codes.`, path: '#credentials', tag: `recovered-${now}` }, now);
    return { id: hash.slice(0, 16), left };
  }

  /**
   * How the owner could get back in after losing every device: recovery codes left, and whether
   * they said they accept losing the account instead. `at_risk` while neither.
   */
  async op_recovery_status() {
    const codes = (await this.storage.get('recovery'))?.hashes?.length ?? 0;
    const acknowledged = (await this.storage.get('profile'))?.no_recovery_acknowledged_at ?? null;
    return { recovery_codes_left: codes, no_recovery_acknowledged_at: acknowledged, at_risk: codes === 0 && !acknowledged };
  }

  /** The owner accepts that losing every device loses the account (shown until a method exists). */
  async op_acknowledge_no_recovery(_args, now) {
    await this.tx(async tx => {
      const profile = await tx.get('profile');
      assert(profile, 'not_found', 'Account not found', 404);
      if (profile.no_recovery_acknowledged_at) return;
      await tx.put('profile', { ...profile, no_recovery_acknowledged_at: now });
      await this.audit(tx, now, 'recovery.none_acknowledged', {});
    });
    return this.op_recovery_status();
  }
}
