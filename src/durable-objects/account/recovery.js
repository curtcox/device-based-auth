import { assert } from '../../utils/errors.js';
import { recoveryHash } from './sign-in.js';
import { gateActive } from '../gates.js';
import { RETRY_AFTER_S, approvalLink, findRequest, gateSignature, hasFactorGates, howPassed, requestKey } from '../gate-requests.js';

// Wrong recovery codes allowed per account in RECOVERY_WINDOW_MS (like gate factors: in memory).
const RECOVERY_TRIES = 5;
const RECOVERY_WINDOW_MS = 15 * 60000;
/** Gates that can let a new device in: a passkey or security key, or another of the owner's devices. */
export const RECOVERY_KINDS = Object.freeze(['webauthn', 'dba-device']);
// Recoveries by gate anyone may start per account per hour (each asks the owner's gates).
const GATE_RECOVERIES_PER_HOUR = 3;
// How long the owner's gates have to approve a recovery.
const RECOVERY_TIMEOUT_S = 600;

const recoveryGates = gates => [...gates.values()].filter(g => gateActive(g) && RECOVERY_KINDS.includes(g.kind));

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
   * Start (or find) a recovery by gate for the new key `jkt`: one entry any of the account's
   * passkey, security-key or device gates may approve, typing the number the new device shows;
   * denied after RECOVERY_TIMEOUT_S. Anyone who knows the account id can ask, so at most
   * GATE_RECOVERIES_PER_HOUR new ones an hour, and an unknown account stores nothing. The owner's
   * browsers are told (factor gates get a link to the approval page); device gates poll.
   */
  async op_recover_gate_start({ jkt, device_name = null, account }, now) {
    let asked = null;
    const result = await this.tx(async tx => {
      asked = null;
      const profile = await tx.get('profile');
      const gates = profile ? recoveryGates(await tx.list({ prefix: 'gate:' })) : [];
      assert(gates.length, 'no_recovery_gate', 'This account has no passkey, security key or device gate that can approve a recovery; use a recovery code', 409);
      const candidate = { gates: [{ any: gates.map(g => g.id).sort(), timeout_s: RECOVERY_TIMEOUT_S, on_timeout: 'deny' }], fail_open: false };
      const subject = { purpose: 'recover', action: 'recover', audience: 'devicebasedauth.org', requester: `jkt:${jkt}`, signature: gateSignature(candidate) };
      let req = await findRequest(tx, subject, now);
      if (req) await this.refreshed(tx, req, now, []);
      else {
        this.recoveryStarts = (this.recoveryStarts || []).filter(at => at > now - 3600000);
        assert(this.recoveryStarts.length < GATE_RECOVERIES_PER_HOUR, 'too_many_attempts', 'Too many recoveries were started for this account this hour; try again later or use a recovery code', 429);
        req = await this.openGateRequest(tx, { device_id: null, device: { name: device_name || 'A new device' } }, subject, candidate, now, 'recover');
        assert(!req.rate_limited, 'too_many_attempts', 'The account\'s gates were asked too often this hour; try again later or use a recovery code', 429);
        this.recoveryStarts.push(now);
        await this.audit(tx, now, 'recovery.requested', { id: req.id, jkt });
        asked = req;
      }
      return { id: req.id, number: req.number, retry_after: RETRY_AFTER_S, expires_at: Math.max(...req.entries.map(e => e.deadline)), ...(hasFactorGates(req) ? { approve_url: await approvalLink(this.env, account, req) } : {}) };
    });
    if (asked) {
      this.notify({ title: 'Someone is recovering your account', body: `“${String(device_name || 'A new device').slice(0, 80)}” asks to be let into your account after losing every device. Approve only if it is you, typing the number it shows; otherwise deny or ignore it.`, ...(result.approve_url ? { url: result.approve_url } : { path: '#approvals' }), tag: `recover-${result.id}` }, now);
      this.deliverAsync(asked, account);
    }
    return result;
  }

  /**
   * Where a recovery by gate stands, for the key that asked. Approved: the Worker issues the new
   * device's credential (its charge id is the request's, so asking again returns the same one);
   * the first time, it is audited, pushed and emailed.
   */
  async op_recover_gate_status({ id, jkt }, now) {
    let announce = false;
    const result = await this.tx(async tx => {
      announce = false;
      const req = await tx.get(requestKey(id));
      assert(req && req.purpose === 'recover' && req.key.includes(`\njkt:${jkt}\n`), 'recovery_expired', 'This recovery is over: it was denied, or its time ran out', 410);
      await this.refreshed(tx, req, now, []);
      if (req.outcome === 'deny') return { status: 'denied' };
      if (req.outcome !== 'allow') return { status: 'pending', retry_after: RETRY_AFTER_S };
      if (!req.recovered_at) {
        req.recovered_at = now;
        await tx.put(requestKey(id), req);
        await this.audit(tx, now, 'recovery.approved', { id, jkt, by: howPassed(req) });
        announce = true;
      }
      return { status: 'allowed', device_name: req.device_name };
    });
    if (announce) await this.alert({ title: 'Account recovered onto a new device', body: `Your gate let “${String(result.device_name).slice(0, 80)}” into your account. If that was not you, revoke it and check your gates.`, path: '#credentials', tag: `recovered-${id}` }, now);
    return result;
  }

  /**
   * How the owner could get back in after losing every device: recovery codes left, the gates
   * that can approve a recovery, and whether they said they accept losing the account instead.
   * `at_risk` while none of these.
   */
  async op_recovery_status() {
    const codes = (await this.storage.get('recovery'))?.hashes?.length ?? 0;
    const gates = recoveryGates(await this.storage.list({ prefix: 'gate:' })).map(g => ({ id: g.id, kind: g.kind, label: g.label }));
    const acknowledged = (await this.storage.get('profile'))?.no_recovery_acknowledged_at ?? null;
    return { recovery_codes_left: codes, recovery_gates: gates, no_recovery_acknowledged_at: acknowledged, at_risk: codes === 0 && !gates.length && !acknowledged };
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
