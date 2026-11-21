import { assert } from '../../utils/errors.js';
import { FACTOR_KINDS, gateActive, gateKey } from '../gates.js';
import { RETRY_AFTER_S, answerRequest, approvalLink, factorView, findRequest, gateSignature, hasFactorGates, howPassed, requestKey, visibleRequest } from '../gate-requests.js';
import { REVERIFY_MINUTES } from '../../auth/reverify.js';

/** Gate kinds that can stand in for a recent sign-in: a factor, or another of the owner's devices. */
export const REVERIFY_KINDS = Object.freeze(['webauthn', 'totp', 'dba-device']);
// How long the owner's gates have to answer a re-verification.
const REVERIFY_TIMEOUT_S = 300;

/**
 * Re-verifying a dashboard device through the owner's gates (done/clerk_free_accounts.md §3.4,
 * STATUS B9): what a recent Clerk sign-in does for a browser session. Mixed into AccountDO
 * (account-do.js): `this` is the account's Durable Object.
 */
export class AccountReverify {
  /**
   * Open (or read) a re-verification for the dashboard device `cid`: one entry any of the account's
   * passkey, security-key, authenticator-app or other-device gates may approve, denying on
   * timeout. `answer` is this device's own factor answer ({ entry, gate, proof: { totp | webauthn } });
   * another device answers from its own gate requests, typing the number shown here. Once
   * approved, the credential's row records `reverified_at`, which the middleware reads with every
   * request (credential-status), so this costs no row of its own.
   */
  async op_session_reverify({ account, cid, device_id, device_name, answer = null }, now) {
    let asked = null;
    const result = await this.tx(async tx => {
      asked = null;
      const cred = await tx.get(`cred:${cid}`);
      assert(cred && !cred.revoked_at, 'revoked', 'Credential has been revoked', 401);
      const gates = [...(await tx.list({ prefix: 'gate:' })).values()].filter(g => gateActive(g) && REVERIFY_KINDS.includes(g.kind) && !(g.kind === 'dba-device' && g.device_id === device_id));
      assert(gates.length, 'no_reverify_gate', 'Add a gate that can confirm it is you first: a passkey or security key, an authenticator app, or another of your devices', 409);
      const candidate = { gates: [{ any: gates.map(g => g.id).sort(), timeout_s: REVERIFY_TIMEOUT_S, on_timeout: 'deny' }], fail_open: false };
      const subject = { purpose: 'reverify', action: 'reverify', audience: 'devicebasedauth.org', requester: `cid:${cid}`, signature: gateSignature(candidate) };
      let req = await findRequest(tx, subject, now);
      if (req) await this.refreshed(tx, req, now, []);
      else {
        req = await this.openGateRequest(tx, { device_id, device: { name: device_name } }, subject, candidate, now, `cid:${cid}`);
        if (req.rate_limited) return { status: 'denied', code: 'gate_rate_limited' };
        await this.refreshed(tx, req, now, []);
        if (!req.outcome) asked = req;
      }
      if (answer && !req.outcome) {
        const gate = await tx.get(gateKey(answer.gate));
        assert(gate && FACTOR_KINDS.includes(gate.kind), 'not_a_gate', 'This device answers only with an authenticator code or a security key; another device answers from its own gate requests', 403);
        // The factor is the authentication, so the asking device may answer with it. The audit row
        // below (session.reverified, with how it passed) records it: one row, as the gate price counts.
        await answerRequest(tx, req, { entry: answer.entry, gate: answer.gate, decision: 'allow', answerer: { kind: 'owner' }, proof: answer.proof }, now, { env: this.env, account, failures: this.factorFailures });
      }
      if (req.outcome === 'deny') return { status: 'denied', code: 'gate_denied' };
      if (req.outcome === 'allow') {
        await tx.delete(requestKey(req.id));
        cred.reverified_at = now;
        await tx.put(`cred:${cid}`, cred);
        await this.audit(tx, now, 'session.reverified', { cid, by: howPassed(req) });
        return { status: 'reverified', until: now + REVERIFY_MINUTES * 60000 };
      }
      return { status: 'pending', gate_request: { ...visibleRequest(req, now), number: req.number, retry_after: RETRY_AFTER_S, ...(hasFactorGates(req) ? { approve_url: await approvalLink(this.env, account, req), factors: await factorView(tx, req, this.env) } : {}) } };
    });
    if (asked) {
      await this.announceGateRequest(asked, now, account);
      this.deliverAsync(asked, account);
    }
    return result;
  }
}
