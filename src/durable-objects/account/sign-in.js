import { assert } from '../../utils/errors.js';
import { randomId } from '../../utils/ids.js';
import { b64u } from '../../../packages/verify/src/jose.js';
import { price } from '../../utils/pricing.js';
import { charge } from '../ledger.js';
import { ACR, FACTOR_KINDS, gateKey, loadGates, looseningEntries, meetsAcr, meetsPolicy, signInClaims } from '../gates.js';
import { RETRY_AFTER_S, answerRequest, approvalLink, factorView, findRequest, gateSignature, hasFactorGates, howPassed, requestKey, visibleRequest } from '../gate-requests.js';
import { dashboardState } from './shared.js';

// A confirmed dashboard session stays confirmed this long (Clerk sessions last at most a week).
const CONFIRMED_SESSION_MS = 7 * 86400000;

/**
 * Gated sign-ins and confirmations: sign-in gate settings, Sign in with devicebasedauth.org and its
 * authorization codes, periodic confirmation of credentials, and the dashboard's own sign-in gate
 * with its recovery codes. Mixed into AccountDO (account-do.js): `this` is the account's Durable
 * Object.
 */
export class AccountSignIn {
  // ---- Sign-in gates (done/additional_gates.md §3.3, §5.1) ----------------------

  async op_get_sign_in_gates() {
    return (await this.storage.get('signin_gates')) || { default: null, audiences: {}, dashboard: null };
  }

  /** Store sign-in gate settings (cleaned by the Worker); every gate must exist and be set up. */
  async op_put_sign_in_gates({ settings, account }, now) {
    // A change that loosens a list (removes it, or lets more gates or a timeout pass) waits for the
    // current gates of that list, so a stolen session cannot switch them off (plan §3.3). The
    // request is keyed by the exact change: approving one change approves only that one.
    const change = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(settings)))));
    let asked = null; const byTimeout = [];
    const next = await this.tx(async tx => {
      asked = null; byTimeout.length = 0;
      const current = (await tx.get('signin_gates')) || { default: null, audiences: {}, dashboard: null };
      const merged = { ...current, ...settings, audiences: settings.audiences ?? current.audiences ?? {} };
      const loosening = looseningEntries(current, merged);
      if (loosening.length) {
        const candidate = { gates: loosening, fail_open: false };
        const subject = { purpose: 'settings', action: 'sign_in_gates', audience: 'devicebasedauth.org', requester: `settings:${change}`, signature: gateSignature(candidate) };
        let req = await findRequest(tx, subject, now);
        if (req) await this.refreshed(tx, req, now, byTimeout);
        else {
          req = await this.openGateRequest(tx, { device_id: null, device: { name: 'Change to sign-in gates' } }, subject, candidate, now, 'settings');
          if (req.rate_limited) return { status: 'denied', code: 'gate_rate_limited' };
          await this.refreshed(tx, req, now, byTimeout);
          if (!req.outcome) asked = req;
        }
        if (req.outcome === 'deny') return { status: 'denied', code: req.entries.some(e => e.by === 'by_timeout_refused') ? 'by_timeout_refused' : 'gate_denied' };
        if (req.outcome !== 'allow') return { status: 'pending', gate_request: { ...visibleRequest(req, now), retry_after: RETRY_AFTER_S, ...(hasFactorGates(req) ? { approve_url: await approvalLink(this.env, account, req) } : {}) } };
        await tx.delete(requestKey(req.id));
      }
      const lists = [merged.default, merged.dashboard, ...Object.values(merged.audiences)].filter(Boolean);
      const gates = await loadGates(tx, lists.flatMap(entries => entries.flatMap(e => e.any)));
      for (const id of new Set(lists.flatMap(entries => entries.flatMap(e => e.any)))) assert(gates.get(id) && (gates.get(id).state ?? 'active') === 'active', 'unknown_gate', `Gate ${id} does not exist or is not set up yet`, 400);
      // A dashboard gate that denies on timeout could lock the owner out (a lost phone): it needs
      // recovery codes first (plan §5.2).
      if (merged.dashboard?.some(e => e.on_timeout !== 'allow')) assert(((await tx.get('recovery'))?.hashes?.length ?? 0) > 0, 'recovery_codes_required', 'Make recovery codes first (POST /api/v1/settings/recovery-codes): a dashboard gate that denies on timeout could otherwise lock you out', 409);
      await tx.put('signin_gates', merged);
      await this.audit(tx, now, 'sign_in_gates.changed', { before: current, after: merged, ...(loosening.length ? { approved_by_gates: true } : {}) });
      return merged;
    });
    if (asked) {
      await this.announceGateRequest(asked, now, account);
      this.deliverAsync(asked, account);
    }
    this.announceTimeouts(byTimeout, now);
    if (next.status) return next;
    this.notify({ title: 'Sign-in gates changed', body: 'The gates that confirm sign-ins to your account were changed. If that was not you, sign in and check your account.', path: '#gates', tag: 'sign-in-gates' }, now);
    return next;
  }

  /**
   * A sign-in through Sign in with devicebasedauth.org (done/additional_gates.md §5.1): resolve its
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
      this.deliverAsync(asked, account);
    }
    this.announceTimeouts(byTimeout, now);
    return result;
  }

  // ---- Periodic confirmation (done/additional_gates.md §3.4, §5.3) ------------------------

  /**
   * Confirm a credential that carries confirm: open (or read) its `confirm` gate request; once its
   * gates pass, record confirmed_until (now + every_s) and return the claims the Worker signs into
   * a dba-confirmation+jwt. Charged the confirmation price when one is issued.
   */
  async op_confirm_credential({ account, cid }, now) {
    let asked = null; const byTimeout = [];
    const result = await this.tx(async tx => {
      asked = null; byTimeout.length = 0;
      const cred = await tx.get(`cred:${cid}`);
      assert(cred && !cred.revoked_at, 'revoked', 'Credential has been revoked', 403);
      assert(cred.confirm, 'no_confirmation', 'This credential does not need confirmation', 409);
      const candidate = { gates: cred.confirm.gates.map(e => ({ any: e.any, timeout_s: e.timeout_s ?? 300, on_timeout: e.on_timeout ?? 'deny' })), fail_open: true };
      const subject = { purpose: 'confirm', action: 'confirm', audience: 'devicebasedauth.org', cid, requester: cid, signature: gateSignature(candidate) };
      let req = await findRequest(tx, subject, now);
      if (req) await this.refreshed(tx, req, now, byTimeout);
      else {
        req = await this.openGateRequest(tx, cred, subject, candidate, now);
        if (req.rate_limited) return { status: 'denied', code: 'gate_rate_limited' };
        await this.refreshed(tx, req, now, byTimeout);
        if (!req.outcome) asked = req;
      }
      if (req.outcome === 'deny') return { status: 'denied', code: 'gate_denied' };
      if (req.outcome === 'allow') {
        await charge(tx, { kind: 'confirm', amount: price('confirm'), aggregate: true }, now);
        await tx.delete(requestKey(req.id));
        const gates = howPassed(req);
        cred.confirmed_at = now; cred.confirmed_until = now + cred.confirm.every_s * 1000; cred.confirmed_by_timeout = !!req.by_timeout;
        await tx.put(`cred:${cid}`, cred);
        await this.audit(tx, now, req.by_timeout ? 'credential.confirmed_by_timeout' : 'credential.confirmed', { cid, until: cred.confirmed_until });
        return { status: 'confirmed', claims: { sub: cred.device_id, aud: cred.aud, cid, cnf: { jkt: cred.jkt }, iat: Math.floor(now / 1000), exp: Math.floor(cred.confirmed_until / 1000), gates, by_timeout: !!req.by_timeout } };
      }
      return { status: 'pending', gate_request: { ...visibleRequest(req, now), retry_after: RETRY_AFTER_S, ...(hasFactorGates(req) ? { approve_url: await approvalLink(this.env, account, req) } : {}) } };
    });
    if (asked) {
      await this.announceGateRequest(asked, now, account);
      this.deliverAsync(asked, account);
    }
    this.announceTimeouts(byTimeout, now);
    return result;
  }

  /** "Stop trusting this device now": end a credential's confirmation (online audiences at once). */
  async op_unconfirm_credential({ cid }, now) {
    return this.tx(async tx => {
      const cred = await tx.get(`cred:${cid}`);
      assert(cred, 'not_found', 'Credential not found', 404);
      assert(cred.confirm, 'no_confirmation', 'This credential does not need confirmation; revoke it instead', 409);
      cred.confirmed_until = Math.min(cred.confirmed_until ?? 0, now);
      await tx.put(`cred:${cid}`, cred);
      await this.audit(tx, now, 'credential.unconfirmed', { cid });
      return { cid, confirmed_until: cred.confirmed_until, note: 'Online checks refuse it now; offline verifiers accept its last confirmation until it expires. Revoke the credential to stop those too.' };
    });
  }

  // ---- The dashboard's own sign-in gate (done/additional_gates.md §5.2) -----------------

  async op_dashboard_status({ session }, now) {
    return { dashboard: await dashboardState(this.storage, session, now), recovery_codes_left: ((await this.storage.get('recovery'))?.hashes?.length ?? 0) };
  }

  /**
   * Confirm a dashboard session through its gates: open or read the request; once it passes, the
   * session is confirmed until it ends (at most CONFIRMED_SESSION_MS). `answer` is this page's own
   * answer for a deny-on-timeout entry ({ entry, gate, proof: { totp | webauthn } }): a locked
   * session may answer only its own request, and only with a factor.
   */
  async op_dashboard_confirm({ account, session, device_id = null, device_name = null, answer = null }, now) {
    let asked = null; const byTimeout = [];
    const result = await this.tx(async tx => {
      asked = null; byTimeout.length = 0;
      const settings = (await tx.get('signin_gates')) || {};
      if (!settings.dashboard) return { status: 'confirmed' };
      const candidate = { gates: settings.dashboard, fail_open: true };
      const subject = { purpose: 'dashboard', action: 'dashboard', audience: 'devicebasedauth.org', requester: session, signature: gateSignature(candidate) };
      let req = await findRequest(tx, subject, now);
      if (req) await this.refreshed(tx, req, now, byTimeout);
      else {
        req = await this.openGateRequest(tx, { device_id, device: { name: device_name } }, subject, candidate, now, session);
        if (req.rate_limited) return { status: 'denied', code: 'gate_rate_limited' };
        await this.refreshed(tx, req, now, byTimeout);
        if (!req.outcome) asked = req;
      }
      if (answer && !req.outcome) {
        const gate = await tx.get(gateKey(answer.gate));
        assert(gate && FACTOR_KINDS.includes(gate.kind), 'not_a_gate', 'A locked session answers only with an authenticator code or a security key', 403);
        await answerRequest(tx, req, { entry: answer.entry, gate: answer.gate, decision: 'allow', answerer: { kind: 'owner', device_id }, proof: answer.proof }, now, { env: this.env, account, failures: this.factorFailures });
        await this.audit(tx, now, 'gate.approved', { id: req.id, gate: answer.gate, purpose: 'dashboard' });
      }
      if (req.outcome === 'deny') return { status: 'denied', code: 'gate_denied' };
      if (req.outcome === 'allow') {
        await tx.delete(requestKey(req.id));
        await tx.put(`dashsess:${session}`, { confirmed_at: now, until: now + CONFIRMED_SESSION_MS, by: howPassed(req) });
        await this.audit(tx, now, 'dashboard.confirmed', { session_kind: session.split(':')[0], by: howPassed(req) });
        await this.scheduleWake(tx, now + CONFIRMED_SESSION_MS);
        return { status: 'confirmed' };
      }
      return { status: 'pending', gate_request: { ...visibleRequest(req, now), number: req.number, retry_after: RETRY_AFTER_S, ...(hasFactorGates(req) ? { approve_url: await approvalLink(this.env, account, req), factors: await factorView(tx, req, this.env) } : {}) } };
    });
    if (asked) {
      await this.announceGateRequest(asked, now, account);
      this.deliverAsync(asked, account);
    }
    this.announceTimeouts(byTimeout, now);
    return result;
  }

  /** Make 10 new one-time recovery codes (shown once; stored hashed). Old ones stop working. */
  async op_recovery_codes(_args, now) {
    const codes = Array.from({ length: 10 }, () => randomId('x', 12).slice(2).replace(/(.{4})(?=.)/g, '$1-'));
    await this.tx(async tx => {
      await tx.put('recovery', { hashes: await Promise.all(codes.map(recoveryHash)), created_at: now });
      await this.audit(tx, now, 'recovery_codes.created', {});
    });
    this.notify({ title: 'New recovery codes', body: 'New recovery codes were made for your account; the old ones no longer work. If that was not you, sign in and check your account.', path: '#gates', tag: 'recovery-codes' }, now);
    return { codes, created_at: now };
  }

  /** Pass the dashboard gate with a recovery code (once per code), announced to every browser. */
  async op_dashboard_recover({ session, code }, now) {
    const left = await this.tx(async tx => {
      const recovery = await tx.get('recovery');
      const hash = await recoveryHash(code);
      const i = recovery?.hashes?.indexOf(hash) ?? -1;
      assert(i >= 0, 'invalid_recovery_code', 'That recovery code is not valid (or was used already)', 403);
      recovery.hashes.splice(i, 1);
      await tx.put('recovery', recovery);
      await tx.put(`dashsess:${session}`, { confirmed_at: now, until: now + CONFIRMED_SESSION_MS, by: [{ kind: 'recovery_code', by: 'answer' }] });
      await this.audit(tx, now, 'recovery_code.used', { session_kind: session.split(':')[0], left: recovery.hashes.length });
      await this.scheduleWake(tx, now + CONFIRMED_SESSION_MS);
      return recovery.hashes.length;
    });
    this.notify({ title: 'A recovery code was used', body: `Someone opened your dashboard with a recovery code (${left} left). If that was not you, revoke everything and change your sign-in.`, path: '#gates', tag: `recovery-used-${now}` }, now);
    return { status: 'confirmed', recovery_codes_left: left };
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
}

/** Hash a recovery code as typed (case and dashes ignored). */
async function recoveryHash(code) {
  const normalized = String(code ?? '').toUpperCase().replace(/[^0-9A-Z]/g, '');
  return b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`dba-recovery\n${normalized}`))));
}
