import { randomId } from '../../utils/ids.js';
import { periodSeconds, actionNamespace } from '../../../packages/verify/src/grants.js';
import { meetsPolicy, loadGates } from '../gates.js';
import { RETRY_AFTER_S, approvalLink, findRequest, gateSignature, hasFactorGates, howPassed, requestKey } from '../gate-requests.js';
import { PAGE } from './shared.js';

const pad = n => String(n).padStart(15, '0');

/**
 * Online authorization: the account's final checks for one decision, and the decision log.
 * Mixed into AccountDO (account-do.js): `this` is the account's Durable Object.
 */
export class AccountAuthorize {
  /**
   * Final online checks for one decision: revocation, proof replay, gates (step-up is the owner
   * gate) and usage counters. candidates: grant indexes that passed every static check, in order,
   * with their online needs ({ index, uses, step_up, gates, gates_reuse_s, fail_open }).
   */
  async op_authorize({ account = null, cid, jti, status_list, proof_jti, proof_exp, candidates, action, resource, audience, caller, country, token_namespace = null, gate_policy = null }, now) {
    const nowSeconds = Math.floor(now / 1000);
    for (const [key, exp] of this.proofs) { if (exp > nowSeconds) break; this.proofs.delete(key); }
    let asked = null; let byTimeout = [];
    const decision = await this.tx(async tx => {
      asked = null; byTimeout = [];
      const cred = await tx.get(`cred:${cid}`);
      let decision;
      if (!cred) decision = { allow: false, code: 'unknown_credential', reasons: ['unknown_credential'] };
      else if (cred.revoked_at) decision = { allow: false, code: 'revoked', reasons: ['revoked'] };
      // Rotation moves the credential to a new status entry and sets the old one: a version (or an
      // access token) carrying the old entry belongs to the replaced key and is revoked.
      else if (status_list && !sameStatusEntry(cred.status, status_list)) decision = { allow: false, code: 'revoked', reasons: ['revoked'] };
      else if (proof_jti && this.proofs.has(proof_jti)) decision = { allow: false, code: 'replayed_proof', reasons: ['replayed_proof'] };
      else {
        if (proof_jti) this.proofs.set(proof_jti, proof_exp);
        const reasons = []; let chosen = null; let needed = null; let denied = null;
        const subject = { cid, action, resource, audience };
        for (const candidate of candidates) {
          // Check both before spending either, so a grant that is out of uses does not burn the
          // owner's approval (nor a refusal count as a use).
          let usage = null;
          if (candidate.uses) {
            const counter = usageCounter(cred, candidate.index, token_namespace);
            if (!counter) { reasons.push('invalid_grant'); continue; }
            const per = periodSeconds(candidate.uses.per);
            const start = Number.isFinite(per) ? Math.floor(nowSeconds / per) * per : 0;
            const key = `usage:${counter}:${start}`;
            const used = (await tx.get(key)) || 0;
            if (used >= candidate.uses.count) { reasons.push('usage_limit_reached'); continue; }
            usage = { key, used };
          }
          // Confirmation online: the account's own record (spec/credential.md §9), so "stop
          // trusting this device now" takes effect at once.
          if (candidate.confirmation) {
            if (!cred.confirmed_until) { reasons.push('confirmation_required'); continue; }
            if (cred.confirmed_until <= now) { reasons.push('confirmation_expired'); continue; }
            if (cred.confirmed_by_timeout && candidate.fail_open === false) { reasons.push('confirmation_by_timeout_refused'); continue; }
          }
          // The audience's policy for this action (spec/evaluation.md §3.8), checked here because
          // only the account knows its gates' kinds; it applies to credentials issued before it.
          if (gate_policy?.require && !meetsPolicy(candidate.gates, gate_policy.kinds ?? null, await loadGates(tx, (candidate.gates || []).flatMap(e => e.any)))) { reasons.push('gate_required'); continue; }
          let approval = null;
          if (candidate.gates) {
            const signature = gateSignature(candidate);
            const req = await findRequest(tx, { purpose: 'authorize', ...subject, signature }, now);
            if (req) await this.refreshed(tx, req, now, byTimeout);
            const [waiting, refused] = candidate.step_up ? ['step_up_required', 'step_up_denied'] : ['gate_pending', 'gate_denied'];
            if (req?.outcome === 'deny') { reasons.push(req.entries.some(e => e.by === 'by_timeout_refused') ? 'by_timeout_refused' : refused); denied ||= { candidate, req }; continue; }
            if (req?.outcome !== 'allow') { reasons.push(waiting); needed ||= { candidate, req, signature }; continue; }
            approval = req;
          }
          if (approval) {
            // A spent approval is deleted (the same single write as marking it used); one that
            // covers repeated uses (gates_reuse_s) stays until it runs out.
            if (!approval.reuse_s) await tx.delete(requestKey(approval.id));
          }
          if (usage) await tx.put(usage.key, usage.used + 1);
          chosen = { candidate, approval }; break;
        }
        if (chosen) decision = { allow: true, code: 'ok', grant_index: chosen.candidate.index, reasons: [], ...(chosen.approval ? { gates: howPassed(chosen.approval), by_timeout: chosen.approval.by_timeout } : {}) };
        else if (needed) {
          // Asking again while a request waits reuses it: one request (and one notice) per thing
          // to approve, however often the site retries.
          let req = needed.req;
          if (!req) {
            req = await this.openGateRequest(tx, cred, subject, needed.candidate, now);
            if (req.rate_limited) decision = { allow: false, code: 'gate_rate_limited', reasons: ['gate_rate_limited'] };
            else {
              // A request with no gate left to answer (all deleted) denies at once.
              await this.refreshed(tx, req, now, byTimeout);
              if (req.outcome === 'deny') decision = { allow: false, code: needed.candidate.step_up ? 'step_up_denied' : 'gate_denied', reasons: reasons.map(r => r === 'gate_pending' ? 'gate_denied' : r === 'step_up_required' ? 'step_up_denied' : r), gate_request: { id: req.id } };
              else asked = req;
            }
          }
          if (!decision) {
            const deadline = Math.max(...req.entries.map(e => e.deadline));
            decision = { allow: false, code: needed.candidate.step_up ? 'step_up_required' : 'gate_pending', reasons, gate_request: { id: req.id, retry_after: RETRY_AFTER_S, deadline: Math.ceil(deadline / 1000), ...(account && hasFactorGates(req) ? { approve_url: await approvalLink(this.env, account, req) } : {}) } };
            if (needed.candidate.step_up) decision.step_up = { id: req.id, expires_in: Math.max(1, Math.ceil((deadline - now) / 1000)) };
          }
        } else if (denied) {
          decision = { allow: false, code: reasons.includes('by_timeout_refused') ? 'by_timeout_refused' : denied.candidate.step_up ? 'step_up_denied' : 'gate_denied', reasons, gate_request: { id: denied.req.id } };
        } else decision = { allow: false, code: 'forbidden', reasons: reasons.length ? reasons : ['no_grant_matched'] };
      }
      if (cred) await tx.put(`decision:${cid}:${pad(now)}:${randomId('d', 6)}`, { at: now, audience, action, resource: resource ?? null, country: country ?? null, allow: decision.allow, code: decision.code, grant_index: decision.grant_index ?? null, caller, jti, ...(decision.by_timeout ? { by_timeout: true } : {}) });
      const alarm = await tx.getAlarm();
      const wake = asked ? Math.max(...asked.entries.map(e => e.deadline)) + 60000 : now + 86400000;
      if (!alarm || alarm > wake) await tx.setAlarm(wake);
      return decision;
    });
    if (asked) await this.announceGateRequest(asked, now, account);
    if (asked && account) this.deliverAsync(asked, account);
    this.announceTimeouts(byTimeout, now);
    return decision;
  }

  async op_decisions({ cid, limit = PAGE }) {
    const rows = await this.storage.list({ prefix: `decision:${cid}:`, reverse: true, limit: Math.min(limit, 200) });
    return { items: [...rows.values()] };
  }
}

/**
 * The usage counter ("<cid>:<grant index>") a grant of this credential spends, for online
 * decisions. Two things keep a `limits.uses` from multiplying (STATUS L12):
 * - An access token carries only the grants in its audience's namespace (exchangeToken), so its
 *   grant indexes are mapped back to the credential's; otherwise a token's uses would land on
 *   another grant's counter, or a fresh one.
 * - A delegated grant whose limit came from its parent (`usage_from`, set at issuance) spends the
 *   parent's counter, so a device limited to 3 uses a day cannot delegate itself more.
 * Returns null when the index does not name a grant of the credential.
 * @param {object} cred stored credential record
 * @param {number} index grant index in the presented credential or access token
 * @param {string|null} tokenNamespace the audience namespace when an access token was presented
 * @returns {string|null}
 */
export function usageCounter(cred, index, tokenNamespace = null) {
  const grants = Array.isArray(cred.grants) ? cred.grants : [];
  const own = tokenNamespace === null ? index
    : grants.map((grant, i) => grant.actions.some(a => actionNamespace(a) === tokenNamespace) ? i : -1).filter(i => i >= 0)[index];
  if (!Number.isSafeInteger(own) || own < 0 || own >= grants.length) return null;
  const parentIndex = cred.parent_cid ? cred.usage_from?.[own] : null;
  return Number.isSafeInteger(parentIndex) ? `${cred.parent_cid}:${parentIndex}` : `${cred.cid}:${own}`;
}

/**
 * Does a credential's status_list claim name the record's current entry? Indexes are per shard,
 * so the list URI must match too: a rotated credential can land on the same index in another shard.
 * @param {{ idx: number, uri: string } | undefined} current the record's status
 * @param {{ idx: number, uri: string }} claimed payload.status.status_list
 * @returns {boolean}
 */
export function sameStatusEntry(current, claimed) {
  return !!current && current.idx === claimed?.idx && current.uri === claimed?.uri;
}
