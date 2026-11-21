import { assert, ApiError } from '../../utils/errors.js';
import { charge } from '../ledger.js';
import { price } from '../../utils/pricing.js';
import { noticeText } from '../../services/push.js';
import { OWNER_GATE, FACTOR_KINDS, VENDOR_KINDS, activateGate, createGate, gateKey, loadGates, visibleGate } from '../gates.js';
import { GATE_REQUESTS_PER_HOUR, answerRequest, approvalLink, contactedGates, factorView, hasFactorGates, newRequest, refreshRequest, requestKey, requestUntil, visibleRequest, withAnswerAs } from '../gate-requests.js';

/**
 * Gates (STATUS B7): the gate registry, and the gate requests every gated operation opens, reads
 * and answers (online decisions, sign-ins, confirmations, settings changes). Mixed into AccountDO
 * (account-do.js): `this` is the account's Durable Object.
 */
export class AccountGates {
  /** Bring a request up to date in a transaction: store what changed, audit it if it settled. */
  async refreshed(tx, req, now, byTimeout) {
    const { changed, settled } = await refreshRequest(tx, req, now);
    if (changed) await tx.put(requestKey(req.id), req);
    if (settled) await this.auditSettled(tx, req, now, byTimeout);
    return req;
  }

  /** Every allow by timeout is announced to the owner's browsers (plan §8). */
  announceTimeouts(requests, now) {
    for (const req of requests) this.notify({ title: 'Allowed because nobody answered', body: `${noticeText(req.action, 120)}${req.resource ? ` on ${noticeText(req.resource, 120)}` : ''} at ${noticeText(req.audience)} by ${noticeText(req.device_name) || 'a device'} was allowed because nobody answered in time.`, path: '#approvals', tag: `gate-timeout-${req.id}` }, now);
  }

  /**
   * Open a gate request: rate limit, charge the account (whose gates they are) for each gate
   * contacted, and record it. A request the balance cannot pay for is recorded but not sent, so
   * its entries wait for their timeouts (plan §2, STATUS D13).
   */
  async openGateRequest(tx, cred, subject, candidate, now, rateKey = cred.device_id) {
    const gates = await loadGates(tx, candidate.gates.flatMap(e => e.any));
    const ids = [...gates.keys()];
    // Push fatigue: a device that keeps asking is refused, not left to time out, so flooding
    // cannot be used to force an allow-on-timeout (plan §8).
    const hour = now - 3600000;
    for (const id of ids) {
      const recent = (this.gateRates.get(`${rateKey}:${id}`) || []).filter(at => at > hour);
      if (recent.length >= GATE_REQUESTS_PER_HOUR) return { rate_limited: true };
    }
    for (const id of ids) this.gateRates.set(`${rateKey}:${id}`, [...(this.gateRates.get(`${rateKey}:${id}`) || []).filter(at => at > hour), now]);
    const subscribed = ((await tx.get('push:subs')) || []).length > 0;
    const devices = new Map();
    for (const gate of gates.values()) if (gate.kind === 'dba-device') devices.set(gate.device_id, await tx.get(`device:${gate.device_id}`));
    // Owner, TOTP and security-key gates are reached through the owner's browsers (the notice links
    // to the approval page); a dba-device gate polls, so it is reached unless revoked; a webhook
    // gate is posted to after the decision answers ("sent" until that POST fails).
    const delivery = gate => gate.kind === 'webhook' || VENDOR_KINDS.includes(gate.kind) ? 'sent' : gate.kind === 'dba-device' ? (devices.get(gate.device_id) && !devices.get(gate.device_id).revoked_at ? 'sent' : 'failed') : (subscribed ? 'sent' : 'failed');
    const req = newRequest({ cred, ...subject, candidate, gates, now, delivery });
    const contacted = contactedGates(req);
    if (contacted.length) {
      // Webhook gates cost more (a signed subrequest; plan §9), so each gate is priced by its kind.
      const priceOf = kind => price(kind === 'webhook' ? 'gate_webhook' : VENDOR_KINDS.includes(kind) ? 'gate_vendor' : 'gate');
      const amount = contacted.reduce((sum, id) => sum + priceOf(gates.get(id)?.kind), 0);
      try { await charge(tx, { kind: 'gate', amount, aggregate: true }, now); }
      catch (error) {
        if (error.code !== 'insufficient_balance') throw error;
        for (const entry of req.entries) for (const g of entry.gates) if (g.state === 'sent' || g.state === 'failed') g.state = 'unpaid';
        req.unpaid = true;
      }
    }
    await tx.put(requestKey(req.id), req);
    return req;
  }

  /** Audit a request that just settled; allows by timeout are also announced (after the response). */
  async auditSettled(tx, req, now, byTimeout) {
    if (req.outcome === 'allow' && req.by_timeout) {
      await this.audit(tx, now, 'gate.allowed_by_timeout', { id: req.id, cid: req.cid, action: req.action, audience: req.audience });
      byTimeout.push(req);
    } else if (req.entries.every(e => e.by !== 'answer')) {
      // Answers are audited when given; a request that settled without one (timeout, deleted gate) here.
      await this.audit(tx, now, req.outcome === 'allow' ? 'gate.allowed' : 'gate.denied', { id: req.id, cid: req.cid, action: req.action, audience: req.audience, by: req.entries.map(e => e.by) });
    }
  }

  /**
   * Tell the gates about a new request: owner, TOTP and security-key gates by Web Push to the
   * owner's browsers (factor gates with a link to the approval page); dba-device gates poll.
   */
  async announceGateRequest(req, now, account) {
    const pushed = req.entries.filter(e => e.gates.some(g => g.state === 'sent' && (g.id === 'owner' || FACTOR_KINDS.includes(g.kind))));
    if (req.unpaid || !pushed.length) return;
    const wait = Math.max(...pushed.map(e => e.timeout_s));
    const minutes = Math.round(wait / 60);
    const link = account && hasFactorGates(req) ? await approvalLink(this.env, account, req) : null;
    this.notify({ title: 'Approval needed', body: `${noticeText(req.device_name) || 'A device'} asks to ${noticeText(req.action, 120)}${req.resource ? ` on ${noticeText(req.resource, 120)}` : ''} at ${noticeText(req.audience)}. Approve or deny within ${minutes >= 1 ? `${minutes} minute${minutes === 1 ? '' : 's'}` : `${wait} seconds`}.`, ...(link ? { url: link } : { path: '#approvals' }), tag: `gate-${req.id}` }, now);
  }

  /** Step-up requests: gate requests the owner gate can still answer (or approved), in the old shape. */
  async op_list_step_ups(_args, now) {
    const items = [];
    for (const req of await this.liveRequests(now)) {
      const owner = req.entries.find(e => e.gates.some(g => g.id === 'owner'));
      if (!owner || req.outcome === 'deny' || (!req.outcome && owner.outcome)) continue;
      items.push({ id: req.id, cid: req.cid, device_id: req.device_id, device_name: req.device_name, action: req.action, resource: req.resource, audience: req.audience, requested_at: req.created_at, expires_at: owner.deadline, ...(req.outcome === 'allow' ? { approved_at: req.settled_at, approved_until: req.approved_until } : {}) });
    }
    return { items };
  }

  /** Every gate request whose time is not over, brought up to date (deadlines, deleted gates). */
  async liveRequests(now) {
    const byTimeout = [];
    const live = await this.tx(async tx => {
      byTimeout.length = 0;
      const rows = [];
      for (const req of (await tx.list({ prefix: 'gatereq:' })).values()) {
        if (requestUntil(req) <= now) continue;
        rows.push(await this.refreshed(tx, req, now, byTimeout));
      }
      return rows;
    });
    this.announceTimeouts(byTimeout, now);
    return live;
  }

  /** Approve or deny a step-up request: an answer from the owner gate (404 once it is not waiting). */
  async op_decide_step_up({ id, approve, approver_device }, now) {
    try {
      const req = await this.op_answer_gate_request({ id, gate: 'owner', decision: approve ? 'allow' : 'deny', answerer: { kind: 'owner', device_id: approver_device ?? null } }, now);
      return { id, approved_at: approve ? now : undefined, denied_at: approve ? undefined : now, status: req.status };
    } catch (error) {
      if (['request_settled', 'expired', 'not_a_gate'].includes(error.code)) throw new ApiError(404, 'not_found', 'Approval request not found or expired');
      throw error;
    }
  }

  // ---- Gate registry and requests (STATUS B7) -----------------------------------

  async op_list_gates() {
    const rows = await this.storage.list({ prefix: 'gate:' });
    return { items: [OWNER_GATE, ...[...rows.values()].map(visibleGate)] };
  }

  async op_create_gate({ input, account }, now) {
    const { gate, setup } = await this.tx(async tx => {
      const created = await createGate(tx, input, now, { env: this.env, account });
      await this.audit(tx, now, 'gate.created', { id: created.gate.id, kind: created.gate.kind, ...(created.gate.device_id ? { device_id: created.gate.device_id } : {}), ...(created.gate.url ? { url: created.gate.url } : {}) });
      return created;
    });
    if (gate.state === 'active') await this.announceGate(gate, now);
    return { ...visibleGate(gate), ...(setup ? { setup } : {}) };
  }

  /** Finish setting up a TOTP or security-key gate. */
  async op_activate_gate({ id, body, account }, now) {
    const gate = await this.tx(async tx => {
      const done = await activateGate(tx, id, body, now, { env: this.env, account });
      await this.audit(tx, now, 'gate.activated', { id, kind: done.kind });
      return done;
    });
    await this.announceGate(gate, now);
    return visibleGate(gate);
  }

  /** Gate changes are announced at once, like dba:* issuance (plan §8). */
  async announceGate(gate, now) {
    await this.alert({ title: 'Gate added', body: `“${noticeText(gate.label)}” (${gate.kind}) can now approve or refuse requests for your account.`, path: '#gates', tag: `gate-added-${gate.id}` }, now);
  }

  /** A request as the approval page shows it, with what it needs to offer factors. */
  async op_link_gate_request({ id }, now) {
    const byTimeout = [];
    const view = await this.tx(async tx => {
      byTimeout.length = 0;
      const req = await tx.get(requestKey(id));
      assert(req && requestUntil(req) > now, 'not_found', 'This request is over (answered, or its time ran out)', 404);
      await this.refreshed(tx, req, now, byTimeout);
      return { ...visibleRequest(req, now), factors: await factorView(tx, req, this.env) };
    });
    this.announceTimeouts(byTimeout, now);
    return view;
  }

  /** Delete a gate. Requests waiting on it can no longer pass through it (nothing to time out). */
  async op_delete_gate({ id }, now) {
    const gate = await this.tx(async tx => {
      const found = await tx.get(gateKey(id));
      assert(found, 'not_found', 'Gate not found', 404);
      await tx.delete(gateKey(id));
      await this.audit(tx, now, 'gate.deleted', { id, kind: found.kind });
      return found;
    });
    await this.alert({ title: 'Gate removed', body: `“${noticeText(gate.label)}” no longer approves requests. Grants that named only this gate now deny.`, path: '#gates', tag: `gate-removed-${id}` }, now);
    return { ...visibleGate(gate), deleted: true };
  }

  /**
   * Gate requests still waiting or approved. `device_id` limits the list to requests one of that
   * device's dba-device gates can answer (what the device itself may see).
   */
  async op_list_gate_requests({ device_id, account }, now) {
    const gates = device_id ? new Set([...(await this.storage.list({ prefix: 'gate:' })).values()].filter(g => g.kind === 'dba-device' && g.device_id === device_id).map(g => g.id)) : null;
    const live = await this.liveRequests(now);
    // A device is also told which of its gates may answer each entry still waiting (answer_as),
    // so a CLI or app can answer without reading the gate registry (which needs gates:read).
    if (gates) return { items: live.filter(req => req.entries.some(e => e.gates.some(g => gates.has(g.id)))).map(req => withAnswerAs(visibleRequest(req, now), gates)) };
    // The owner's dashboard links each waiting request that a code or security key answers to its
    // approval page (the owner's session cannot stand in for the factor, plan §4.3).
    return { items: await Promise.all(live.map(async req => ({ ...visibleRequest(req, now), ...(account && !req.outcome && hasFactorGates(req) ? { approve_url: await approvalLink(this.env, account, req) } : {}) }))) };
  }

  async op_get_gate_request({ id, device_id }, now) {
    const byTimeout = [];
    const found = await this.tx(async tx => {
      byTimeout.length = 0;
      const req = await tx.get(requestKey(id));
      assert(req && requestUntil(req) > now, 'not_found', 'Gate request not found or expired', 404);
      let mine = null;
      if (device_id) {
        const ids = req.entries.flatMap(e => e.gates.map(g => g.id)).filter(g => g !== 'owner');
        mine = new Set([...(await loadGates(tx, ids)).values()].filter(g => g.kind === 'dba-device' && g.device_id === device_id).map(g => g.id));
        assert(mine.size || req.device_id === device_id, 'not_found', 'Gate request not found or expired', 404);
      }
      return withAnswerAs(visibleRequest(await this.refreshed(tx, req, now, byTimeout), now), mine);
    });
    this.announceTimeouts(byTimeout, now);
    return found;
  }

  async op_answer_gate_request({ id, entry, gate, decision, answerer, proof, account }, now) {
    const byTimeout = [];
    const req = await this.tx(async tx => {
      byTimeout.length = 0;
      const found = await tx.get(requestKey(id));
      assert(found && requestUntil(found) > now, 'not_found', 'Gate request not found or expired', 404);
      await answerRequest(tx, found, { entry, gate, decision, answerer, proof }, now, { env: this.env, account, failures: this.factorFailures });
      await this.audit(tx, now, decision === 'allow' ? 'gate.approved' : 'gate.refused', { id, gate, cid: found.cid, action: found.action, audience: found.audience, by: answerer.device_id ?? 'session' });
      // This answer may finish a request whose other entries passed by timeout.
      if (found.outcome === 'allow' && found.by_timeout) await this.auditSettled(tx, found, now, byTimeout);
      return found;
    });
    this.announceTimeouts(byTimeout, now);
    return visibleRequest(req, now);
  }
}
