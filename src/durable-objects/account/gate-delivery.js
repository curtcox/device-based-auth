import { assert } from '../../utils/errors.js';
import { startPush, pollPush, POLL_INTERVAL_MS, MAX_POLLS } from '../../services/vendors.js';
import { unseal } from '../../services/sealing.js';
import { gateKey, postGateEvent, signGateEvent, verifyGateAnswer } from '../gates.js';
import { answerRequest, callbackUrl, requestKey, requestUntil, vendorTargets, visibleRequest, webhookTargets } from '../gate-requests.js';

/**
 * Reaching gates over the network: Duo and Okta Verify pushes (started, then polled from the
 * alarm), webhook gates' signed requests, and their late answers. Mixed into AccountDO
 * (account-do.js): `this` is the account's Durable Object.
 */
export class AccountGateDelivery {
  /** Start what reaches gates over the network, after the response: webhooks and vendor pushes. */
  deliverAsync(req, account) {
    if (webhookTargets(req).length) this.background(this.deliverWebhooks(req.id, account));
    if (vendorTargets(req).length) this.background(this.startPushes(req.id, account));
  }

  /**
   * Start Duo / Okta Verify pushes for a new request, record what to poll, and wake the alarm to
   * poll (plan §4.4). A push that cannot be started marks the gate "failed": its entry waits for
   * its timeout.
   */
  async startPushes(id, account) {
    const req = await this.storage.get(requestKey(id));
    if (!req) return;
    const fetcher = this.env.VENDOR_FETCH || fetch;
    const started = await Promise.all(vendorTargets(req).map(async ({ entry, gate: gateId }) => {
      const gate = await this.storage.get(gateKey(gateId));
      if (!gate) return null;
      const secret = new TextDecoder().decode(await unseal(this.env, { account, gateId }, gate.secret));
      const what = { action: req.action, site: req.audience, device: req.device_name || 'a device', ...(req.resource ? { resource: req.resource } : {}) };
      return { entry, gate: gateId, result: await startPush(gate, secret, what, { fetcher }) };
    }));
    const now = Date.now();
    await this.tx(async tx => {
      const fresh = await tx.get(requestKey(id));
      if (!fresh) return;
      for (const s of started.filter(Boolean)) {
        const g = fresh.entries[s.entry].gates.find(x => x.id === s.gate);
        if (!g || g.state !== 'sent') continue;
        if (s.result.token) g.push = { ...s.result.token, started_at: now }; else { g.state = 'failed'; g.reason = s.result.failed; }
      }
      await tx.put(requestKey(id), fresh);
      await this.scheduleWake(tx, now + POLL_INTERVAL_MS);
    });
  }

  /**
   * Poll started pushes (from the alarm): each at most every POLL_INTERVAL_MS and MAX_POLLS times
   * (by time since it started), until answered or past its entry's deadline. Returns the next time
   * a poll is due, or null.
   */
  async pollPushes(now) {
    const fetcher = this.env.VENDOR_FETCH || fetch;
    const account = (await this.storage.get('profile'))?.account;
    let next = null;
    const answers = [];
    for (const req of (await this.storage.list({ prefix: 'gatereq:' })).values()) {
      if (req.outcome) continue;
      for (const [i, e] of req.entries.entries()) {
        if (e.answer || e.outcome || now >= e.deadline) continue;
        for (const g of e.gates) {
          if (!g.push || g.state !== 'sent') continue;
          const window = g.push.started_at + MAX_POLLS * POLL_INTERVAL_MS;
          const key = `${req.id}:${i}:${g.id}`;
          if (now > window) continue;
          if ((this.vendorPolls.get(key) ?? 0) + POLL_INTERVAL_MS > now) { next = Math.min(next ?? Infinity, (this.vendorPolls.get(key) ?? 0) + POLL_INTERVAL_MS); continue; }
          this.vendorPolls.set(key, now);
          const gate = await this.storage.get(gateKey(g.id));
          if (!gate || !account) continue;
          const secret = new TextDecoder().decode(await unseal(this.env, { account, gateId: g.id }, gate.secret));
          const decision = await pollPush(gate, secret, g.push, { fetcher, now });
          if (decision) answers.push({ id: req.id, entry: i, gate: g.id, decision });
          else if (now + POLL_INTERVAL_MS <= Math.min(window, e.deadline)) next = Math.min(next ?? Infinity, now + POLL_INTERVAL_MS);
        }
      }
    }
    for (const [key, at] of this.vendorPolls) if (at < now - 3600000) this.vendorPolls.delete(key);
    if (answers.length) {
      const byTimeout = [];
      await this.tx(async tx => {
        byTimeout.length = 0;
        for (const a of answers) {
          const req = await tx.get(requestKey(a.id));
          if (!req) continue;
          try {
            await answerRequest(tx, req, { entry: a.entry, gate: a.gate, decision: a.decision, answerer: { kind: 'vendor', gate: a.gate } }, now);
            await this.audit(tx, now, a.decision === 'allow' ? 'gate.approved' : 'gate.refused', { id: a.id, gate: a.gate, cid: req.cid, action: req.action, audience: req.audience, by: 'vendor' });
            if (req.outcome === 'allow' && req.by_timeout) await this.auditSettled(tx, req, now, byTimeout);
          } catch { /* settled meanwhile */ }
        }
      });
      this.announceTimeouts(byTimeout, now);
    }
    return next === Infinity ? null : next;
  }

  /**
   * Post a new request to its webhook gates (after the decision has answered gate_pending). A
   * service that answers at once settles its entry; one that cannot be reached is marked
   * "failed" and its entry waits for its timeout (plan §2).
   */
  async deliverWebhooks(id, account) {
    const req = await this.storage.get(requestKey(id));
    if (!req) return;
    const callback = await callbackUrl(this.env, account, req);
    const results = await Promise.all(webhookTargets(req).map(async ({ entry, gate: gateId }) => {
      const gate = await this.storage.get(gateKey(gateId));
      if (!gate) return null;
      const jws = await signGateEvent(this.env, { req, entryIndex: entry, gate, account, callback });
      return { entry, gate: gateId, result: await postGateEvent(this.env, gate.url, jws) };
    }));
    const now = Date.now();
    const byTimeout = [];
    await this.tx(async tx => {
      byTimeout.length = 0;
      const fresh = await tx.get(requestKey(id));
      if (!fresh) return;
      for (const r of results.filter(Boolean)) {
        if (!r.result.delivered) {
          const g = fresh.entries[r.entry].gates.find(x => x.id === r.gate);
          if (g && g.state === 'sent') g.state = 'failed';
        } else if (r.result.decision) {
          try {
            await answerRequest(tx, fresh, { entry: r.entry, gate: r.gate, decision: r.result.decision, answerer: { kind: 'webhook', gate: r.gate } }, now);
            await this.audit(tx, now, r.result.decision === 'allow' ? 'gate.approved' : 'gate.refused', { id, gate: r.gate, cid: fresh.cid, action: fresh.action, audience: fresh.audience, by: 'webhook' });
          } catch { /* settled or past its deadline meanwhile */ }
        }
      }
      await this.refreshed(tx, fresh, now, byTimeout);
      await tx.put(requestKey(id), fresh);
    });
    this.announceTimeouts(byTimeout, now);
  }

  /** A webhook gate's late answer (POST …/gate-links/<link>/callback). */
  async op_webhook_gate_answer({ id, jws }, now) {
    const byTimeout = [];
    const req = await this.tx(async tx => {
      byTimeout.length = 0;
      const found = await tx.get(requestKey(id));
      assert(found && requestUntil(found) > now, 'not_found', 'Gate request not found or expired', 404);
      const answer = await verifyGateAnswer(tx, jws, id, now);
      await answerRequest(tx, found, { ...answer, answerer: { kind: 'webhook', gate: answer.gate } }, now);
      await this.audit(tx, now, answer.decision === 'allow' ? 'gate.approved' : 'gate.refused', { id, gate: answer.gate, cid: found.cid, action: found.action, audience: found.audience, by: 'webhook' });
      if (found.outcome === 'allow' && found.by_timeout) await this.auditSettled(tx, found, now, byTimeout);
      return found;
    });
    this.announceTimeouts(byTimeout, now);
    return { id, status: visibleRequest(req, now).status };
  }
}
