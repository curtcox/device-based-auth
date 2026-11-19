/**
 * Gates (STATUS B7, todo/additional_gates.md): named devices or services that must say yes before
 * devicebasedauth.org lets something happen. This module holds the account's gate registry rows
 * (`gate:<id>`) and the gate request engine (`gatereq:<id>`) the AccountDO runs; it replaces the
 * old step-up rows (a step-up is a request whose only gate is `owner`).
 *
 * Outcomes are decided lazily, whenever a request is read: an entry is settled by its first
 * answer, or at its deadline by its `on_timeout`. No alarm is needed for correctness; the
 * account's alarm only prunes rows whose time is over.
 */
import { assert } from '../utils/errors.js';
import { randomId } from '../utils/ids.js';

/** Gates an account may register (the built-in `owner` gate is not stored). */
export const MAX_GATES = 20;
/** Kinds that can be registered today; G4–G8 add totp, webauthn, webhook, duo and okta-verify. */
export const STORED_KINDS = Object.freeze(['dba-device']);
/** An approval for a grant with gates_reuse_s 0 must be used within this long. */
export const APPROVED_TTL_MS = 5 * 60000;
/** New gate requests per (requesting device, gate) per hour (push-fatigue guard, plan §8). */
export const GATE_REQUESTS_PER_HOUR = 10;
/** Seconds a caller should wait before asking again about a pending request. */
export const RETRY_AFTER_S = 2;
// A gate that can still answer. `failed` and `unpaid` gates were not notified, but their approver
// can still answer from the dashboard; `deleted` and `self` gates never can.
const ANSWERABLE = new Set(['sent', 'failed', 'unpaid']);

export const gateKey = id => `gate:${id}`;
export const requestKey = id => `gatereq:${id}`;

/** The built-in owner gate as listed to clients. */
export const OWNER_GATE = Object.freeze({ id: 'owner', kind: 'owner', label: 'Account owner (signed-in browsers and dashboard devices)', builtin: true });

/** What a client may see of a gate row (gate rows hold no secrets yet; later kinds will). */
export function visibleGate(gate) {
  return { id: gate.id, kind: gate.kind, label: gate.label, ...(gate.device_id ? { device_id: gate.device_id } : {}), created_at: gate.created_at };
}

/** Clean a request to create a gate (validated again in the DO against its devices). */
export function cleanGateInput(body) {
  assert(body && typeof body === 'object', 'invalid_gate', 'Send a JSON object');
  assert(STORED_KINDS.includes(body.kind), 'gate_kind_not_available', `kind must be one of ${STORED_KINDS.join(', ')} (owner is built in; TOTP, security keys, webhooks, Duo and Okta Verify come later)`);
  const label = typeof body.label === 'string' ? body.label.trim().slice(0, 80) : '';
  assert(label.length > 0, 'invalid_gate', 'label is required (1–80 characters)');
  assert(typeof body.device_id === 'string' && /^dev_[A-Za-z0-9]{8,64}$/.test(body.device_id), 'invalid_gate', 'device_id must name one of your devices');
  return { kind: body.kind, label, device_id: body.device_id };
}

/** Create a gate row. */
export async function createGate(tx, input, now) {
  const existing = await tx.list({ prefix: 'gate:' });
  assert(existing.size < MAX_GATES, 'too_many_gates', `An account can have at most ${MAX_GATES} gates`, 409);
  const device = await tx.get(`device:${input.device_id}`);
  assert(device && !device.revoked_at, 'unknown_device', 'device_id must name one of your devices that is not revoked', 400);
  const gate = { id: randomId('gate', 16), kind: input.kind, label: input.label, device_id: input.device_id, created_at: now };
  await tx.put(gateKey(gate.id), gate);
  return gate;
}

/** Gate rows for the ids named (owner is built in). */
export async function loadGates(tx, ids) {
  const gates = new Map();
  for (const id of new Set(ids)) {
    if (id === 'owner') { gates.set(id, OWNER_GATE); continue; }
    const gate = await tx.get(gateKey(id));
    if (gate) gates.set(id, gate);
  }
  return gates;
}

/**
 * At issuance: every gate a grant names must exist, and no dba-device gate may be the device the
 * credential is for (it would approve its own requests).
 */
export async function checkGatesForIssue(tx, grants, deviceId) {
  const ids = (grants || []).flatMap(g => Array.isArray(g?.require?.gates) ? g.require.gates.flatMap(e => e.any) : []);
  if (!ids.length) return;
  const gates = await loadGates(tx, ids);
  for (const id of new Set(ids)) {
    const gate = gates.get(id);
    assert(gate, 'unknown_gate', `Gate ${id} does not exist in this account; create it first (GET /api/v1/gates lists them)`, 400);
    assert(!(gate.kind === 'dba-device' && gate.device_id === deviceId), 'self_gate', `Gate ${id} is the device this credential is for; a device cannot approve its own requests`, 400);
  }
}

/** Requests are matched to the grant's gates exactly: a different gate list needs its own approval. */
export function gateSignature(candidate) {
  return JSON.stringify({ gates: candidate.gates, fail_open: candidate.fail_open !== false });
}

/** How one entry stands now: { outcome: 'allow' | 'deny', by } or null while it waits. */
export function entryOutcome(entry, now, failOpen = true) {
  if (entry.answer) return { outcome: entry.answer.decision, by: 'answer' };
  // No gate left to answer (deleted, or the requesting device itself): nothing to wait for, so it
  // denies at once even when it would allow on timeout (plan §2).
  if (!entry.gates.some(g => ANSWERABLE.has(g.state))) return { outcome: 'deny', by: 'no_gate' };
  if (now < entry.deadline) return null;
  if (entry.on_timeout === 'allow') return failOpen ? { outcome: 'allow', by: 'timeout' } : { outcome: 'deny', by: 'by_timeout_refused' };
  return { outcome: 'deny', by: 'timeout' };
}

/**
 * When a request row stops mattering: an unused approval's end; a denial's last deadline (a
 * denial stands that long); and for one still unsettled, a while after its last deadline, so the
 * site's next retry finds it and settles it (an allow by timeout is only seen that way).
 */
export function requestUntil(req) {
  if (req.outcome === 'allow') return req.approved_until;
  const last = Math.max(...req.entries.map(e => e.deadline));
  return req.outcome ? last : last + APPROVED_TTL_MS;
}

/**
 * Bring a request up to date: mark gates deleted since it was made, and settle it when every
 * entry allows or any entry denies. Returns { changed, settled } (settled: it settled just now).
 */
export async function refreshRequest(tx, req, now) {
  if (req.outcome) return { changed: false, settled: false };
  let changed = false;
  const gates = await loadGates(tx, req.entries.flatMap(e => e.gates.map(g => g.id)));
  for (const entry of req.entries) for (const g of entry.gates) {
    if (!entry.answer && g.state !== 'deleted' && !gates.has(g.id)) { g.state = 'deleted'; changed = true; }
  }
  const outcomes = req.entries.map(e => entryOutcome(e, now, req.fail_open));
  for (const [i, o] of outcomes.entries()) if (o && !req.entries[i].outcome) { req.entries[i].outcome = o.outcome; req.entries[i].by = o.by; changed = true; }
  const denied = outcomes.some(o => o?.outcome === 'deny');
  const allowed = outcomes.every(o => o?.outcome === 'allow');
  if (!denied && !allowed) return { changed, settled: false };
  req.outcome = denied ? 'deny' : 'allow';
  req.settled_at = now;
  req.by_timeout = req.entries.some(e => e.by === 'timeout');
  if (allowed) req.approved_until = now + (req.reuse_s ? req.reuse_s * 1000 : APPROVED_TTL_MS);
  return { changed: true, settled: true };
}

/** The live request for this subject and gate list, if any. */
export async function findRequest(tx, { cid, action, resource, audience, signature }, now) {
  for (const req of (await tx.list({ prefix: 'gatereq:' })).values()) {
    if (req.purpose === 'authorize' && req.cid === cid && req.action === action && (req.resource ?? null) === (resource ?? null) && req.audience === audience && req.signature === signature && requestUntil(req) > now) return req;
  }
  return null;
}

/**
 * Build a new request for a candidate grant's gates. `delivery(gate)` says whether DBA could
 * reach the gate ('sent' or 'failed'); `paid` false marks every gate 'unpaid' (DBA sends nothing,
 * plan §2: an entry then waits for its timeout).
 */
export function newRequest({ cred, cid, action, resource, audience, candidate, gates, now, delivery }) {
  const entries = candidate.gates.map(entry => ({
    any: entry.any, timeout_s: entry.timeout_s, on_timeout: entry.on_timeout, deadline: now + entry.timeout_s * 1000,
    gates: entry.any.map(id => {
      const gate = gates.get(id);
      if (!gate) return { id, kind: null, state: 'deleted' };
      if (gate.kind === 'dba-device' && gate.device_id === cred.device_id) return { id, kind: gate.kind, state: 'self' };
      return { id, kind: gate.kind, state: delivery(gate) };
    }),
    answer: null, outcome: null
  }));
  return {
    id: randomId('gtr', 16), purpose: 'authorize', step_up: !!candidate.step_up, cid, device_id: cred.device_id, device_name: cred.device?.name ?? null,
    action, resource: resource ?? null, audience, signature: gateSignature(candidate), fail_open: candidate.fail_open !== false,
    reuse_s: candidate.gates_reuse_s || 0, entries, number: String(10 + Math.floor(Math.random() * 90)), created_at: now, outcome: null
  };
}

/** The distinct gates DBA contacts for a request (each is charged, plan §9). */
export function contactedGates(req) {
  return [...new Set(req.entries.flatMap(e => e.gates.filter(g => g.state === 'sent' || g.state === 'failed').map(g => g.id)))];
}

/** How a settled allow passed, for decisions and tokens: [{ kind, by }] per entry. */
export function howPassed(req) {
  return req.entries.map(e => ({ kind: e.answer ? (e.gates.find(g => g.id === e.answer.gate)?.kind ?? 'owner') : null, by: e.by === 'timeout' ? 'timeout' : 'answer' }));
}

/** A request as clients see it. */
export function visibleRequest(req, now) {
  return {
    id: req.id, purpose: req.purpose, cid: req.cid, device_id: req.device_id, device_name: req.device_name,
    audience: req.audience, action: req.action, resource: req.resource, number: req.number, created_at: req.created_at,
    status: req.outcome === 'allow' ? 'allowed' : req.outcome === 'deny' ? 'denied' : 'pending',
    by_timeout: req.by_timeout ?? false,
    entries: req.entries.map(e => ({
      any: e.any, timeout_s: e.timeout_s, on_timeout: e.on_timeout, deadline: e.deadline, expires_in: Math.max(0, Math.ceil((e.deadline - now) / 1000)),
      gates: e.gates.map(g => ({ id: g.id, kind: g.kind, delivery: g.state })), outcome: e.outcome, by: e.by ?? null,
      answer: e.answer ? { gate: e.answer.gate, decision: e.answer.decision, at: e.answer.at } : null
    }))
  };
}

/**
 * Record one answer. `answerer` is { kind: 'owner' | 'device', device_id } as authenticated by
 * the Worker. Returns the updated request. The first answer settles an entry; a request that has
 * settled, or an entry past its deadline, takes no more answers.
 */
export async function answerRequest(tx, req, { entry: entryIndex, gate: gateId, decision, answerer }, now) {
  assert(decision === 'allow' || decision === 'deny', 'invalid_answer', 'decision must be "allow" or "deny"');
  await refreshRequest(tx, req, now);
  const named = req.entries.filter((e, i) => (entryIndex === undefined || entryIndex === i) && e.gates.some(g => g.id === gateId && ANSWERABLE.has(g.state)));
  assert(named.length, 'not_a_gate', `Gate ${gateId} cannot answer ${entryIndex === undefined ? 'this request' : `entry ${entryIndex}`}`, 403);
  const e = named.find(x => !x.answer && !x.outcome && now < x.deadline);
  assert(e || !named.some(x => !x.answer && now >= x.deadline), 'expired', 'This request is no longer waiting for an answer', 410);
  assert(e && !req.outcome, 'request_settled', `This request has already been ${req.outcome === 'allow' ? 'allowed' : 'denied'}`, 409);
  const gate = gateId === 'owner' ? OWNER_GATE : await tx.get(gateKey(gateId));
  assert(gate, 'not_a_gate', `Gate ${gateId} no longer exists`, 403);
  if (gate.kind === 'owner') {
    assert(answerer.kind === 'owner', 'not_the_gate', 'Only the account owner (a signed-in browser or dashboard device) answers for the owner gate', 403);
  } else if (gate.kind === 'dba-device') {
    assert(answerer.kind === 'device' && answerer.device_id === gate.device_id, 'not_the_gate', `Only device ${gate.device_id} answers for gate ${gate.id}`, 403);
  }
  // A device that asked may refuse its own request but never approve it.
  assert(decision === 'deny' || !answerer.device_id || answerer.device_id !== req.device_id, 'self_approval', 'A device cannot approve its own request; approve it from another device or a signed-in browser', 403);
  e.answer = { gate: gateId, decision, at: now, by: answerer.device_id ?? 'session' };
  await refreshRequest(tx, req, now);
  await tx.put(requestKey(req.id), req);
  return req;
}
