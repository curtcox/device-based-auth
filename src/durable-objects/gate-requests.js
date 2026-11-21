/**
 * The gate request engine (STATUS B7, done/additional_gates.md): one `gatereq:<id>` row per thing
 * waiting for gates to say yes (an online decision, a sign-in, a confirmation, a settings change),
 * its entries, answers and approval links. The gate registry it reads is in gates.js.
 *
 * Outcomes are decided lazily, whenever a request is read: an entry is settled by its first
 * answer, or at its deadline by its `on_timeout`. No alarm is needed for correctness; the
 * account's alarm only prunes rows whose time is over.
 */
import { assert, ApiError } from '../utils/errors.js';
import { randomId } from '../utils/ids.js';
import { b64u } from '../../packages/verify/src/jose.js';
import { signToken } from '../auth/tokens.js';
import { unseal } from '../services/sealing.js';
import { matchStep } from '../services/totp.js';
import { verifyAssertion, answerChallenge, rpIdFor, WebAuthnError } from '../services/webauthn.js';
import { OWNER_GATE, VENDOR_KINDS, FACTOR_KINDS, gateKey, gateActive, loadGates } from './gates.js';

/** Wrong codes or assertions per gate per 15 minutes before it refuses for a while (guessing). */
export const FACTOR_FAILURES = 5;
const LINK_PREFIX = 'dbag_';
/** An approval for a grant with gates_reuse_s 0 must be used within this long. */
export const APPROVED_TTL_MS = 5 * 60000;
/** New gate requests per (requesting device, gate) per hour (push-fatigue guard, plan §8). */
export const GATE_REQUESTS_PER_HOUR = 10;
/** Seconds a caller should wait before asking again about a pending request. */
export const RETRY_AFTER_S = 2;
// A gate that can still answer. `failed` and `unpaid` gates were not notified, but their approver
// can still answer from the dashboard; `deleted` and `self` gates never can.
const ANSWERABLE = new Set(['sent', 'failed', 'unpaid']);

export const requestKey = id => `gatereq:${id}`;

/** The signed link token for one request (HMAC; it routes itself to the account). */
export async function linkToken(env, account, req) {
  const exp = Math.ceil(Math.max(...req.entries.map(e => e.deadline)) / 1000) + 60;
  return signToken(LINK_PREFIX, { a: account, r: req.id, exp }, env.TOKEN_SIGNING_KEY);
}

/** A link to the approval page for one request. */
export async function approvalLink(env, account, req) {
  return `${env.APP_ORIGIN}/gate.html#${await linkToken(env, account, req)}`;
}

/** Where a webhook gate sends a late answer for one request. */
export async function callbackUrl(env, account, req) {
  return `${env.APP_ORIGIN}/api/v1/gate-links/${await linkToken(env, account, req)}/callback`;
}

/** Vendor gates DBA has to start a push for. */
export const vendorTargets = req => req.entries.flatMap((e, i) => e.gates.filter(g => VENDOR_KINDS.includes(g.kind) && g.state === 'sent' && !g.push).map(g => ({ entry: i, gate: g.id })));

/** Webhook gates DBA has to post this request to. */
export const webhookTargets = req => req.entries.flatMap((e, i) => e.gates.filter(g => g.kind === 'webhook' && g.state === 'sent').map(g => ({ entry: i, gate: g.id })));

/** Does a request have gates answered on the approval page? */
export const hasFactorGates = req => req.entries.some(e => e.gates.some(g => FACTOR_KINDS.includes(g.kind) && g.state !== 'deleted'));

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

/**
 * What makes two requests the same thing to approve: an online decision's credential, action,
 * resource and audience, or a sign-in's site and requester, plus the exact gate list.
 */
export function requestKeyFor({ purpose = 'authorize', cid, action, resource, audience, requester, signature }) {
  return purpose === 'sign_in' || purpose === 'dashboard' || purpose === 'settings'
    ? [purpose, audience, requester, signature].join('\n')
    : ['authorize', cid, action, resource ?? '', audience, signature].join('\n');
}

/**
 * Is `next` at least as strict as `current` (both sign-in gate entry lists, or null)? Every
 * current entry must be matched by a next entry whose gates are among its gates (fewer gates that
 * may answer is stricter) and that does not allow on timeout where the current one denies.
 * Anything else loosens the list, which needs the current gates' approval (plan §3.3).

/** The live request for this subject and gate list, if any. */
export async function findRequest(tx, subject, now) {
  const key = requestKeyFor(subject);
  for (const req of (await tx.list({ prefix: 'gatereq:' })).values()) {
    if (req.key === key && requestUntil(req) > now) return req;
  }
  return null;
}

/**
 * Build a new request for a candidate grant's gates. `delivery(gate)` says whether DBA could
 * reach the gate ('sent' or 'failed'); `paid` false marks every gate 'unpaid' (DBA sends nothing,
 * plan §2: an entry then waits for its timeout).
 */
export function newRequest({ cred, purpose = 'authorize', cid, action, resource, audience, requester, candidate, gates, now, delivery }) {
  const entries = candidate.gates.map(entry => ({
    any: entry.any, timeout_s: entry.timeout_s, on_timeout: entry.on_timeout, deadline: now + entry.timeout_s * 1000,
    gates: entry.any.map(id => {
      const gate = gates.get(id);
      if (!gateActive(gate)) return { id, kind: gate?.kind ?? null, state: 'deleted' };
      if (gate.kind === 'dba-device' && gate.device_id === cred.device_id) return { id, kind: gate.kind, state: 'self' };
      return { id, kind: gate.kind, state: delivery(gate) };
    }),
    answer: null, outcome: null
  }));
  return {
    id: randomId('gtr', 16), purpose, step_up: !!candidate.step_up, cid: cid ?? null, device_id: cred.device_id ?? null, device_name: cred.device?.name ?? null,
    action, resource: resource ?? null, audience, signature: gateSignature(candidate), fail_open: candidate.fail_open !== false,
    key: requestKeyFor({ purpose, cid, action, resource, audience, requester, signature: gateSignature(candidate) }),
    reuse_s: candidate.gates_reuse_s || 0, entries, number: String(10 + Math.floor(Math.random() * 90)), created_at: now, outcome: null,
    // Security-key answers sign a challenge made from the request, entry, decision and this salt.
    salt: b64u(crypto.getRandomValues(new Uint8Array(16)))
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
    audience: req.audience, action: req.action, resource: req.resource, created_at: req.created_at,
    // A sign-in's number is shown only where the sign-in waits; approvers type it (number matching).
    ...(req.purpose === 'sign_in' || req.purpose === 'dashboard' ? {} : { number: req.number }),
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
 * Add answer_as to a request shown to a device: per entry still waiting, the device's own gates
 * that may answer it ([{ entry, gate }]). `mine` is the set of the device's gate ids (null: the
 * owner, who is not given it).
 */
export function withAnswerAs(visible, mine) {
  if (!mine) return visible;
  const answerAs = visible.status !== 'pending' ? [] : visible.entries.flatMap((e, entry) => e.answer || e.outcome || e.expires_in <= 0 ? [] : e.gates.filter(g => mine.has(g.id) && ANSWERABLE.has(g.delivery)).map(g => ({ entry, gate: g.id })));
  return { ...visible, answer_as: answerAs };
}

/**
 * Record one answer. `answerer` is { kind: 'owner' | 'device', device_id } as authenticated by
 * the Worker. Returns the updated request. The first answer settles an entry; a request that has
 * settled, or an entry past its deadline, takes no more answers.
 */
export async function answerRequest(tx, req, { entry: entryIndex, gate: gateId, decision, answerer, proof }, now, factors = {}) {
  assert(decision === 'allow' || decision === 'deny', 'invalid_answer', 'decision must be "allow" or "deny"');
  await refreshRequest(tx, req, now);
  const named = req.entries.filter((e, i) => (entryIndex === undefined || entryIndex === i) && e.gates.some(g => g.id === gateId && ANSWERABLE.has(g.state)));
  assert(named.length, 'not_a_gate', `Gate ${gateId} cannot answer ${entryIndex === undefined ? 'this request' : `entry ${entryIndex}`}`, 403);
  const e = named.find(x => !x.answer && !x.outcome && now < x.deadline);
  const index = req.entries.indexOf(e);
  assert(e || !named.some(x => !x.answer && now >= x.deadline), 'expired', 'This request is no longer waiting for an answer', 410);
  assert(e && !req.outcome, 'request_settled', `This request has already been ${req.outcome === 'allow' ? 'allowed' : 'denied'}`, 409);
  const gate = gateId === 'owner' ? OWNER_GATE : await tx.get(gateKey(gateId));
  assert(gate, 'not_a_gate', `Gate ${gateId} no longer exists`, 403);
  if (gate.kind === 'owner') {
    assert(answerer.kind === 'owner', 'not_the_gate', 'Only the account owner (a signed-in browser or dashboard device) answers for the owner gate', 403);
  } else if (gate.kind === 'dba-device') {
    assert(answerer.kind === 'device' && answerer.device_id === gate.device_id, 'not_the_gate', `Only device ${gate.device_id} answers for gate ${gate.id}`, 403);
  } else if (VENDOR_KINDS.includes(gate.kind)) {
    assert(answerer.kind === 'vendor' && answerer.gate === gate.id, 'not_the_gate', `Gate ${gate.id} is answered by ${gate.kind === 'duo' ? 'Duo' : 'Okta Verify'}, as DBA polls it`, 403);
  } else if (gate.kind === 'webhook') {
    assert(answerer.kind === 'webhook' && answerer.gate === gate.id, 'not_the_gate', `Only the service behind gate ${gate.id} answers for it`, 403);
  } else if (FACTOR_KINDS.includes(gate.kind)) {
    // The factor is the authentication: whoever holds the authenticator app or the security key
    // answers, signed in or not (plan §4.3). Each wrong try counts against the gate.
    await checkFactor(tx, gate, req, index, decision, proof, now, factors);
  }
  if (req.purpose === 'sign_in' || req.purpose === 'dashboard') {
    // Allow-on-timeout entries are never answered by the person signing in (plan §2): there,
    // silence is theirs to choose, so only another approver's answer counts.
    assert(!(answerer.kind === 'owner' && e.on_timeout === 'allow'), 'not_inline', 'This approval waits for someone else (it allows on timeout); answer it from the approval link or the approving device', 403);
    // Number matching against push fatigue: an approver elsewhere types the number the sign-in page shows.
    assert(decision === 'deny' || answerer.kind === 'owner' || answerer.kind === 'webhook' || String(proof?.number ?? '') === req.number, 'wrong_number', 'Enter the two-digit number shown on the sign-in page', 403);
  }
  // A device that asked may refuse its own request but never approve it.
  assert(decision === 'deny' || !answerer.device_id || answerer.device_id !== req.device_id, 'self_approval', 'A device cannot approve its own request; approve it from another device or a signed-in browser', 403);
  e.answer = { gate: gateId, decision, at: now, by: answerer.device_id ?? 'session' };
  await refreshRequest(tx, req, now);
  await tx.put(requestKey(req.id), req);
  return req;
}

/** Check a TOTP code or a security-key assertion for one answer, and remember what it used. */
async function checkFactor(tx, gate, req, index, decision, proof, now, { env, account, failures }) {
  const key = `${gate.id}`;
  const recent = (failures?.get(key) || []).filter(at => at > now - 15 * 60000);
  assert(recent.length < FACTOR_FAILURES, 'too_many_attempts', 'Too many wrong answers for this gate; wait 15 minutes', 429);
  const wrong = (code, message) => { failures?.set(key, [...recent, now]); throw new ApiError(403, code, message); };
  if (gate.kind === 'totp') {
    // Each step is accepted once per gate: a code seen once (by a shoulder, a proxy) is spent.
    const step = await matchStep(await unseal(env, { account, gateId: gate.id }, gate.secret), String(proof?.totp?.code ?? ''), now, gate.last_step ?? -1);
    if (step === null) wrong('invalid_code', 'That code is not right, or was already used');
    gate.last_step = step;
  } else {
    const challenge = await answerChallenge({ requestId: req.id, entry: index, decision, salt: req.salt });
    try {
      const result = await verifyAssertion(proof?.webauthn, { challenge, origin: env.APP_ORIGIN, rpId: rpIdFor(env.APP_ORIGIN), credential: gate.credential, requireUV: gate.user_verification === 'required' });
      gate.credential.sign_count = result.sign_count;
    } catch (error) { if (error instanceof WebAuthnError) wrong('invalid_webauthn', error.message); throw error; }
  }
  await tx.put(gateKey(gate.id), gate);
}

/** What the approval page needs to offer factors: per entry, its security keys and challenge salt. */
export async function factorView(tx, req, env) {
  const gates = await loadGates(tx, req.entries.flatMap(e => e.gates.map(g => g.id)));
  return {
    rp_id: rpIdFor(env.APP_ORIGIN), salt: req.salt,
    entries: req.entries.map(e => ({
      gates: e.gates.filter(g => g.state !== 'deleted').map(g => {
        const gate = gates.get(g.id);
        return { id: g.id, kind: g.kind, label: gate?.label ?? (g.id === 'owner' ? 'Account owner' : null), ...(gate?.kind === 'webauthn' && gate.credential ? { credential_id: gate.credential.credential_id, user_verification: gate.user_verification } : {}) };
      })
    }))
  };
}
