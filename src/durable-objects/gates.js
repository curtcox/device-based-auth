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
import { assert, ApiError } from '../utils/errors.js';
import { randomId } from '../utils/ids.js';
import { b64u } from '../../packages/verify/src/jose.js';
import { signToken } from '../auth/tokens.js';
import { seal, unseal } from '../services/sealing.js';
import { matchStep, otpauthUri, base32 } from '../services/totp.js';
import { creationOptions, verifyRegistration, verifyAssertion, answerChallenge, rpIdFor, WebAuthnError } from '../services/webauthn.js';
import { publicJwk, verifyJws, decodeJws, signJws } from '../../packages/verify/src/jose.js';
import { activeSigner, issuerName } from '../services/issuer.js';
import { cleanVendorInput } from '../services/vendors.js';

/** Gates an account may register (the built-in `owner` gate is not stored). */
export const MAX_GATES = 20;
/** Kinds that can be registered today; G5–G8 add webhook, duo and okta-verify. */
export const STORED_KINDS = Object.freeze(['dba-device', 'totp', 'webauthn', 'webhook', 'duo', 'okta-verify']);
/** Push MFA vendors: DBA starts a push and polls for the answer. */
export const VENDOR_KINDS = Object.freeze(['duo', 'okta-verify']);
/** typ of the signed gate request DBA posts to a webhook gate (spec/events.md §6). */
export const GATE_EVENT_TYP = 'dba-gate+jwt';
/** typ of a webhook gate's signed late answer. */
export const GATE_ANSWER_TYP = 'dba-gate-answer+jwt';
/** How long DBA waits for a webhook gate's response (an unanswered POST is "failed"). */
export const WEBHOOK_TIMEOUT_MS = 10000;
/** Kinds answered with a factor (a code, a security key) on the approval page, without a session. */
export const FACTOR_KINDS = Object.freeze(['totp', 'webauthn']);
/** A TOTP or security-key registration must be finished within this long. */
export const SETUP_TTL_MS = 15 * 60000;
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

/** Authentication context classes for sign-ins (todo/additional_gates.md §5.1). */
export const ACR = Object.freeze({ gated: 'urn:devicebasedauth.org:acr:gated', gatedTimeout: 'urn:devicebasedauth.org:acr:gated-timeout', session: 'urn:devicebasedauth.org:acr:session' });
// RFC 8176 authentication method references for each kind of gate that answered.
const AMR_FOR_KIND = { totp: 'otp', webauthn: 'hwk', 'dba-device': 'swk', webhook: 'mfa' };

/**
 * What a passed sign-in adds to the ID token: amr values for the gates that answered ("mfa" when
 * any did), the acr (gated, or gated-timeout when an entry passed by silence) and dba_gates.
 */
export function signInClaims(gates, byTimeout) {
  const answered = gates.filter(g => g.by === 'answer');
  return { amr: [...new Set([...answered.map(g => AMR_FOR_KIND[g.kind]).filter(Boolean), ...(answered.length ? ['mfa'] : [])])], acr: byTimeout ? ACR.gatedTimeout : ACR.gated, dba_gates: gates };
}

/** Does an acr meet the site's acr_values (none asked: anything does)? gated meets gated-timeout too. */
export function meetsAcr(acr, wanted) {
  return !wanted.length || wanted.includes(acr) || wanted.includes(ACR.session) || (acr === ACR.gated && wanted.includes(ACR.gatedTimeout));
}

export const gateKey = id => `gate:${id}`;
export const requestKey = id => `gatereq:${id}`;

/** The built-in owner gate as listed to clients. */
export const OWNER_GATE = Object.freeze({ id: 'owner', kind: 'owner', label: 'Account owner (signed-in browsers and dashboard devices)', builtin: true });

/** What a client may see of a gate row: never a sealed secret or a public key's material. */
export function visibleGate(gate) {
  return {
    id: gate.id, kind: gate.kind, label: gate.label, state: gate.state ?? 'active',
    ...(gate.device_id ? { device_id: gate.device_id } : {}),
    ...(gate.kind === 'webauthn' ? { user_verification: gate.user_verification } : {}),
    ...(gate.kind === 'webhook' ? { url: gate.url, public_jwk: gate.public_jwk } : {}),
    ...(gate.kind === 'duo' ? { api_host: gate.api_host, integration_key: gate.integration_key, username: gate.username } : {}),
    ...(gate.kind === 'okta-verify' ? { org_url: gate.org_url, user_id: gate.user_id, factor_id: gate.factor_id } : {}),
    created_at: gate.created_at, ...(gate.activated_at ? { activated_at: gate.activated_at } : {})
  };
}

/**
 * A webhook gate's URL: https, a public host name (no IP literals, no localhost), the default
 * port, no credentials or fragment. Local development also allows http on localhost.
 */
export function cleanGateWebhookUrl(value, env = {}) {
  let u; try { u = new URL(String(value ?? '')); } catch { assert(false, 'invalid_gate', 'url must be the https URL of your approval service'); }
  const local = env.ENVIRONMENT === 'local' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname.endsWith('.localhost'));
  assert(u.protocol === 'https:' || (local && u.protocol === 'http:'), 'invalid_gate', 'url must use https');
  assert(!u.username && !u.password && !u.hash, 'invalid_gate', 'url cannot contain credentials or a fragment');
  assert(local || (!u.port && u.hostname.includes('.') && !/^[\d.]+$/.test(u.hostname) && !u.hostname.startsWith('[') && !u.hostname.endsWith('.localhost') && !u.hostname.endsWith('.local') && !u.hostname.endsWith('.internal')), 'invalid_gate', 'url must name a public host by its domain name, on the default port');
  assert(u.toString().length <= 2048, 'invalid_gate', 'url is too long');
  return u.toString();
}

/** Usable in grants and requests: registered, and (for factors) set up. */
export const gateActive = gate => !!gate && (gate.state ?? 'active') === 'active';

/** Clean a request to create a gate (validated again in the DO against its devices). */
export function cleanGateInput(body, env = {}) {
  assert(body && typeof body === 'object', 'invalid_gate', 'Send a JSON object');
  assert(STORED_KINDS.includes(body.kind), 'gate_kind_not_available', `kind must be one of ${STORED_KINDS.join(', ')} (owner is built in; TOTP, security keys, webhooks, Duo and Okta Verify come later)`);
  const label = typeof body.label === 'string' ? body.label.replace(/[\p{Cc}\p{Cf}]/gu, '').trim().slice(0, 80) : '';
  assert(label.length > 0, 'invalid_gate', 'label is required (1–80 characters)');
  if (body.kind === 'dba-device') {
    assert(typeof body.device_id === 'string' && /^dev_[A-Za-z0-9]{8,64}$/.test(body.device_id), 'invalid_gate', 'device_id must name one of your devices');
    return { kind: body.kind, label, device_id: body.device_id };
  }
  if (VENDOR_KINDS.includes(body.kind)) return { kind: body.kind, label, ...cleanVendorInput(body) };
  if (body.kind === 'webhook') {
    let key;
    try { key = publicJwk(body.public_jwk); } catch { assert(false, 'invalid_gate', 'public_jwk must be the P-256 public key (JWK) your service signs late answers with'); }
    return { kind: body.kind, label, url: cleanGateWebhookUrl(body.url, env), public_jwk: key };
  }
  if (body.kind === 'webauthn') {
    assert(body.user_verification === undefined || ['required', 'preferred'].includes(body.user_verification), 'invalid_gate', 'user_verification must be "required" or "preferred"');
    return { kind: body.kind, label, user_verification: body.user_verification ?? 'preferred' };
  }
  return { kind: body.kind, label };
}

/**
 * Create a gate row. dba-device gates are active at once; TOTP and security-key gates start
 * `pending` and return what the owner needs to set them up (shown once), then become active when
 * activateGate sees a first code or the registration (so a mistyped QR scan cannot lock anyone out).
 */
export async function createGate(tx, input, now, { env, account }) {
  const existing = await tx.list({ prefix: 'gate:' });
  assert(existing.size < MAX_GATES, 'too_many_gates', `An account can have at most ${MAX_GATES} gates`, 409);
  const gate = { id: randomId('gate', 16), kind: input.kind, label: input.label, created_at: now };
  let setup;
  if (input.kind === 'dba-device') {
    const device = await tx.get(`device:${input.device_id}`);
    assert(device && !device.revoked_at, 'unknown_device', 'device_id must name one of your devices that is not revoked', 400);
    gate.device_id = input.device_id; gate.state = 'active';
  } else if (input.kind === 'webhook') {
    gate.url = input.url; gate.public_jwk = input.public_jwk; gate.state = 'active';
  } else if (VENDOR_KINDS.includes(input.kind)) {
    // The vendor's secret (Duo secret key, Okta API token) is sealed and never returned (plan §7).
    assert(env.GATE_SEALING_KEYS, 'gate_kind_unavailable', 'Duo and Okta gates are not available on this server (no sealing key configured)', 503);
    Object.assign(gate, input.config, { state: 'active', secret: await seal(env, { account, gateId: gate.id }, new TextEncoder().encode(input.secret)) });
  } else if (input.kind === 'totp') {
    assert(env.GATE_SEALING_KEYS, 'gate_kind_unavailable', 'TOTP gates are not available on this server (no sealing key configured)', 503);
    const secret = crypto.getRandomValues(new Uint8Array(20));
    gate.state = 'pending'; gate.setup_until = now + SETUP_TTL_MS;
    gate.secret = await seal(env, { account, gateId: gate.id }, secret);
    setup = { secret: base32(secret), otpauth_uri: otpauthUri({ secret, label: input.label }), expires_in: SETUP_TTL_MS / 1000 };
  } else {
    gate.state = 'pending'; gate.setup_until = now + SETUP_TTL_MS; gate.user_verification = input.user_verification;
    gate.challenge = b64u(crypto.getRandomValues(new Uint8Array(32)));
    const exclude = [...existing.values()].filter(g => g.kind === 'webauthn' && g.credential).map(g => g.credential.credential_id);
    setup = { public_key: creationOptions({ challenge: gate.challenge, rpId: rpIdFor(env.APP_ORIGIN), userId: b64u(new TextEncoder().encode(gate.id)), label: input.label, exclude }), expires_in: SETUP_TTL_MS / 1000 };
    setup.public_key.authenticatorSelection.userVerification = input.user_verification;
  }
  await tx.put(gateKey(gate.id), gate);
  return { gate, setup };
}

/** Finish setting up a TOTP gate (a first code) or a security key (its registration). */
export async function activateGate(tx, id, body, now, { env, account }) {
  const gate = await tx.get(gateKey(id));
  assert(gate, 'not_found', 'Gate not found', 404);
  assert(gate.state === 'pending', 'gate_active', 'This gate is already set up', 409);
  assert(gate.setup_until > now, 'setup_expired', 'Setting up this gate took too long; delete it and add it again', 410);
  if (gate.kind === 'totp') {
    const step = await matchStep(await unseal(env, { account, gateId: id }, gate.secret), String(body?.code ?? ''), now);
    assert(step !== null, 'invalid_code', 'That code is not right; check the authenticator app\'s clock and try the current code', 400);
    gate.last_step = step;
  } else if (gate.kind === 'webauthn') {
    try {
      gate.credential = await verifyRegistration(body?.registration, { challenge: gate.challenge, origin: env.APP_ORIGIN, rpId: rpIdFor(env.APP_ORIGIN), requireUV: gate.user_verification === 'required' });
    } catch (error) { if (error instanceof WebAuthnError) throw new ApiError(400, 'invalid_webauthn', error.message); throw error; }
    delete gate.challenge;
  } else assert(false, 'gate_active', 'This gate needs no setup', 409);
  gate.state = 'active'; gate.activated_at = now; delete gate.setup_until;
  await tx.put(gateKey(id), gate);
  return gate;
}

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
export async function checkGatesForIssue(tx, grants, deviceId, policies = []) {
  const ids = (grants || []).flatMap(g => Array.isArray(g?.require?.gates) ? g.require.gates.flatMap(e => e.any) : []);
  const gates = await loadGates(tx, ids);
  for (const id of new Set(ids)) {
    const gate = gates.get(id);
    assert(gate, 'unknown_gate', `Gate ${id} does not exist in this account; create it first (GET /api/v1/gates lists them)`, 400);
    assert(gateActive(gate), 'gate_not_active', `Gate ${id} is not set up yet; finish its setup first`, 400);
    assert(!(gate.kind === 'dba-device' && gate.device_id === deviceId), 'self_gate', `Gate ${id} is the device this credential is for; a device cannot approve its own requests`, 400);
  }
  for (const { grant_index: i, action, kinds } of policies) {
    assert(meetsPolicy(grantEntries(grants[i]), kinds, gates), 'gate_required', `grants[${i}]: ${action} requires a gate entry whose gates are all of kind ${kinds?.join(' or ') ?? 'any'}`, 400, { grant_index: i, action, policy: { require: true, ...(kinds ? { kinds } : {}) } });
  }
}

/** A grant's gate entries (step_up is the owner entry), or []. */
function grantEntries(grant) {
  if (Array.isArray(grant?.require?.gates)) return grant.require.gates;
  return grant?.require?.step_up === true ? [{ any: ['owner'] }] : [];
}

/**
 * Does one entry consist only of gates of the accepted kinds (any kind when `kinds` is null)?
 * spec/evaluation.md §3.8; `gates` maps ids to rows (a missing gate is of no kind).
 */
export function meetsPolicy(entries, kinds, gates) {
  return (entries || []).some(entry => entry.any.every(id => {
    const kind = id === 'owner' ? 'owner' : gates.get(id)?.kind;
    return typeof kind === 'string' && (!kinds || kinds.includes(kind));
  }));
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
 */
export function atLeastAsStrict(current, next) {
  if (!current?.length) return true;
  if (!next?.length) return false;
  return current.every(c => next.some(n => n.any.every(id => c.any.includes(id)) && (c.on_timeout === 'allow' || n.on_timeout !== 'allow')));
}

/**
 * The current entries a sign-in gate change must pass: those of every list it loosens, without
 * duplicates, at most 3 (the most a gate list holds). Empty when nothing is loosened.
 */
export function looseningEntries(current, merged) {
  const lists = [[current.default, merged.default], [current.dashboard, merged.dashboard],
    ...Object.entries(current.audiences || {}).map(([name, entries]) => [entries, merged.audiences?.[name]])];
  const seen = new Map();
  for (const [before, after] of lists) {
    if (atLeastAsStrict(before, after)) continue;
    for (const entry of before) seen.set(JSON.stringify(entry), entry);
  }
  return [...seen.values()].slice(0, 3);
}

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

/**
 * The signed gate request DBA posts to a webhook gate (spec/events.md §6): who asks for what,
 * which entry it answers, until when, and where to send a late answer.
 */
export async function signGateEvent(env, { req, entryIndex, gate, account, callback }) {
  const signer = await activeSigner(env);
  const entry = req.entries[entryIndex];
  const payload = {
    iss: issuerName(env), aud: gate.url, iat: Math.floor(Date.now() / 1000), exp: Math.ceil(entry.deadline / 1000), jti: randomId('gev', 16),
    type: 'gate.request', account, gate: gate.id, request: req.id, entry: entryIndex, number: req.number,
    device: { id: req.device_id, name: req.device_name }, action: req.action, resource: req.resource, audience: req.audience,
    on_timeout: entry.on_timeout, callback
  };
  return signJws({ typ: GATE_EVENT_TYP, kid: signer.kid }, payload, signer.key);
}

/**
 * A test message for a webhook gate (dashboard "Test", `dba gates test`): signed like a gate
 * request but `type: "gate.test"`, with no request, entry or callback. Services verify it the
 * same way; whatever they answer is reported back and nothing is decided.
 */
export async function signGateTest(env, { gate, account }) {
  const signer = await activeSigner(env);
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss: issuerName(env), aud: gate.url, iat: now, exp: now + 60, jti: randomId('gev', 16), type: 'gate.test', account, gate: gate.id };
  return signJws({ typ: GATE_EVENT_TYP, kid: signer.kid }, payload, signer.key);
}

/**
 * POST a gate request to a webhook gate. Returns { delivered, decision? }: a 2xx is delivered; a
 * 200 whose JSON says { "decision": "allow" | "deny" } answers at once. Never follows redirects.
 */
export async function postGateEvent(env, url, jws) {
  const fetcher = env.WEBHOOK_FETCH || fetch;
  try {
    const response = await fetcher(url, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/jwt', Accept: 'application/json', 'User-Agent': 'devicebasedauth.org-gates/1' }, body: jws, signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS) });
    if (response.status < 200 || response.status >= 300) { try { await response.body?.cancel(); } catch { /* ignore */ } return { delivered: false, status: response.status }; }
    let decision = null;
    if (response.status === 200) {
      const text = (await response.text()).slice(0, 4096);
      try { const body = JSON.parse(text); if (body?.decision === 'allow' || body?.decision === 'deny') decision = body.decision; } catch { /* a 200 without an answer is a delivery */ }
    } else { try { await response.body?.cancel(); } catch { /* ignore */ } }
    return { delivered: true, status: response.status, decision };
  } catch (error) {
    return { delivered: false, status: 0, error: error.name === 'TimeoutError' ? 'timeout' : 'network_error' };
  }
}

/**
 * A webhook gate's late answer: a compact JWS (ES256, typ dba-gate-answer+jwt) signed by the key
 * the gate registered, over { gate, request, entry, decision, iat }. Returns those claims.
 */
export async function verifyGateAnswer(tx, jws, requestId, now) {
  let decoded;
  try { decoded = decodeJws(String(jws ?? '').trim()); } catch { assert(false, 'invalid_answer', 'The body must be a compact JWS'); }
  const { header, payload } = decoded;
  assert(header.typ === GATE_ANSWER_TYP && header.alg === 'ES256', 'invalid_answer', `The answer must be an ES256 JWS with typ ${GATE_ANSWER_TYP}`);
  assert(typeof payload.gate === 'string' && payload.request === requestId, 'invalid_answer', 'The answer names another request');
  const gate = await tx.get(gateKey(payload.gate));
  assert(gate?.kind === 'webhook', 'not_a_gate', 'The answer names no webhook gate of this account', 403);
  let signed = false;
  try { signed = !!await verifyJws(jws.trim(), gate.public_jwk); } catch { signed = false; }
  assert(signed, 'invalid_signature', 'The answer is not signed by the key this gate registered', 403);
  assert(Number.isSafeInteger(payload.iat) && Math.abs(payload.iat - now / 1000) <= 300, 'stale_answer', 'The answer\'s iat must be within 5 minutes of now', 400);
  assert(Number.isSafeInteger(payload.entry) && payload.entry >= 0 && payload.entry < 3, 'invalid_answer', 'entry must be 0, 1 or 2');
  assert(payload.decision === 'allow' || payload.decision === 'deny', 'invalid_answer', 'decision must be "allow" or "deny"');
  return { gate: gate.id, entry: payload.entry, decision: payload.decision };
}
