/**
 * Gates (STATUS B7, done/additional_gates.md): named devices or services that must say yes before
 * devicebasedauth.org lets something happen. This module holds the account's gate registry rows
 * (`gate:<id>`), the checks made when a grant or sign-in names gates, and the signed messages
 * exchanged with webhook gates. The request engine (`gatereq:<id>`) the AccountDO runs is in
 * gate-requests.js; it replaces the old step-up rows (a step-up is a request whose only gate is
 * `owner`).
 */
import { assert, ApiError } from '../utils/errors.js';
import { randomId } from '../utils/ids.js';
import { b64u, publicJwk, verifyJws, decodeJws, signJws } from '../../packages/verify/src/jose.js';
import { seal, unseal } from '../services/sealing.js';
import { matchStep, otpauthUri, base32 } from '../services/totp.js';
import { creationOptions, verifyRegistration, rpIdFor, WebAuthnError } from '../services/webauthn.js';
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

/** Authentication context classes for sign-ins (done/additional_gates.md §5.1). */
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
