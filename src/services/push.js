/**
 * Web Push security notices to the account owner's browsers (master plan §10: "push to registered
 * DBA devices on every issuance"). Messages are encrypted to the browser (RFC 8291, aes128gcm per
 * RFC 8188), so the push service sees only their size and timing, and signed with DBA's VAPID key
 * (RFC 8292). Nothing here is billed on its own: issuance prepays the CPU of its notices
 * (src/utils/cost-policy.js), and subscriptions are capped per account.
 */
import { b64u, unb64u } from '../../packages/verify/src/jose.js';
import { assert } from '../utils/errors.js';

/** At most this many browsers per account get notices (bounds what one issuance sends). */
export const MAX_SUBSCRIPTIONS = 5;
/** Ordinary issuances are announced at most this often; account-control ones every time. */
export const NOTICE_INTERVAL_MS = 3600000;
const TIMEOUT_MS = 5000;
const TTL_SECONDS = 86400;
const RECORD_SIZE = 4096;
const VAPID_LIFETIME_S = 12 * 3600;

// Push services of the browsers people use. Endpoints anywhere else are refused, so a subscription
// can never point DBA's requests at an arbitrary host.
const PUSH_HOSTS = ['fcm.googleapis.com', 'updates.push.services.mozilla.com', 'web.push.apple.com'];
const PUSH_HOST_SUFFIXES = ['.notify.windows.com', '.push.apple.com'];
const isLocalHost = host => host === 'localhost' || host.endsWith('.localhost') || host === '127.0.0.1';
const encoder = new TextEncoder();

/**
 * Validate a browser's PushSubscription (its toJSON()). Returns { endpoint, keys: { p256dh, auth } }.
 * Local development also accepts http on localhost.
 */
export function cleanSubscription(value, env) {
  assert(value && typeof value === 'object', 'invalid_subscription', 'subscription must be a PushSubscription object');
  let u; try { u = new URL(String(value.endpoint)); } catch { assert(false, 'invalid_subscription', 'subscription.endpoint must be a URL'); }
  const local = env.ENVIRONMENT === 'local' && isLocalHost(u.hostname);
  assert(u.protocol === 'https:' || (local && u.protocol === 'http:'), 'invalid_subscription', 'subscription.endpoint must use https');
  assert(!u.username && !u.password && !u.hash, 'invalid_subscription', 'subscription.endpoint cannot contain credentials or a fragment');
  assert(local || (!u.port && (PUSH_HOSTS.includes(u.hostname) || PUSH_HOST_SUFFIXES.some(s => u.hostname.endsWith(s)))), 'invalid_subscription', 'subscription.endpoint is not a known browser push service');
  assert(u.toString().length <= 1024, 'invalid_subscription', 'subscription.endpoint is too long');
  const p256dh = decodeKey(value.keys?.p256dh, 65, 'p256dh');
  assert(p256dh[0] === 4, 'invalid_subscription', 'subscription.keys.p256dh must be an uncompressed P-256 point');
  decodeKey(value.keys?.auth, 16, 'auth');
  return { endpoint: u.toString(), keys: { p256dh: value.keys.p256dh, auth: value.keys.auth } };
}

function decodeKey(value, length, name) {
  let bytes = null;
  try { bytes = typeof value === 'string' && /^[A-Za-z0-9_-]+={0,2}$/.test(value) ? unb64u(value.replace(/=+$/, '')) : null; } catch { bytes = null; }
  assert(bytes && bytes.length === length, 'invalid_subscription', `subscription.keys.${name} must be ${length} bytes, base64url`);
  return bytes;
}

// ---- VAPID ---------------------------------------------------------------------------------

let localVapid = null;
const vapidCache = new Map();

/**
 * DBA's VAPID key pair from PUSH_VAPID_KEY (a private P-256 JWK). Local development makes one per
 * isolate when the secret is missing. Returns null when push is not configured.
 */
export async function vapidKeys(env) {
  if (env.PUSH_VAPID_KEY) {
    const cached = vapidCache.get(env.PUSH_VAPID_KEY);
    if (cached) return cached;
    const jwk = JSON.parse(env.PUSH_VAPID_KEY);
    const privateKey = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const publicKey = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    const keys = { privateKey, publicKey: b64u(new Uint8Array(await crypto.subtle.exportKey('raw', publicKey))), jwts: new Map() };
    vapidCache.set(env.PUSH_VAPID_KEY, keys);
    return keys;
  }
  if (env.ENVIRONMENT !== 'local') return null;
  if (!localVapid) {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    localVapid = { privateKey: pair.privateKey, publicKey: b64u(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))), jwts: new Map() };
  }
  return localVapid;
}

/** The VAPID Authorization header for an endpoint (RFC 8292), reused per push service for hours. */
async function vapidAuthorization(env, keys, endpoint, now) {
  const audience = new URL(endpoint).origin;
  const cached = keys.jwts.get(audience);
  if (cached && cached.exp - 3600 > now / 1000) return cached.header;
  const exp = Math.floor(now / 1000) + VAPID_LIFETIME_S;
  const part = value => b64u(encoder.encode(JSON.stringify(value)));
  const input = `${part({ typ: 'JWT', alg: 'ES256' })}.${part({ aud: audience, exp, sub: env.APP_ORIGIN || 'https://devicebasedauth.org' })}`;
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, encoder.encode(input)));
  const header = `vapid t=${input}.${b64u(signature)}, k=${keys.publicKey}`;
  keys.jwts.set(audience, { exp, header });
  return header;
}

// ---- Message encryption (RFC 8291) ---------------------------------------------------------

async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, length * 8));
}

const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0; for (const p of parts) { out.set(p, i); i += p.length; } return out; };

/**
 * Encrypt a message to a subscription as one aes128gcm record. `ephemeral` and `salt` are for
 * tests; each real message uses a fresh key pair and salt.
 * @returns {Promise<Uint8Array>} the request body
 */
export async function encryptMessage(subscription, plaintext, { ephemeral, salt = crypto.getRandomValues(new Uint8Array(16)) } = {}) {
  const uaPublic = unb64u(subscription.keys.p256dh);
  const authSecret = unb64u(subscription.keys.auth);
  const pair = ephemeral || await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, pair.privateKey, 256));
  const ikm = await hkdf(authSecret, shared, concat(encoder.encode('WebPush: info\0'), uaPublic, asPublic), 32);
  const cek = await hkdf(salt, ikm, encoder.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, encoder.encode('Content-Encoding: nonce\0'), 12);
  const body = typeof plaintext === 'string' ? encoder.encode(plaintext) : plaintext;
  assert(body.length + 1 + 16 <= RECORD_SIZE, 'push_too_large', 'Push message too large', 500);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  // A single record: content, then the last-record delimiter 0x02, no padding.
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, concat(body, new Uint8Array([2]))));
  const header = new Uint8Array(21 + asPublic.length);
  header.set(salt, 0); new DataView(header.buffer).setUint32(16, RECORD_SIZE); header[20] = asPublic.length; header.set(asPublic, 21);
  return concat(header, sealed);
}

// ---- Sending ---------------------------------------------------------------------------------

/**
 * Send one notice to one subscription. Never throws; returns { ok, status, gone } (gone: the
 * browser unsubscribed, so the subscription can be dropped). env.PUSH_FETCH replaces fetch in
 * tests and local mode.
 * @param {{ title: string, body: string, url?: string, tag?: string }} message
 */
export async function sendNotice(env, subscription, message, now = Date.now()) {
  try {
    const keys = await vapidKeys(env);
    if (!keys) return { ok: false, status: 0, error: 'push_unavailable' };
    const body = await encryptMessage(subscription, JSON.stringify(message));
    const fetcher = env.PUSH_FETCH || fetch;
    const response = await fetcher(subscription.endpoint, {
      method: 'POST', redirect: 'manual', body, signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { 'Content-Type': 'application/octet-stream', 'Content-Encoding': 'aes128gcm', TTL: String(TTL_SECONDS), Urgency: 'high', Authorization: await vapidAuthorization(env, keys, subscription.endpoint, now) }
    });
    try { await response.body?.cancel(); } catch { /* ignore */ }
    return { ok: response.status >= 200 && response.status < 300, status: response.status, gone: response.status === 404 || response.status === 410 };
  } catch (error) {
    return { ok: false, status: 0, error: error.name === 'TimeoutError' ? 'timeout' : 'network_error' };
  }
}

/** Send a notice to every subscription at once. */
export function broadcast(env, subscriptions, message, now = Date.now()) {
  return Promise.all(subscriptions.map(s => sendNotice(env, s, message, now).then(result => ({ id: s.id, ...result }))));
}

/** Strip control characters and cap the length of untrusted text going into a notification. */
export function noticeText(value, max = 64) {
  return String(value ?? '').replace(/[\p{Cc}\p{Cf}]/gu, '').slice(0, max);
}

/**
 * Coalesce ordinary notices: `state` lives on a row the caller writes anyway (the balance row),
 * so deciding costs no extra write. Returns the number of issuances to announce now (this one
 * plus those held back since the last notice), or 0 to hold this one back.
 */
export function nextNotice(state, now, urgent) {
  const pending = (state.notice?.pending || 0) + 1;
  if (urgent || !state.notice?.at || now - state.notice.at >= NOTICE_INTERVAL_MS) { state.notice = { at: now, pending: 0 }; return pending; }
  state.notice = { ...state.notice, pending };
  return 0;
}
