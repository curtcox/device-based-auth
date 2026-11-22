/**
 * devicebasedauth.org browser SDK.
 *
 *   import { DBA } from 'https://devicebasedauth.org/sdk/v1.4.0/dba.js';
 *   const dba = new DBA();
 *   if (!await dba.ready()) await dba.enroll({ aud: ['example.com'], grants: [{ actions: ['example:read'] }] });
 *   const response = await dba.fetch('https://example.com/api/things');
 *
 * The device key is a non-extractable WebCrypto P-256 key kept in IndexedDB: scripts on this
 * origin can use it to sign, but nothing (including this SDK) can ever read it out.
 *
 * On devicebasedauth.org itself, signUp() creates an account by paying its first deposit and
 * recover() gets back into one after losing every device; finish() waits for either.
 */
import { generateKeyPair, exportPublicJwk, signJws } from '../verify/src/jose.js';
import { createProof, inspectCredential } from '../verify/src/credential.js';
import { describeGrant, evaluateGrants } from '../verify/src/grants.js';

export const VERSION = '1.4.0';
const DB = 'devicebasedauth';
const STORE = 'devices';

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function idb(mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode); const request = fn(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(request?.result); tx.onerror = () => reject(tx.error); tx.onabort = () => reject(tx.error);
    });
  } finally { db.close(); }
}

/** An error carrying the server's machine-readable code. */
export class DBAError extends Error {
  constructor(message, code, details = {}) { super(message); this.code = code; Object.assign(this, details); }
}

/** The longest delay setTimeout honours. */
const MAX_TIMER_MS = 2 ** 31 - 1;

export class DBA {
  /**
   * @param {object} [options]
   * @param {string} [options.origin] devicebasedauth.org origin (default https://devicebasedauth.org)
   * @param {string} [options.name] slot name, so one page can hold several device identities
   */
  constructor({ origin = 'https://devicebasedauth.org', name = 'default' } = {}) {
    this.origin = origin.replace(/\/$/, ''); this.name = `${this.origin}#${name}`; this.state = null; this.renewTimer = null;
    // DPoP nonces servers handed out (RFC 9449 §8), by origin: put in every later proof there.
    this.nonces = new Map();
  }

  /**
   * Keep the DPoP nonce a response hands out (header DPoP-Nonce) for its origin, and say whether
   * the response is a nonce challenge (401 use_dpop_nonce): then send the request again, with new
   * headers. devicebasedauth.org asks for one in the first minute after an account's object
   * starts; api(), fetch() and fetchWithGates() retry once by themselves.
   * @returns {Promise<boolean>}
   */
  async nonceChallenge(url, response) {
    const origin = new URL(url, location.href).origin;
    const header = response.headers.get('DPoP-Nonce');
    if (response.status !== 401) { if (header) this.nonces.set(origin, header); return false; }
    const body = await response.clone().json().catch(() => null);
    const asked = body?.code === 'use_dpop_nonce' || body?.error === 'use_dpop_nonce' || /error="use_dpop_nonce"/.test(response.headers.get('WWW-Authenticate') || '');
    const nonce = header || (typeof body?.dpop_nonce === 'string' ? body.dpop_nonce : null);
    if (!asked || !nonce || nonce === this.nonces.get(origin)) return false;
    this.nonces.set(origin, nonce);
    return true;
  }

  /** Load the stored key and credential. Returns true when a usable (unexpired) credential exists. */
  async ready() {
    this.state = (await idb('readonly', store => store.get(this.name))) || null;
    return !!this.credential && this.expiresIn() > 0;
  }

  async save() { await idb('readwrite', store => store.put(this.state, this.name)); }

  /** The current credential (compact JWS) or null. */
  get credential() { return this.state?.credential || null; }
  /** The decoded credential payload (not verified — use for display and local checks only). */
  get payload() { return this.credential ? inspectCredential(this.credential).payload : null; }
  /** Seconds until the credential expires (0 when none). */
  expiresIn() { const p = this.payload; return p ? Math.max(0, p.exp - Math.floor(Date.now() / 1000)) : 0; }
  /** Plain-English descriptions of each grant. */
  describe() { return (this.payload?.grants || []).map(describeGrant); }

  /**
   * Would the credential allow this action right now (time, location and action checks only)?
   * A hint for UI; servers still decide, and only they know about revocation.
   */
  allows(action, { resource, location } = {}) {
    const p = this.payload; if (!p || this.expiresIn() <= 0) return false;
    return evaluateGrants(p.grants, { now: Math.floor(Date.now() / 1000), action, resource, location, online: false, attestation: p.device?.attestation }).allow;
  }

  async key() {
    if (!this.state?.privateKey) {
      const pair = await generateKeyPair(false);
      this.state = { privateKey: pair.privateKey, publicJwk: await exportPublicJwk(pair.publicKey), credential: null, created_at: Date.now() };
      await this.save();
    }
    return this.state;
  }

  async api(path, { method = 'GET', body, auth = false, confirm = true } = {}) {
    const url = `${this.origin}${path}`;
    const send = async () => fetch(url, { method, headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(auth ? await this.headers(method, url, { confirm }) : {}) }, body: body ? JSON.stringify(body) : undefined });
    let response = await send();
    if (auth && await this.nonceChallenge(url, response)) response = await send();
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new DBAError(data.error || `HTTP ${response.status}`, data.code || 'http_error', { status: response.status, details: data });
    return data;
  }

  /**
   * Ask the account owner to approve this device. Opens the approval page in a popup (call from a
   * click handler so it is not blocked) and resolves with the credential.
   * @param {object} request { aud: string[], grants: object[], device?: {name, kind}, lifetime_seconds? }
   * @param {object} [options] { popup: true, onApprovalUrl(url), timeoutMs, enrollmentToken }
   *   enrollmentToken: a dbae_… token the owner created (kiosks, fleets); the credential is issued
   *   at once without a popup, and aud/grants may be left out to take the token's.
   */
  async enroll(request, { popup = true, onApprovalUrl, timeoutMs = 15 * 60000, enrollmentToken } = {}) {
    const signed = await this.enrollmentRequest(request);
    if (enrollmentToken) {
      // Pre-approved by the owner (a kiosk or fleet): issued at once, no approval popup.
      const issued = await this.api('/api/v1/enrollments/redeem', { method: 'POST', body: { request: signed, enrollment_token: enrollmentToken } });
      this.state.credential = issued.credential; await this.save();
      return issued.credential;
    }
    const started = await this.api('/api/v1/enrollments', { method: 'POST', body: { request: signed } });
    const win = popup ? window.open(started.approval_url, 'devicebasedauth-approve', 'popup,width=520,height=760') : null;
    if (!win && onApprovalUrl) onApprovalUrl(started.approval_url);
    else if (!win && popup) throw new DBAError('The approval popup was blocked; call enroll() from a click handler or pass onApprovalUrl', 'popup_blocked', { approval_url: started.approval_url });
    const result = await new Promise((resolve, reject) => {
      const deadline = Date.now() + timeoutMs; let done = false;
      const finish = (fn, value) => { if (done) return; done = true; window.removeEventListener('message', onMessage); fn(value); };
      const onMessage = event => {
        if (event.origin !== this.origin || event.data?.source !== 'devicebasedauth' || event.data.enrollment_id !== started.enrollment_id) return;
        if (event.data.status === 'approved') finish(resolve, event.data); else finish(reject, new DBAError('The owner did not approve this device', 'denied'));
      };
      window.addEventListener('message', onMessage);
      // Polling also covers approvals made on another device (e.g. scanning the link on a phone).
      const poll = async () => {
        if (done) return;
        if (Date.now() > deadline) return finish(reject, new DBAError('Enrollment timed out', 'expired'));
        try {
          const state = await fetch(started.poll_url).then(r => r.json());
          if (state.status === 'approved') return finish(resolve, state);
          if (state.status === 'denied' || state.status === 'expired') return finish(reject, new DBAError(`Enrollment ${state.status}`, state.status));
        } catch { /* transient; keep polling */ }
        setTimeout(poll, (started.interval || 3) * 1000);
      };
      setTimeout(poll, (started.interval || 3) * 1000);
    });
    this.state.credential = result.credential; await this.save();
    return result.credential;
  }

  /** An enrollment request (dba-enroll+jwt) signed by this slot's key. */
  async enrollmentRequest(request = {}) {
    const { privateKey, publicJwk } = await this.key();
    const device = { name: defaultDeviceName(), kind: 'browser', ...request.device, key_protection: 'webcrypto-nonextractable' };
    return signJws({ typ: 'dba-enroll+jwt', jwk: publicJwk }, { iat: Math.floor(Date.now() / 1000), ...(request.aud ? { aud: request.aud } : {}), ...(request.grants ? { grants: request.grants } : {}), device, ...(request.lifetime_seconds ? { lifetime_seconds: request.lifetime_seconds } : {}), return_origin: location.origin }, privateKey);
  }

  /** A fresh key for a new identity, refusing to drop a credential that still works. */
  async freshKey(replace) {
    if (this.credential && this.expiresIn() > 0 && !replace) throw new DBAError('This slot already holds a working credential; pass { replace: true } to start over', 'already_enrolled');
    clearTimeout(this.renewTimer); this.state = null;
    await this.key();
  }

  /**
   * Create a devicebasedauth.org account by paying its first deposit; no sign-in provider needed.
   * The new key's sign-up waits in this slot (across page loads) until finish(). Resolves with the
   * server's answer: send the person to `url` (Stripe Checkout), or with `local_payment` (a local
   * development server) pay through POST /api/v1/dev/signup-paid; then call finish().
   * @param {{ creditCents: number, acceptTerms: boolean, device?: object, replace?: boolean }} options
   */
  async signUp({ creditCents, acceptTerms, device, replace = false } = {}) {
    await this.freshKey(replace);
    const request = await this.enrollmentRequest({ device });
    const started = await this.api('/api/v1/signup', { method: 'POST', body: { request, credit_cents: creditCents, accept_terms: acceptTerms === true } });
    this.state.pending = { kind: 'signup', ticket: started.ticket, account: started.account, path: '/api/v1/signup/complete', interval: started.interval, local_payment: !!started.local_payment };
    await this.save();
    return started;
  }

  /**
   * Get back into an account after losing every device, with a new key in this slot:
   * { account, code } (a recovery code: done at once), { account, via: 'gate' } (a passkey or
   * another device approves, typing the `number` shown), or { email, via: 'email' } (a link to
   * the verified address, then a wait any signed-in device can cancel). Unless recovered at once,
   * the recovery waits in this slot until finish().
   */
  async recover({ account, code, email, via = code ? 'code' : email ? 'email' : 'gate', device, replace = false } = {}) {
    await this.freshKey(replace);
    const request = await this.enrollmentRequest({ device });
    const result = await this.api('/api/v1/recover', { method: 'POST', body: { via, request, ...(account ? { account } : {}), ...(code ? { code } : {}), ...(email ? { email } : {}) } });
    if (result.status === 'recovered') { this.state.credential = result.credential; await this.save(); return result; }
    this.state.pending = { kind: `recover-${via}`, ticket: result.ticket, account: result.account ?? null, path: '/api/v1/recover/complete', interval: result.interval, number: result.number ?? null, approve_url: result.approve_url ?? null };
    await this.save();
    return result;
  }

  /** The sign-up or recovery this slot is waiting for ({ kind, account, number, … }), or null. */
  get pending() { return this.state?.pending ?? null; }

  /**
   * Wait for the pending sign-up or recovery and keep its credential. onPending(answer) hears each
   * "not yet" (a recovery by email says { stage, ready_at }). Rejects with code `pending` when
   * timeoutMs passes (call again later), or the server's code when it was refused.
   */
  async finish({ timeoutMs = 15 * 60000, onPending } = {}) {
    const pending = this.pending;
    if (!pending) throw new DBAError('No sign-up or recovery is waiting in this slot', 'nothing_pending');
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const url = `${this.origin}${pending.path}`;
      const proof = await createProof({ privateKey: this.state.privateKey, publicJwk: this.state.publicJwk, method: 'POST', url, credential: pending.ticket });
      const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', DPoP: proof }, body: JSON.stringify({ ticket: pending.ticket }) });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        // Refused for good: forget it, so the page can start over.
        if (['recovery_denied', 'invalid_signup', 'invalid_recovery'].includes(data.code)) { delete this.state.pending; await this.save(); }
        throw new DBAError(data.error || `HTTP ${response.status}`, data.code || 'http_error', { status: response.status, details: data });
      }
      if (data.credential) { this.state.credential = data.credential; delete this.state.pending; await this.save(); return data.credential; }
      onPending?.(data);
      if (Date.now() >= deadline) throw new DBAError('Still waiting; call finish() again later', 'pending', { pending: data });
      await new Promise(resolve => setTimeout(resolve, Math.min((data.interval || pending.interval || 3) * 1000, Math.max(0, deadline - Date.now()))));
    }
  }

  /**
   * Headers for one request: Authorization: DBA <credential> and a fresh DPoP proof, plus
   * DBA-Confirmation for a credential issued with `confirm`. When that confirmation is missing or
   * about to end, a new one is asked for first (see confirm(); pass { confirm: false } to send the
   * request without one instead).
   */
  async headers(method, url, { location: loc, confirm = true } = {}) {
    if (!this.credential) throw new DBAError('No credential; call enroll() first', 'no_credential');
    const confirmation = this.payload.confirm ? (this.confirmation || (confirm ? (await this.confirm()).confirmation : null)) : null;
    const target = new URL(url, location.href);
    const proof = await createProof({ privateKey: this.state.privateKey, publicJwk: this.state.publicJwk, method, url: target.href, credential: this.credential, nonce: this.nonces.get(target.origin), location: loc });
    return { Authorization: `DBA ${this.credential}`, DPoP: proof, ...(confirmation ? { 'DBA-Confirmation': confirmation } : {}) };
  }

  /**
   * fetch() with the credential and a proof attached. init.dba: { location, confirm }. Sent once
   * more with a fresh proof when the server answers with a DPoP nonce challenge.
   */
  async fetch(input, init = {}) {
    const original = new Request(input, init);
    const send = async () => {
      const request = original.clone();
      const headers = new Headers(request.headers);
      for (const [k, v] of Object.entries(await this.headers(request.method, request.url, init.dba || {}))) headers.set(k, v);
      return fetch(new Request(request, { headers }));
    };
    const response = await send();
    return await this.nonceChallenge(original.url, response) ? send() : response;
  }

  /**
   * fetch() that waits while the site's online check says the request's gates have not decided
   * yet (403 { code: "gate_pending", gate_request: { retry_after } }, spec/credential.md §8): it
   * sends the request again, with a fresh proof, every retry_after seconds until the site answers
   * anything else or timeoutMs passes (then the last gate_pending response is returned).
   * onPending(gate_request) is called once, so the page can say who must approve.
   */
  async fetchWithGates(input, init = {}, { timeoutMs = 5 * 60000, onPending } = {}) {
    const original = new Request(input, init);
    const deadline = Date.now() + timeoutMs; let told = false;
    for (;;) {
      const response = await this.fetch(original.clone(), { dba: init.dba });
      if (response.status !== 403) return response;
      const body = await response.clone().json().catch(() => null);
      if (body?.code !== 'gate_pending') return response;
      if (!told) { told = true; onPending?.(body.gate_request); }
      const wait = Math.max(1, Number(body.gate_request?.retry_after) || 2) * 1000;
      if (Date.now() + wait > deadline) return response;
      await new Promise(resolve => setTimeout(resolve, wait));
    }
  }

  /**
   * The saved confirmation while it is current (more than 30 s left, for this credential and key),
   * else null. Only credentials issued with `confirm` need one.
   */
  get confirmation() {
    const jwt = this.state?.confirmation; const p = this.payload;
    if (!jwt || !p) return null;
    try {
      const c = inspectCredential(jwt).payload;
      return c.cid === p.cid && c.cnf?.jkt === p.cnf?.jkt && c.exp - 30 > Date.now() / 1000 ? jwt : null;
    } catch { return null; }
  }

  /**
   * Ask this credential's gates to confirm the device is still trusted (credentials issued with
   * `confirm`; 12 µ$ when one is issued), waiting while they decide. Resolves with
   * { confirmation, expires_at, by_timeout } and keeps the confirmation for headers(); rejects with
   * DBAError 'gate_denied' or 'confirmation_timeout'. Concurrent calls share one wait.
   * @param {object} [options] { timeoutMs (default 5 minutes), onPending(gate_request) }
   */
  confirm({ timeoutMs = 5 * 60000, onPending } = {}) {
    this.confirming ||= this.waitForConfirmation(timeoutMs, onPending).finally(() => { this.confirming = null; });
    return this.confirming;
  }

  async waitForConfirmation(timeoutMs, onPending) {
    const p = this.payload; if (!p) throw new DBAError('No credential to confirm', 'no_credential');
    const deadline = Date.now() + timeoutMs; let told = false;
    for (;;) {
      const result = await this.api(`/api/v1/credentials/${p.cid}/confirm`, { method: 'POST', body: {}, auth: true, confirm: false });
      if (result.status === 'confirmed') {
        this.state = { ...this.state, confirmation: result.confirmation }; await this.save();
        return result;
      }
      if (result.status === 'denied') throw new DBAError('The gates refused to confirm this device', result.code || 'gate_denied');
      if (!told) { told = true; onPending?.(result.gate_request); }
      const wait = Math.max(1, Number(result.gate_request?.retry_after) || 2) * 1000;
      if (Date.now() + wait > deadline) throw new DBAError('Gave up waiting for the gates to confirm this device', 'confirmation_timeout', { gate_request: result.gate_request });
      await new Promise(resolve => setTimeout(resolve, wait));
    }
  }

  /** Renew before expiry (same key), or rotate to a fresh non-extractable key. */
  async renew({ rotate = false } = {}) {
    const p = this.payload; if (!p) throw new DBAError('No credential to renew', 'no_credential');
    const path = `/api/v1/credentials/${p.cid}/renew`; const body = {};
    let next = null;
    if (rotate) {
      const pair = await generateKeyPair(false); const jwk = await exportPublicJwk(pair.publicKey);
      body.new_key_proof = await signJws({ typ: 'dba-rotate+jwt', jwk }, { cid: p.cid, iat: Math.floor(Date.now() / 1000) }, pair.privateKey);
      next = { privateKey: pair.privateKey, publicJwk: jwk };
    }
    const result = await this.api(path, { method: 'POST', body, auth: true, confirm: false });
    this.state = { ...this.state, ...(next || {}), credential: result.credential }; await this.save();
    return result;
  }

  /**
   * Renew automatically at two thirds of the credential's lifetime while the page is open, and at
   * once (free) if the issuer has withdrawn the key that signed it.
   */
  autoRenew({ onError } = {}) {
    clearTimeout(this.renewTimer);
    const p = this.payload; if (!p) return;
    const run = () => this.renew().then(() => this.autoRenew({ onError }), onError || (() => {}));
    const at = (p.iat + (p.exp - p.iat) * 2 / 3) * 1000 - Date.now();
    // Browsers fire a setTimeout longer than 2^31-1 ms (24.8 days) at once, which would renew in a
    // loop; wait in steps instead.
    this.renewTimer = at > MAX_TIMER_MS ? setTimeout(() => this.autoRenew({ onError }), MAX_TIMER_MS) : setTimeout(run, Math.max(0, at));
    // Each signing key is checked once per instance, so a JWKS that somehow lacks the current key
    // cannot cause a renewal loop.
    const { kid } = inspectCredential(this.credential).header;
    this.checkedKids ||= new Set();
    if (at > 0 && !this.checkedKids.has(kid)) {
      this.checkedKids.add(kid);
      const credential = this.credential;
      this.keyWithdrawn().then(withdrawn => {
        if (withdrawn && this.credential === credential) { clearTimeout(this.renewTimer); run(); }
      }, () => {});
    }
  }

  /**
   * True when the issuer's JWKS no longer lists the key that signed this credential (the key was
   * withdrawn after a compromise). Relying parties then refuse the credential; renew() replaces it
   * at no charge. False when there is no credential or the JWKS cannot be fetched.
   */
  async keyWithdrawn() {
    if (!this.credential) return false;
    const { header } = inspectCredential(this.credential);
    // no-cache: a copy cached from before a rotation would not list the newest key.
    const response = await fetch(`${this.origin}/.well-known/jwks.json`, { cache: 'no-cache' }).catch(() => null);
    const keys = response?.ok ? (await response.json().catch(() => ({}))).keys : null;
    return Array.isArray(keys) && keys.length > 0 && !keys.some(k => k.kid === header.kid);
  }

  /** A short-lived bearer token for one audience (for code that cannot sign each request). */
  async token(audience) { return (await this.api('/api/v1/token', { method: 'POST', body: { audience }, auth: true, confirm: false })).access_token; }

  /** Revoke this device's credential everywhere and forget the key. */
  async revoke() {
    if (this.credential) await this.api('/api/v1/self/revoke', { method: 'POST', auth: true, confirm: false });
    await this.forget();
  }

  /** Delete the key and credential from this browser (does not revoke). */
  async forget() { clearTimeout(this.renewTimer); this.state = null; await idb('readwrite', store => store.delete(this.name)); }

  /** Decode any credential for display (no verification). */
  static inspect(jws) { return inspectCredential(jws); }
}

function defaultDeviceName() {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS X/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '';
  return `${browser}${os ? ` on ${os}` : ''} (${location.host})`;
}

export { describeGrant };
