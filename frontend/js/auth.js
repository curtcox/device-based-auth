/**
 * Sign-in for every page. Three ways to be signed in, in order of preference:
 *
 *  1. device — this browser holds a devicebasedauth.org credential for our own audience with
 *     `dba:session` (Stage B dogfooding, master plan §9.2): each request carries the credential
 *     and a fresh DPoP proof, and revoking the credential ends the session everywhere.
 *  2. clerk  — a Clerk session (production), sent as `Authorization: Bearer <session token>`.
 *  3. local  — local development only: an account name kept in localStorage and sent as
 *     `Authorization: LocalDev <name>`. The server refuses it outside local mode.
 */
import { h, replace, notice } from './html.js';

const LOCAL_KEY = 'dba-local-user';
// Clerk refuses sign-in from clerk-js versions it calls outdated (v5 stopped working in November
// 2026). Since v6 the sign-in UI is a separate package that registers its constructor on window.
const CLERK_SRC = 'https://cdn.jsdelivr.net/npm/@clerk/clerk-js@6/dist/clerk.browser.js';
const CLERK_UI_SRC = 'https://cdn.jsdelivr.net/npm/@clerk/ui@1/dist/ui.browser.js';
/** The SDK slot that holds the dashboard's own device credential. */
export const DEVICE_SLOT = 'dashboard';
export const SESSION_ACTION = 'dba:session';

let configPromise = null;
let sdkPromise = null;
let clerk = null;
let device = null;
let mode = null;
let localName = null;

/** GET /api/public/config, fetched once per page. */
export function getConfig() {
  configPromise ||= fetch('/api/public/config').then(async response => {
    if (!response.ok) throw new Error(`Could not load the site configuration (HTTP ${response.status})`);
    return response.json();
  });
  return configPromise;
}

function store() { try { return window.localStorage; } catch { return null; } }

/** The local development account name, or null. */
export function localUser() { try { return store()?.getItem(LOCAL_KEY) || null; } catch { return null; } }

/** Remember a local development account name (local mode only). */
export function setLocalUser(name) {
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(name)) throw new Error('Use 1–128 letters, digits, "-" or "_"');
  try { store()?.setItem(LOCAL_KEY, name); } catch { /* private mode: lasts for this page only */ }
  localName = name; mode = 'local';
}

/**
 * Each local sign-in is its own session, as a Clerk sign-in is (the dashboard sign-in gate
 * confirms sessions one by one). Kept with the name; a new sign-in starts a new one.
 */
let localSessionId = null;
function localSession() {
  if (localSessionId) return localSessionId;
  try { localSessionId = store()?.getItem(`${LOCAL_KEY}:session`) || null; } catch { localSessionId = null; }
  if (!localSessionId) {
    localSessionId = [...crypto.getRandomValues(new Uint8Array(9))].map(b => b.toString(36).padStart(2, '0')).join('').slice(0, 16);
    try { store()?.setItem(`${LOCAL_KEY}:session`, localSessionId); } catch { /* this page only */ }
  }
  return localSessionId;
}

/** Load the browser SDK once (it is only needed for device sign-in). */
function sdk() { sdkPromise ||= import('/sdk/dba.js'); return sdkPromise; }

/** A DBA SDK instance for the dashboard's device slot. */
export async function dashboardDevice() {
  const { DBA } = await sdk();
  return new DBA({ origin: location.origin, name: DEVICE_SLOT });
}

async function loadDevice(config) {
  try {
    const dba = await dashboardDevice();
    if (!await dba.ready()) return null;
    if (!dba.payload?.aud?.includes(config.audience) || !dba.allows(SESSION_ACTION)) return null;
    return dba;
  } catch { return null; }
}

function loadScript(src, data = {}) {
  const script = document.createElement('script');
  script.src = src; script.crossOrigin = 'anonymous'; script.async = true;
  Object.assign(script.dataset, data);
  return new Promise((resolve, reject) => {
    script.onload = resolve; script.onerror = () => reject(new Error('Could not load the sign-in service'));
    document.head.append(script);
  });
}

async function loadClerk(key) {
  await Promise.all([
    window.Clerk ? null : loadScript(CLERK_SRC, { clerkPublishableKey: key }),
    window.__internal_ClerkUICtor ? null : loadScript(CLERK_UI_SRC),
  ]);
  await window.Clerk.load({ ui: { ClerkUI: window.__internal_ClerkUICtor } });
  return window.Clerk;
}

/**
 * Work out who is signed in. Clerk is only loaded when no device credential is available, so
 * a browser signed in with its own device never needs a Clerk session.
 * @returns {Promise<{mode: string|null, config: object}>}
 */
export async function initAuth() {
  const config = await getConfig();
  device = await loadDevice(config);
  if (device) mode = 'device';
  else if (config.local) { localName = localUser(); mode = localName ? 'local' : null; }
  else if (config.clerk_publishable_key) { clerk = await loadClerk(config.clerk_publishable_key); mode = clerk.user ? 'clerk' : null; }
  else mode = null;
  return { mode, config };
}

/** The current sign-in mode: 'device', 'clerk', 'local' or null. */
export function authMode() { return mode; }

/** A short description of who is signed in, for the header. */
export function signedInLabel() {
  if (mode === 'device') return `This browser (${device.payload?.device?.name || 'device credential'})`;
  if (mode === 'clerk') return clerk?.user?.primaryEmailAddress?.emailAddress || clerk?.user?.username || 'Signed in';
  if (mode === 'local') return `Local account "${localName}"`;
  return 'Signed out';
}

/** The dashboard device credential in use, if any. */
export function currentDevice() { return mode === 'device' ? device : null; }

/**
 * Authorization headers for one request. Device proofs are bound to the method and URL.
 * @param {string} method
 * @param {string} url absolute URL
 */
export async function authHeaders(method, url) {
  if (mode === 'device' && device) return device.headers(method, url);
  if (mode === 'clerk' && clerk?.session) { const token = await clerk.session.getToken(); return token ? { Authorization: `Bearer ${token}` } : {}; }
  if (mode === 'local' && localName) return { Authorization: `LocalDev ${localName} ${localSession()}` };
  return {};
}

/**
 * Called by api() on a 401 before handleUnauthorized: a dashboard device's request met an account
 * object that just started and asks for its DPoP nonce. True when it should be sent again.
 */
export async function nonceChallenge(url, response) {
  return mode === 'device' && device ? device.nonceChallenge(url, response) : false;
}

/**
 * Called by api() on a 401. A revoked or expired dashboard credential is forgotten so the page
 * can fall back to another sign-in. Returns true when a retry might succeed.
 */
export async function handleUnauthorized() {
  if (mode !== 'device') return false;
  try { await device.forget(); } catch { /* already gone */ }
  device = null;
  const config = await getConfig();
  if (config.local) { localName = localUser(); mode = localName ? 'local' : null; }
  else if (config.clerk_publishable_key) { clerk ||= await loadClerk(config.clerk_publishable_key); mode = clerk.user ? 'clerk' : null; }
  else mode = null;
  return mode !== null;
}

/**
 * Sign in again for an operation that needs a recent sign-in (403 reverification_required).
 * Only a Clerk session can do that: sign out of Clerk and come back to the sign-in panel.
 * Returns false when this sign-in mode cannot re-verify.
 */
export async function reauthenticate() {
  if (mode !== 'clerk' || !clerk) return false;
  await clerk.signOut();
  location.reload();
  return true;
}

/**
 * A Clerk session token for linking a password sign-in to this account (STATUS B9): loads Clerk
 * if needed, opens its sign-up window when nobody is signed in to it, and waits for the sign-in.
 * The dashboard keeps using this browser's device; the token is only sent to be linked.
 */
export async function clerkTokenForLinking() {
  const config = await getConfig();
  if (!config.clerk_publishable_key) throw new Error('This server has no password sign-in');
  clerk ||= await loadClerk(config.clerk_publishable_key);
  if (!clerk.user) {
    await new Promise(resolve => {
      const stop = clerk.addListener(({ user }) => { if (user) { stop?.(); resolve(); } });
      clerk.openSignUp({});
    });
  }
  return clerk.session.getToken();
}

/** Sign out. A device-credential session revokes its own credential (free) and forgets the key. */
export async function signOut() {
  if (mode === 'device' && device) { try { await device.revoke(); } catch { await device.forget().catch(() => {}); } }
  else if (mode === 'clerk' && clerk) await clerk.signOut();
  try { store()?.removeItem(LOCAL_KEY); store()?.removeItem(`${LOCAL_KEY}:session`); } catch { /* nothing stored */ }
  localName = null; mode = null; device = null; localSessionId = null;
  location.reload();
}

/**
 * Enroll this browser as a device for the dashboard: a non-extractable key in IndexedDB and a
 * credential for our own audience with dba:session. Call from a click handler (it opens the
 * approval popup, which the signed-in owner approves).
 * @param {string} name device name shown in the dashboard
 */
export async function enrollDashboardDevice(name) {
  const config = await getConfig();
  const dba = await dashboardDevice();
  await dba.enroll({ aud: [config.audience], grants: [{ actions: [SESSION_ACTION] }], device: { name, kind: 'browser' } });
  device = dba; mode = 'device';
  return dba;
}

/** Preload the SDK so a later click can open the approval popup without delay. */
export function preloadSdk() { sdk().catch(() => {}); }

/**
 * Render a sign-in panel into a container. Resolves (and calls onSignedIn) once signed in.
 * @param {HTMLElement} container
 * @param {{ title?: string, intro?: string, onSignedIn: () => void }} options
 */
export async function renderSignIn(container, { title = 'Sign in', intro = '', onSignedIn }) {
  const config = await getConfig();
  const panel = h('section', { class: 'panel sign-in' }, h('h2', {}, title), intro ? h('p', {}, intro) : null);
  replace(container, panel, h('p', { class: 'muted small', id: 'sign-in-alternatives' }, 'New here? ', h('a', { href: '/signup.html' }, 'Create an account with this browser'), ' (no password). Lost your devices? ', h('a', { href: '/recover.html' }, 'Recover your account'), '.'));
  if (config.local) {
    const form = h('form', { class: 'stack', id: 'local-sign-in' },
      h('label', {}, 'Local account name', h('input', { name: 'user', value: 'developer', required: true, pattern: '[a-zA-Z0-9_\\-]{1,128}', autocomplete: 'username' })),
      h('button', { type: 'submit' }, 'Use local account'),
      h('p', { class: 'muted small' }, 'Local development mode: accounts are names, and credit comes from the free development deposit.'));
    form.addEventListener('submit', event => {
      event.preventDefault();
      try { setLocalUser(form.elements.user.value.trim()); onSignedIn(); }
      catch (error) { form.append(notice('error', error.message)); }
    });
    panel.append(form);
    return;
  }
  if (!config.clerk_publishable_key) { panel.append(notice('warn', 'Sign-in is being configured. Please check back soon.')); return; }
  try { clerk ||= await loadClerk(config.clerk_publishable_key); }
  catch (error) { panel.append(notice('error', error.message)); return; }
  const button = h('button', { type: 'button' }, 'Sign in');
  button.addEventListener('click', () => clerk.openSignIn({ fallbackRedirectUrl: location.href, forceRedirectUrl: location.href }));
  panel.append(button, h('p', { class: 'muted small' }, 'After your first sign-in you can make this browser a device and sign in with it instead.'));
  let done = false;
  clerk.addListener(({ user }) => { if (user && !done) { done = true; mode = 'clerk'; onSignedIn(); } });
}
