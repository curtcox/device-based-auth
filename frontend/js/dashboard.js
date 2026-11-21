/**
 * The dashboard's shell, shared by every page module: account state, flash messages, error boxes,
 * confirmation and busy helpers, the account strip and the hash router. app.js registers the
 * pages (setViews) instead of this module importing them, so page modules can import the shell
 * without an import cycle.
 */
import { api } from './api.js';
import { signOut, reauthenticate, authMode, signedInLabel, enrollDashboardDevice, currentDevice } from './auth.js';
import { h, $, replace, usd, money, num, badge, notice } from './html.js';

/**
 * State shared across pages. One object rather than exported `let`s, because a module cannot
 * assign to a binding it imported: config is set at boot, accountInfo by the strip and by pages
 * that reload it, pollTimer by whichever page polls (render clears it on every navigation).
 */
export const state = { config: null, accountInfo: null, pollTimer: null };
/** The element every page renders into. */
export const view = $('#view');
/** Short alias for putting untrusted ids into URL paths. */
export const enc = encodeURIComponent;

let renderToken = 0;
let views = {};
let lockView = null;

/**
 * Register the pages, keyed by the first #hash segment, and the page shown while the dashboard's
 * sign-in gate holds the session.
 * @param {Record<string, (arg: string, current: () => boolean) => Promise<any>>} pages
 * @param {(current: () => boolean) => Promise<any>} locked
 */
export function setViews(pages, locked) { views = pages; lockView = locked; }

// ---------------------------------------------------------------------------------------------
// Flash messages, errors and form helpers

/** Show a message above the current section until the next navigation. */
export function flash(kind, ...children) { replace($('#flash'), notice(kind, ...children)); $('#flash').scrollIntoView?.({ block: 'nearest' }); }
/** Remove the flash message (on navigation). */
export function clearFlash() { replace($('#flash')); }

/** Render an API error, with a way forward for the common cases. */
export function errorBox(error) {
  if (error.status === 402) {
    const needed = error.details?.needed_microdollars;
    return notice('error', h('strong', {}, 'Insufficient balance. '), needed ? `This needs ${money(needed)} more. ` : '', h('a', { href: '#account' }, 'Add credit on the Account page'), '.');
  }
  if (error.code === 'reverification_required') {
    return notice('warn', h('strong', {}, 'Please confirm it is you. '), `${error.message}. `,
      authMode() === 'clerk' ? h('button', { type: 'button', class: 'link', onclick: () => reauthenticate() }, 'Sign in again') : null);
  }
  if (error.status === 401) return notice('error', `${error.message}. `, h('button', { type: 'button', class: 'link', onclick: () => location.reload() }, 'Sign in again'));
  return notice('error', error.message || String(error), error.code ? h('span', { class: 'muted small' }, ` (${error.code})`) : null);
}

/** Two-step confirmation: the first click reveals a confirm button. */
export function confirmButton(label, question, onConfirm, { confirmLabel = `Yes, ${label.toLowerCase()}` } = {}) {
  const wrap = h('span', { class: 'confirm' });
  const start = h('button', { type: 'button', class: 'danger small' }, label);
  const reset = () => replace(wrap, start);
  start.addEventListener('click', () => {
    const yes = h('button', { type: 'button', class: 'danger small' }, confirmLabel);
    yes.addEventListener('click', async () => {
      yes.disabled = true;
      try { await onConfirm(); } catch (error) { flash('error', error.message); reset(); }
    });
    replace(wrap, h('span', { class: 'small' }, question, ' '), yes, ' ', h('button', { type: 'button', class: 'secondary small', onclick: reset }, 'Cancel'));
  });
  return replace(wrap, start);
}

/** Disable a form's buttons while an async submit runs. */
export async function busy(form, fn) {
  const buttons = [...form.querySelectorAll('button')];
  buttons.forEach(b => { b.disabled = true; });
  try { return await fn(); } finally { buttons.forEach(b => { b.disabled = false; }); }
}

// ---------------------------------------------------------------------------------------------
// The account strip and routing

/** Reload the account and redraw the strip above every page (balance, signed-in identity). */
export async function refreshStrip() {
  const strip = $('#account-strip');
  try { state.accountInfo = await api('/api/v1/account'); } catch (error) {
    state.accountInfo = null;
    if (error.code === 'sign_in_gate_required') replace(strip, h('strong', {}, 'Waiting for your sign-in gate'), h('span', { class: 'spacer' }), h('button', { type: 'button', class: 'secondary small', onclick: () => signOut() }, 'Sign out'));
    else replace(strip, errorBox(error));
    strip.hidden = false; return;
  }
  const device = currentDevice();
  const useDevice = h('button', { type: 'button', class: 'secondary small', id: 'use-device' }, 'Use this browser as a device for the dashboard');
  useDevice.addEventListener('click', () => enrollThisBrowser(useDevice));
  replace(strip,
    h('strong', { id: 'balance' }, `Balance ${usd(state.accountInfo.balance_microdollars)}`),
    h('span', { class: 'muted small' }, `${num(state.accountInfo.balance_microdollars)} µ$`),
    h('span', { class: 'small', id: 'signed-in-as' }, signedInLabel()),
    h('span', { class: 'spacer' }),
    device ? badge('active', 'Signed in with this device') : useDevice,
    h('a', { href: '#account', class: 'small' }, 'Add credit'),
    h('button', { type: 'button', class: 'secondary small', id: 'sign-out', onclick: () => signOut() }, device ? 'Sign out (revokes this browser)' : 'Sign out'));
  strip.hidden = false;
}

/** Stage B dogfooding: enroll this browser for dba:session and use it for every call. */
async function enrollThisBrowser(button) {
  button.disabled = true;
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  flash('info', 'Approve this browser in the window that just opened. You can rename it there.');
  try {
    const dba = await enrollDashboardDevice(`Dashboard — ${browser}`);
    flash('success', `This browser is now a device (${dba.payload.cid}). The dashboard signs every request with its own key; revoking it signs this browser out.`);
    await refreshStrip(); await render();
  } catch (error) {
    flash('error', error.code === 'popup_blocked' ? 'The approval window was blocked. Allow pop-ups for this site and try again.' : error.message);
    button.disabled = false;
  }
}

function route() {
  const raw = location.hash.slice(1) || 'credentials';
  const [name, ...rest] = raw.split('/');
  return { name, arg: decodeURIComponent(rest.join('/')) };
}

function markNav(name) {
  for (const link of document.querySelectorAll('#app-nav a')) {
    if (link.hash === `#${name}`) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
  }
}

/** Render the page the #hash names; a slower earlier render that finishes late is discarded. */
export async function render() {
  clearInterval(state.pollTimer); state.pollTimer = null;
  const token = ++renderToken;
  const { name, arg } = route();
  const show = views[name] ? name : 'credentials';
  markNav(show === 'credential' ? 'credentials' : show);
  view.setAttribute('aria-busy', 'true');
  try {
    const content = await views[show](arg, () => token === renderToken);
    if (token === renderToken) replace(view, content);
  } catch (error) {
    if (token === renderToken && error.code === 'sign_in_gate_required') replace(view, await lockView(() => token === renderToken));
    else if (token === renderToken) replace(view, h('h1', {}, 'Something went wrong'), errorBox(error));
  } finally { if (token === renderToken) view.removeAttribute('aria-busy'); }
}
