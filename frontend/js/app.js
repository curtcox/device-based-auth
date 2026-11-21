/**
 * The dashboard: hash-routed sections over the account API. Everything the API returns about
 * devices and credentials is untrusted (device names, grants, audience descriptions), so the UI
 * is built with h(), which only ever sets text and attributes.
 *
 * This is the entry point: it maps each #hash to its page module and boots sign-in. The shared
 * shell (state, flash messages, the account strip and the router) is dashboard.js.
 */
import { initAuth, renderSignIn, preloadSdk } from './auth.js';
import { $, replace } from './html.js';
import { state, setViews, render, refreshStrip, clearFlash, errorBox } from './dashboard.js';
import { lockView } from './dashboard-lock.js';
import { credentials, credential, devices, panic } from './dashboard-credentials.js';
import { approvals, gatesView } from './dashboard-gates.js';
import { issue, keys, tokens } from './dashboard-api-access.js';
import { accountView, transactions } from './dashboard-account.js';
import { audiences } from './dashboard-audiences.js';

setViews({ credentials, credential, devices, approvals, gates: gatesView, issue, tokens, account: accountView, transactions, keys, audiences, panic }, lockView);

// ---------------------------------------------------------------------------------------------
// Boot

async function signedIn() {
  replace($('#sign-in-area'));
  $('#app-layout').hidden = false;
  await refreshStrip();
  await render();
}

async function boot() {
  preloadSdk();
  const auth = await initAuth();
  state.config = auth.config;
  window.addEventListener('hashchange', () => { clearFlash(); render(); });
  if (auth.mode) return signedIn();
  await renderSignIn($('#sign-in-area'), { title: 'Sign in to your dashboard', intro: 'See every device and credential you issued, approve requests, and revoke anything.', onSignedIn: signedIn });
}

boot().catch(error => replace($('#sign-in-area'), errorBox(error)));
