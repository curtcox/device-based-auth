/**
 * OpenID Connect consent page. GET /oauth/authorize redirects here with the client's query string;
 * the signed-in user allows or denies, and POST /oauth/authorize answers with the URL to return to.
 * Two kinds of client: a site signing the user in (a registered audience), or an app (MCP client,
 * client_id dbamcp_…) asking to use the account through the MCP server like an API key.
 */
import { api } from './api.js';
import { initAuth, renderSignIn, signedInLabel, authMode, reauthenticate } from './auth.js';
import { h, $, replace, badge, notice, dl } from './html.js';

const PARAMS = ['client_id', 'redirect_uri', 'response_type', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method', 'resource'];
const MCP_PREFIX = 'dbamcp_';
const SCOPE_TEXT = {
  openid: 'Your devicebasedauth.org account id',
  profile: 'Your account id as your profile (no name or email is shared)',
  device: 'Which device you signed in with (device id, credential id and device name), when you use one'
};
const root = $('#authorize-root');
const query = new URLSearchParams(location.search);
const request = Object.fromEntries(PARAMS.filter(p => query.has(p)).map(p => [p, query.get(p)]));

/** Allow or deny, then follow the redirect the server returns. */
function decider(out) {
  return async approve => {
    for (const b of root.querySelectorAll('button')) b.disabled = true;
    try {
      const result = await api('/oauth/authorize', { method: 'POST', body: { ...request, approve } });
      replace(out, notice('info', approve ? 'Returning to the app…' : 'Returning without access…'));
      // Never follow anything but a web address, whatever the server says (a javascript: URL
      // would run on this origin).
      const next = new URL(result.redirect);
      if (next.protocol !== 'https:' && next.protocol !== 'http:') throw Object.assign(new Error('The app\'s return address is not a web address'), { code: 'invalid_redirect_uri' });
      location.assign(next.href);
    } catch (error) {
      const again = error.code === 'reverification_required' && authMode() === 'clerk'
        ? h('button', { type: 'button', class: 'link', onclick: () => reauthenticate() }, 'Sign in again') : null;
      replace(out, notice(again ? 'warn' : 'error', `${error.message}. `, again));
      for (const b of root.querySelectorAll('button')) b.disabled = false;
    }
  };
}

/** An MCP client asks to act for the account with some of its API scopes. */
async function appConsent() {
  const client = await api(`/oauth/client?client_id=${encodeURIComponent(request.client_id)}`, { auth: false }).catch(error => ({ error }));
  if (client.error) { replace(root, notice('error', 'This app registration is not valid. Ask the app to connect again.')); return; }
  if (!client.redirect_uris.includes(request.redirect_uri)) { replace(root, notice('error', `The return address ${request.redirect_uri} is not one this app registered. For your safety you will not be sent there.`)); return; }
  const asked = (request.scope || '').split(' ').filter(s => s && s !== 'openid' && s !== 'offline_access');
  const scopes = asked.length ? asked : client.default_scopes;
  const unknown = scopes.filter(s => !client.scopes[s]);
  const out = h('div', {});
  const decide = decider(out);
  replace(root,
    h('div', { class: 'panel' },
      h('h2', { id: 'client-name' }, client.client_name),
      h('p', {}, 'An app that calls itself ', h('strong', {}, client.client_name), ' wants to use your devicebasedauth.org account through the MCP server, the way an API key would. The name is the app’s own claim; check the return address below.'),
      h('h3', {}, 'It will be able to'),
      h('ul', { id: 'app-scopes' }, scopes.map(s => h('li', {}, h('code', {}, s), ` — ${client.scopes[s] || 'unknown permission (the request will be refused)'}`))),
      unknown.length ? notice('error', 'This request names permissions that do not exist and will be refused.') : null,
      h('p', { class: 'small muted' }, 'Reads it makes are paid from your balance like an API key’s. It appears under API keys in the dashboard, where you can revoke it at any time; it stops working at once.'),
      h('p', { class: 'small muted' }, 'Signed in as ', signedInLabel(), '. You will return to ', h('span', { class: 'mono', id: 'return-origin' }, new URL(request.redirect_uri).origin), '.'),
      h('div', { class: 'actions' },
        h('button', { type: 'button', id: 'allow', onclick: () => decide(true) }, `Allow ${client.client_name}`),
        h('button', { type: 'button', class: 'secondary', id: 'deny', onclick: () => decide(false) }, 'Cancel'))),
    out);
}

async function consent() {
  if (request.client_id.startsWith(MCP_PREFIX)) return appConsent();
  const [client, me] = await Promise.all([
    api(`/api/v1/audiences/${encodeURIComponent(request.client_id)}`, { auth: false }).catch(error => ({ error })),
    api('/api/v1/whoami')
  ]);
  if (client.error) { replace(root, notice('error', `Unknown site “${request.client_id}”. It has to register as an audience before it can use Sign in with devicebasedauth.org.`)); return; }
  if (!client.redirect_uris?.includes(request.redirect_uri)) { replace(root, notice('error', `The return address ${request.redirect_uri} is not registered for ${client.name}. For your safety you will not be sent there.`)); return; }
  const scopes = (request.scope || 'openid').split(' ').filter(Boolean);
  const shared = [['Account id', h('span', { class: 'mono', id: 'shared-account' }, me.account)]];
  if (me.kind === 'device') shared.push(['Device', [h('span', { class: 'mono', id: 'shared-device' }, me.device_id), h('span', { class: 'muted small' }, ` (credential ${me.cid})`)]]);
  const out = h('div', {});
  const decide = decider(out);
  replace(root,
    h('div', { class: 'panel' },
      h('h2', { id: 'client-name' }, client.name, client.first_party ? [' ', badge('active', 'first party')] : null),
      client.description ? h('p', { id: 'client-description' }, client.description) : null,
      h('p', {}, `${client.name} wants to sign you in with your devicebasedauth.org account.`),
      h('h3', {}, 'It will receive'),
      dl(shared),
      h('ul', { class: 'small' }, scopes.map(s => h('li', {}, h('code', {}, s), ` — ${SCOPE_TEXT[s] || 'unknown scope (the request will be refused)'}`))),
      h('p', { class: 'small muted' }, 'Signed in as ', signedInLabel(), authMode() === 'device' ? '. Because you are using a device credential, the site learns which device you used.' : '.'),
      h('p', { class: 'small muted' }, 'You will return to ', h('span', { class: 'mono' }, new URL(request.redirect_uri).origin), '.'),
      h('div', { class: 'actions' },
        h('button', { type: 'button', id: 'allow', onclick: () => decide(true) }, `Sign in to ${client.name}`),
        h('button', { type: 'button', class: 'secondary', id: 'deny', onclick: () => decide(false) }, 'Cancel'))),
    out);
}

async function boot() {
  if (!request.client_id || !request.redirect_uri) { replace(root, notice('error', 'This page is opened by a site that signs you in with devicebasedauth.org; the link is missing its client_id or redirect_uri.')); return; }
  try { new URL(request.redirect_uri); } catch { replace(root, notice('error', 'The redirect_uri is not a URL.')); return; }
  const { mode } = await initAuth();
  if (mode) return consent();
  replace(root, h('p', {}, request.client_id.startsWith(MCP_PREFIX) ? 'An app wants to use your devicebasedauth.org account.' : `${request.client_id} wants you to sign in with devicebasedauth.org.`));
  await renderSignIn($('#authorize-sign-in'), { title: 'Sign in first', onSignedIn: () => { replace($('#authorize-sign-in')); consent().catch(error => replace(root, notice('error', error.message))); } });
}

boot().catch(error => replace(root, notice('error', error.message)));
