/**
 * OpenID Connect consent page. GET /oauth/authorize redirects here with the client's query string;
 * the signed-in user allows or denies, and POST /oauth/authorize answers with the URL to return to.
 */
import { api } from './api.js';
import { initAuth, renderSignIn, signedInLabel, authMode } from './auth.js';
import { h, $, replace, badge, notice, dl } from './html.js';

const PARAMS = ['client_id', 'redirect_uri', 'response_type', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method'];
const SCOPE_TEXT = {
  openid: 'Your devicebasedauth.org account id',
  profile: 'Your account id as your profile (no name or email is shared)',
  device: 'Which device you signed in with (device id, credential id and device name), when you use one'
};
const root = $('#authorize-root');
const query = new URLSearchParams(location.search);
const request = Object.fromEntries(PARAMS.filter(p => query.has(p)).map(p => [p, query.get(p)]));

async function consent() {
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
  const decide = async approve => {
    for (const b of root.querySelectorAll('button')) b.disabled = true;
    try {
      const result = await api('/oauth/authorize', { method: 'POST', body: { ...request, approve } });
      replace(out, notice('info', approve ? 'Signing you in…' : 'Returning to the site…'));
      location.assign(result.redirect);
    } catch (error) {
      replace(out, notice('error', error.message));
      for (const b of root.querySelectorAll('button')) b.disabled = false;
    }
  };
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
  replace(root, h('p', {}, `${request.client_id} wants you to sign in with devicebasedauth.org.`));
  await renderSignIn($('#authorize-sign-in'), { title: 'Sign in first', onSignedIn: () => { replace($('#authorize-sign-in')); consent().catch(error => replace(root, notice('error', error.message))); } });
}

boot().catch(error => replace(root, notice('error', error.message)));
