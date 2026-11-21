/**
 * The page links in devicebasedauth.org's own emails open (STATUS B9,
 * done/clerk_free_accounts.md §3.5): confirming a security email address (emv_… links) and
 * recovering an account by email (erl_… links). The signed link is the URL fragment, so it never
 * reaches server logs or Referer headers. Nothing happens until the reader presses the button, so
 * mail scanners that open links change nothing.
 */
import { api } from './api.js';
import { h, $, replace, notice } from './html.js';

const token = location.hash.slice(1);
const root = $('#email-link-root');
const when = at => new Date(at).toLocaleString();

function act(label, intro, run) {
  const status = h('div', { id: 'email-link-status' });
  const button = h('button', { type: 'button', onclick: async () => {
    button.disabled = true;
    try { replace(status, await run()); } catch (error) { replace(status, notice('error', error.message)); button.disabled = false; }
  } }, label);
  replace(root, ...intro, h('div', { class: 'actions' }, button), status);
}

if (token.startsWith('emv_')) {
  act('Confirm this address', [h('p', {}, 'Use this address for your account\'s security email and for recovering the account by email.')], async () => {
    const done = await api('/api/v1/account/email/verify', { method: 'POST', auth: false, body: { token } });
    return notice('success', h('strong', {}, 'Confirmed. '), `${done.security_email_address} now gets your security email and can recover the account.`);
  });
} else if (token.startsWith('erl_')) {
  act('Yes, recover my account', [
    notice('warn', h('strong', {}, 'Only continue if you asked to recover your account. '), 'The device that asked will get into your account after a waiting period. Until then, any of your signed-in devices or browsers can cancel it.')
  ], async () => {
    const done = await api('/api/v1/recover/email-link', { method: 'POST', auth: false, body: { token } });
    return notice('success', h('strong', {}, 'Recovery started. '), `The new device gets in at ${when(done.ready_at)}. Keep it open, or open it then; it finishes by itself.`);
  });
} else {
  replace(root, notice('error', 'This page needs the link from your email.'));
}
