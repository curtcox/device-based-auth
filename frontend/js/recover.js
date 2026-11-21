/**
 * Get back into an account after losing every device (STATUS B9, done/clerk_free_accounts.md
 * §3.5): this browser gets a new key in the dashboard's device slot, and a recovery code, a
 * passkey or another of the owner's devices, or the verified email address lets it in. A waiting
 * recovery (a gate's answer, or the email's wait) is kept with the key, so this page picks it up
 * again on the next visit.
 */
import { DBA } from '/sdk/dba.js';
import { h, $, replace, notice } from './html.js';

const root = $('#recover-root');
const dba = new DBA({ origin: location.origin, name: 'dashboard' });
const when = at => new Date(at).toLocaleString();

/** One way in: a titled form that starts a recovery with `fields`. */
function method(id, title, intro, fields, label, run) {
  const out = h('div', {});
  const form = h('form', { class: 'stack', id }, ...fields, h('div', { class: 'actions' }, h('button', { type: 'submit' }, label)), out);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const button = form.querySelector('button[type=submit]'); button.disabled = true;
    try { await run(form); } catch (error) { replace(out, notice('error', error.message)); button.disabled = false; }
  });
  return h('section', { class: 'panel' }, h('h2', {}, title), h('p', { class: 'muted' }, intro), form);
}

const accountField = () => h('label', {}, 'Account id', h('input', { name: 'account', required: true, autocomplete: 'username', placeholder: 'acct_… (on your recovery sheet and the Account page)', pattern: '[A-Za-z0-9_\\-]{1,128}' }));
const device = () => ({ name: 'Recovered browser' });

function choose() {
  replace(root,
    method('recover-code', 'With a recovery code', 'Each code on your recovery sheet works once.',
      [accountField(), h('label', {}, 'Recovery code', h('input', { name: 'code', required: true, autocomplete: 'off', placeholder: 'XXXX-XXXX-XXXX' }))], 'Recover',
      async form => { await dba.recover({ account: form.elements.account.value.trim(), code: form.elements.code.value.trim(), device: device(), replace: true }); done(); }),
    method('recover-gate', 'With a passkey or another device', 'A passkey, security key or another of your devices you added as a gate approves this browser, typing the number shown here.',
      [accountField()], 'Ask for approval',
      async form => { await dba.recover({ account: form.elements.account.value.trim(), via: 'gate', device: device(), replace: true }); waiting(); }),
    method('recover-email', 'By email', 'If your account verified this address, we email it a link. Once the link is used, this browser gets in after 72 hours unless one of your signed-in devices cancels it.',
      [h('label', {}, 'Email address', h('input', { name: 'email', type: 'email', required: true, autocomplete: 'email' }))], 'Email me a link',
      async form => { await dba.recover({ email: form.elements.email.value.trim(), via: 'email', device: device(), replace: true }); waiting(); }),
    h('p', { class: 'muted small' }, 'No way back in? Without codes, a gate or a verified address the account cannot be recovered. ', h('a', { href: '/signup.html' }, 'Create a new account'), '.'));
}

/** A recovery waits for a gate or for the email's wait to end. */
async function waiting() {
  const pending = dba.pending;
  const status = h('p', { id: 'recover-status' });
  const byEmail = pending.kind === 'recover-email';
  replace(root,
    byEmail
      ? notice('info', 'If that address belongs to an account, a link is on its way. After the link is used, this browser gets in after 72 hours; you can close this page and come back.')
      : [h('p', {}, 'Number ', h('strong', { class: 'mono', id: 'recover-number' }, pending.number), ' — type it wherever you approve.'),
        pending.approve_url ? h('p', {}, h('a', { href: pending.approve_url, target: '_blank', rel: 'noopener' }, 'Approve with a passkey or security key'), ' (opens the approval page).') : null,
        h('p', {}, 'Or approve on another of your devices.')],
    status,
    h('p', { class: 'muted small' }, h('button', { type: 'button', class: 'link', onclick: async () => { await dba.forget(); choose(); } }, 'Try another way')));
  const onPending = answer => replace(status, answer.stage === 'waiting' ? `The link was used. This browser gets in at ${when(answer.ready_at)}.` : byEmail ? 'Waiting for the emailed link to be used…' : 'Waiting for approval…');
  onPending({});
  try { await dba.finish({ timeoutMs: byEmail ? 12 * 3600000 : 15 * 60000, onPending }); done(); }
  catch (error) { replace(status, notice('error', `${error.message}. `)); }
}

function done() {
  replace(root,
    notice('success', h('strong', {}, 'You are back in. '), 'This browser is now a device on account ', h('span', { class: 'mono', id: 'recovered-account' }, dba.payload.acct), '.'),
    h('p', {}, 'For the next ten minutes you can, without confirming it is you: revoke the devices you lost, and make new recovery codes.'),
    h('div', { class: 'actions' }, h('a', { class: 'button', href: '/app.html#devices' }, 'Revoke lost devices'), h('a', { class: 'button secondary', href: '/app.html#account' }, 'Account page')));
}

async function start() {
  try {
    await dba.ready();
    if (dba.pending?.kind?.startsWith('recover-')) return waiting();
    if (dba.credential && dba.expiresIn() > 0) return replace(root, notice('info', 'This browser is already signed in to an account. '), h('div', { class: 'actions' }, h('a', { class: 'button', href: '/app.html' }, 'Open the dashboard')));
    choose();
  } catch (error) { replace(root, notice('error', error.message)); }
}

start();
