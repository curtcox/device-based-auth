/**
 * The Account page's security email and recovery sections (STATUS S8, B9;
 * todo/clerk_free_accounts.md §3.5, §3.7): the address security email goes to (from the sign-in
 * provider, or verified here), how the owner could get back in after losing every device, and
 * email recoveries waiting, which any signed-in browser or device may cancel.
 */
import { api } from './api.js';
import { h, replace, money, date, notice, table, field } from './html.js';
import { state, flash, errorBox, confirmButton, busy, render } from './dashboard.js';

const EMAIL_LEVELS = [
  ['all', 'Everything: takeover-sensitive events at once, other issuances in an hourly digest'],
  ['sensitive', 'Takeover-sensitive events only'],
  ['off', 'None']
];

/** Ask for a verification link to `address`. */
function addressForm(current) {
  const form = h('form', { class: 'row', id: 'email-address-form' },
    h('label', {}, current ? 'Use another address' : 'Email address', h('input', { name: 'email', type: 'email', autocomplete: 'email', required: true, maxlength: 254 })),
    h('div', { class: 'shrink' }, h('button', { type: 'submit' }, 'Send a link')));
  const out = h('div', {});
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      try {
        await api('/api/v1/account/email', { method: 'POST', body: { email: field(form, 'email') } });
        replace(out, notice('success', `We emailed a link to ${field(form, 'email')}. Open it within an hour to start using that address (${money(state.config.prices.notice)}).`));
      } catch (error) { replace(out, errorBox(error)); }
    });
  });
  return [form, out];
}

/** Security email: where it goes, how much of it, and changing or removing the address. */
export function emailSection(settings, a) {
  const intro = h('p', { class: 'muted' }, `An email when something that could hand your account to someone else happens (credentials that can act on your account, API keys, enrollment tokens, gates, recovery codes, raised limits) and, if you like, one digest an hour of other issuances. Each email costs ${money(state.config.prices.notice)}, charged when it is queued; with too little balance none is sent. An address verified here can also recover the account.`);
  if (!state.config.security_email) return [intro, h('p', { class: 'muted' }, 'Security email is not configured on this server.')];
  const address = a.security_email_address;
  const pending = a.security_email_pending ? h('p', { class: 'muted', id: 'security-email-pending' }, `Waiting for you to open the link sent to ${a.security_email_pending}.`) : null;
  if (!address) return [intro, h('p', { class: 'muted' }, 'No security email is sent: there is no address yet.'), pending, ...addressForm(false)];
  const form = h('form', { class: 'stack', id: 'email-form' },
    h('p', {}, 'Sent to ', h('strong', { id: 'security-email-address' }, address), h('span', { class: 'muted small' }, a.security_email_source === 'verified' ? ' (verified here; it can recover the account)' : ' (your sign-in’s primary address)')),
    h('label', {}, 'Security emails', h('select', { name: 'level' }, EMAIL_LEVELS.map(([value, label]) => h('option', { value, selected: settings.security_email === value }, label)))),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Save'),
      confirmButton('Remove address', `Stop sending security email to ${address}${a.security_email_source === 'verified' ? ' and stop it recovering the account' : ''}?`, async () => { await api('/api/v1/account/email', { method: 'DELETE' }); flash('success', 'Address removed.'); await render(); })));
  const out = h('div', {});
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      try {
        const saved = await api('/api/v1/account/settings', { method: 'PATCH', body: { security_email: field(form, 'level') } });
        replace(out, notice('success', saved.security_email === 'off' ? 'Saved. A last email says they were turned off.' : 'Saved.'));
      } catch (error) { replace(out, errorBox(error)); }
    });
  });
  return [intro, form, h('p', { class: 'muted small' }, 'Turning emails down or removing the address needs a recent sign-in, since it is what a thief would do first.'), out, pending, ...addressForm(true)];
}

/** Getting back in after losing every device, and email recoveries waiting to be cancelled. */
export function recoverySection(r) {
  const waiting = r.pending_email_recoveries.length
    ? notice('warn', h('strong', {}, 'Recovery by email in progress. '), 'If this is not you, cancel it.',
      table(['Device', 'Asked', 'Gets in', ''], r.pending_email_recoveries.map(e => [e.device_name, date(e.requested_at), e.ready_at ? date(e.ready_at) : 'after the emailed link is used',
        confirmButton('Cancel', `Cancel the recovery onto “${e.device_name}”?`, async () => { await api('/api/v1/account/recovery', { method: 'POST', body: { cancel_email_recovery: e.id } }); flash('success', 'Recovery cancelled.'); await render(); })])))
    : null;
  const ways = [
    r.recovery_codes_left ? `${r.recovery_codes_left} recovery code${r.recovery_codes_left === 1 ? '' : 's'}` : null,
    ...r.recovery_gates.map(g => `${g.kind === 'webauthn' ? 'passkey or security key' : 'device'} “${g.label}”`),
    r.recovery_email ? `email to ${r.recovery_email}` : null
  ].filter(Boolean);
  const risk = r.at_risk
    ? notice('error', h('strong', {}, 'No way back in. '), 'If you lose every signed-in device, you lose this account and its balance. Make recovery codes or add a passkey on the Gates page, verify an email address above, or ',
      h('button', { type: 'button', class: 'link', id: 'accept-no-recovery', onclick: async () => { await api('/api/v1/account/recovery', { method: 'POST', body: { acknowledge_no_recovery: true } }); await render(); } }, 'accept that'), '.')
    : null;
  return [waiting, risk, h('p', { id: 'recovery-ways' }, ways.length ? `You can get back in with: ${ways.join('; ')}.` : 'You accepted having no way back in.')];
}
