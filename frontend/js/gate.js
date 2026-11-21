/**
 * The gate approval page (STATUS B7, done/additional_gates.md §4.3), opened from a security
 * notice or a site's gate_request.approve_url. The signed link is the URL fragment, so it never
 * reaches server logs or Referer headers. Whoever holds the authenticator app or security key a
 * gate names answers here, signed in or not: the factor is the authentication. Everything shown
 * (device names, actions, resources) is untrusted and goes through h(), which only sets text.
 */
import { api } from './api.js';
import { h, $, replace, badge, notice, dl } from './html.js';
import { b64u, unb64u } from '/lib/verify/index.js';

const link = location.hash.slice(1);
const root = $('#gate-root');
const encoder = new TextEncoder();
let view = null;

const seconds = n => n % 3600 === 0 ? `${n / 3600} hour${n === 3600 ? '' : 's'}` : n % 60 === 0 ? `${n / 60} minute${n === 60 ? '' : 's'}` : `${n} seconds`;
const KIND = { owner: 'the account owner, from the dashboard', 'dba-device': 'a device, from its own app', totp: 'an authenticator app code', webauthn: 'a security key or passkey', webhook: 'an approval service' };

/** The challenge a security key signs for one answer (mirrors src/services/webauthn.js). */
async function challengeFor(entry, decision) {
  const text = `dba-gate-answer\n${view.id}\n${entry}\n${decision}\n${view.factors.salt}`;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text)));
}

/**
 * A sign-in, or a dashboard device confirming it is the owner (STATUS B9), shows a two-digit number;
 * the approver types it (number matching, plan §5.1).
 */
const TYPES_NUMBER = new Set(['sign_in', 'reverify']);
const numberInput = h('input', { id: 'gate-number-input', inputmode: 'numeric', maxlength: 2, pattern: '[0-9]{2}', 'aria-label': 'Number shown on the sign-in page' });

async function answer(entry, gate, decision, proof, status) {
  replace(status, h('span', { class: 'muted' }, 'Sending…'));
  try {
    const number = TYPES_NUMBER.has(view.purpose) && decision === 'allow' ? { number: numberInput.value.trim() } : {};
    view = { ...await api(`/api/v1/gate-links/${encodeURIComponent(link)}/answer`, { method: 'POST', auth: false, body: { entry, gate, decision, ...number, ...proof } }), factors: view.factors };
    render(notice('success', decision === 'allow' ? 'Approved. Thank you.' : 'Denied. The device will be refused.'));
  } catch (error) {
    replace(status, notice('error', error.message));
  }
}

async function withKey(entry, gate, decision, status) {
  if (!window.PublicKeyCredential) { replace(status, notice('error', 'This browser cannot use security keys.')); return; }
  try {
    const assertion = await navigator.credentials.get({ publicKey: {
      challenge: await challengeFor(entry, decision), rpId: view.factors.rp_id, timeout: 120000,
      allowCredentials: [{ type: 'public-key', id: unb64u(gate.credential_id) }], userVerification: gate.user_verification === 'required' ? 'required' : 'preferred'
    } });
    const r = assertion.response;
    await answer(entry, gate.id, decision, { webauthn: { credential_id: b64u(new Uint8Array(assertion.rawId)), clientDataJSON: b64u(new Uint8Array(r.clientDataJSON)), authenticatorData: b64u(new Uint8Array(r.authenticatorData)), signature: b64u(new Uint8Array(r.signature)) } }, status);
  } catch (error) {
    replace(status, notice('error', error.name === 'NotAllowedError' ? 'The security key did not answer (cancelled or timed out).' : error.message));
  }
}

function factorForm(entry, gate) {
  const status = h('div', { class: 'gate-status' });
  if (gate.kind === 'totp') {
    const input = h('input', { name: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', pattern: '[0-9]{6}', maxlength: 6, required: true, 'aria-label': `Code from ${gate.label || 'the authenticator app'}` });
    const form = h('form', { class: 'row gate-totp' },
      h('label', {}, `Code from “${gate.label || 'authenticator app'}”`, input),
      h('div', { class: 'actions' },
        h('button', { type: 'submit', value: 'allow' }, 'Approve'),
        h('button', { type: 'submit', value: 'deny', class: 'secondary' }, 'Deny')));
    form.addEventListener('submit', event => { event.preventDefault(); answer(entry, gate.id, event.submitter?.value === 'deny' ? 'deny' : 'allow', { totp: { code: input.value.trim() } }, status); });
    return h('div', {}, form, status);
  }
  return h('div', {},
    h('p', {}, `Security key “${gate.label || 'security key'}”`),
    h('div', { class: 'actions' },
      h('button', { type: 'button', onclick: () => withKey(entry, gate, 'allow', status) }, 'Approve with security key'),
      h('button', { type: 'button', class: 'secondary', onclick: () => withKey(entry, gate, 'deny', status) }, 'Deny with security key')),
    status);
}

function entryView(entry, index) {
  const gates = view.factors.entries[index]?.gates || [];
  const open = !entry.outcome && entry.expires_in > 0 && view.status === 'pending';
  const factorGates = gates.filter(g => (g.kind === 'totp' || g.kind === 'webauthn'));
  return h('section', { class: 'gate-entry' },
    h('h3', {}, view.entries.length > 1 ? `Approval ${index + 1} of ${view.entries.length}` : 'Approval', ' ', badge(entry.outcome === 'allow' ? 'approved' : entry.outcome === 'deny' ? 'denied' : 'pending', entry.outcome ? (entry.outcome === 'allow' ? 'approved' : 'denied') + (entry.by === 'timeout' ? ' (nobody answered)' : '') : 'waiting')),
    entry.on_timeout === 'allow'
      ? notice('warn', h('strong', {}, `Allowed if nobody answers within ${seconds(entry.timeout_s)}.`), ' Denying is the only way to stop it.')
      : h('p', { class: 'muted small' }, `Denied if nobody answers within ${seconds(entry.timeout_s)}.`),
    h('p', {}, 'Any one of these can answer: ', gates.map((g, i) => [i ? ', ' : '', h('strong', {}, g.label || g.id), ` (${KIND[g.kind] || g.kind})`])),
    open && factorGates.length ? factorGates.map(g => factorForm(index, g)) : null,
    open && !factorGates.length ? h('p', { class: 'muted' }, 'This approval is answered from the dashboard or on the approving device, not here.') : null,
    open ? h('p', { class: 'muted small' }, `Time left: about ${seconds(Math.max(1, entry.expires_in))}.`) : null);
}

function render(banner) {
  replace(root,
    banner || null,
    h('div', { id: 'gate-summary' },
      h('h2', {}, view.device_name || 'Unnamed device', ' ', badge(view.status === 'allowed' ? 'approved' : view.status === 'denied' ? 'denied' : 'pending', view.status)),
      dl([
        ...(view.purpose === 'sign_in' ? [['Wants to', `sign in to ${view.audience}`]]
          : view.purpose === 'reverify' ? [['Wants to', 'confirm it is you, to change account settings on the dashboard']]
          : [['Wants to', h('span', { class: 'mono' }, view.action)], ['On', view.resource ? h('span', { class: 'mono' }, view.resource) : 'any resource'], ['At', view.audience], ['Request number', h('strong', { class: 'mono' }, view.number)]]),
        ['Asked', new Date(view.created_at).toLocaleString()]
      ])),
    TYPES_NUMBER.has(view.purpose) && view.status === 'pending'
      ? h('label', { class: 'gate-number' }, view.purpose === 'reverify' ? 'Number shown on the dashboard ' : 'Number shown on the sign-in page ', numberInput, h('span', { class: 'hint' }, view.purpose === 'reverify' ? ' — if you did not just ask to confirm it is you, deny.' : ' — if you are not signing in right now, deny.'))
      : null,
    view.entries.map(entryView));
}

async function load() {
  if (!link) { replace(root, notice('error', 'This page needs the link from your notice or the site that sent you here.')); return; }
  try { view = await api(`/api/v1/gate-links/${encodeURIComponent(link)}`, { auth: false }); }
  catch (error) { replace(root, notice('error', error.status === 404 ? 'This request is over: it was answered, its time ran out, or the link is wrong.' : error.message)); return; }
  render();
}

load();
