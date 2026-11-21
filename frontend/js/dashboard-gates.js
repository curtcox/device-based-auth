/**
 * Dashboard pages for gates (STATUS B7): the Approvals page lists gate requests, the Gates page sets
 * up the devices and factors that answer them and the sign-in gates.
 */
import { api } from './api.js';
import { h, replace, usd, relative, copyButton, badge, notice, table, field } from './html.js';
import { b64u, unb64u } from '/lib/verify/index.js';
import { qrSvg } from './qr.js';
import { state, enc, flash, errorBox, confirmButton, busy, refreshStrip, render } from './dashboard.js';

// ---------------------------------------------------------------------------------------------
// Approvals: every gate request still waiting or approved (step-up is the owner gate, STATUS B7)

/** What a gate request asks for, in words. */
function requestSubject(r) {
  switch (r.purpose) {
    case 'authorize': return [h('span', { class: 'mono' }, r.action), h('div', { class: 'small muted' }, `on ${r.audience}${r.resource ? ` · resource ${r.resource}` : ''}`)];
    case 'confirm': return [h('span', {}, 'Confirm this credential'), h('div', { class: 'small muted' }, 'periodic confirmation: it stops working without one')];
    case 'sign_in': return [h('span', {}, `Sign in to ${r.audience}`), h('div', { class: 'small muted' }, 'with Sign in with devicebasedauth.org')];
    case 'dashboard': return [h('span', {}, 'Sign in to this dashboard'), h('div', { class: 'small muted' }, 'a new session waits for its sign-in gate')];
    case 'settings': return [h('span', {}, 'Loosen your sign-in gates'), h('div', { class: 'small muted' }, 'a change waits for your current gates')];
    case 'reverify': return [h('span', {}, 'Confirm it is you'), h('div', { class: 'small muted' }, 'a dashboard device asks before changing account settings (it shows a number to type)')];
    default: return [h('span', {}, r.purpose)];
  }
}

/** Page #approvals: gate requests waiting or approved, polled while open. */
export async function approvals(_arg, current) {
  const list = h('div', { id: 'approval-list' });
  let labels = new Map();
  const gateName = g => g.id === 'owner' ? 'You (this dashboard)' : `${labels.get(g.id) || g.id} (${GATE_KINDS[g.kind] || g.kind})`;
  const entryCell = (r, e, index) => {
    const waiting = r.status === 'pending' && !e.answer && !e.outcome && e.expires_in > 0;
    const owner = e.gates.some(g => g.id === 'owner');
    const factor = e.gates.some(g => g.kind === 'totp' || g.kind === 'webauthn');
    return h('div', { class: 'stack small', dataset: { entry: index } },
      h('div', {}, e.gates.map(gateName).join(' or ')),
      h('div', { class: 'muted' }, e.answer ? `${e.answer.decision === 'allow' ? 'Allowed' : 'Denied'} by ${e.answer.gate === 'owner' ? 'you' : labels.get(e.answer.gate) || e.answer.gate}`
        : e.outcome ? ({ timeout: `${e.outcome === 'allow' ? 'Allowed' : 'Denied'}: nobody answered`, by_timeout_refused: 'Denied: nobody answered, and the site refuses allows by timeout' }[e.by] || (e.outcome === 'allow' ? 'Allowed' : 'Denied'))
          : waiting ? `${e.on_timeout === 'allow' ? 'Allowed' : 'Denied'} ${relative(Math.floor(Date.now() / 1000) + e.expires_in)} unless answered` : 'No longer waiting'),
      waiting && owner ? h('div', { class: 'actions' },
        h('button', { type: 'button', class: 'small', onclick: () => decide(r, index, true) }, 'Approve'),
        h('button', { type: 'button', class: 'secondary small', onclick: () => decide(r, index, false) }, 'Deny')) : null,
      waiting && factor && r.approve_url ? h('a', { href: r.approve_url, class: 'button small secondary' }, 'Answer with a code or security key') : null);
  };
  const load = async () => {
    let data;
    try { data = await api('/api/v1/gate-requests'); } catch (error) { replace(list, errorBox(error)); return; }
    if (!current()) return;
    if (!data.items.length) { replace(list, h('p', { class: 'muted' }, 'Nothing is waiting for your approval.')); return; }
    replace(list, table(['Asked by', 'Wants to', 'Requested', 'Gates', 'Status'], data.items.map(r => [
      [h('strong', {}, r.device_name || (r.purpose === 'dashboard' || r.purpose === 'settings' ? 'You' : 'Unnamed device')), r.cid ? h('div', { class: 'small' }, h('a', { href: `#credential/${enc(r.cid)}` }, r.cid)) : null],
      requestSubject(r),
      relative(Math.floor(r.created_at / 1000)),
      r.entries.map((e, i) => entryCell(r, e, i)),
      [badge(r.status), r.by_timeout ? h('div', { class: 'small muted' }, 'by timeout') : null]
    ])));
  };
  const decide = async (r, entry, approve) => {
    try {
      const answered = await api(`/api/v1/gate-requests/${enc(r.id)}/answer`, { method: 'POST', body: { entry, gate: 'owner', decision: approve ? 'allow' : 'deny' } });
      flash('success', !approve ? 'Denied.' : answered.status === 'allowed' ? 'Approved for the next use.' : 'Approved; other gates must still answer.');
    } catch (error) { flash('error', error.message); }
    await load();
  };
  try { labels = new Map((await api('/api/v1/gates')).items.map(g => [g.id, g.label])); } catch { /* ids are shown instead */ }
  await load();
  state.pollTimer = setInterval(() => { if (current()) load(); }, 10000);
  return [
    h('h1', {}, 'Approvals'),
    h('p', { class: 'muted' }, 'Requests waiting for your gates: grants with require.gates or require.step_up, periodic confirmations, and sign-ins with sign-in gates. Approve those that name you; codes and security keys answer on their approval page; devices and services answer on their own. This list refreshes every 10 seconds.'),
    list
  ];
}

// ---------------------------------------------------------------------------------------------
// Gates (STATUS B7): devices and factors that approve requests named in require.gates

const GATE_KINDS = { owner: 'Account owner', 'dba-device': 'Device', totp: 'Authenticator app (TOTP)', webauthn: 'Security key or passkey', webhook: 'Approval service (webhook)', duo: 'Duo Push', 'okta-verify': 'Okta Verify push' };

/** Send a webhook gate a signed gate.test message and say what its service answered. */
function testGateButton(gate) {
  const button = h('button', { type: 'button', class: 'secondary small', dataset: { test: gate.id } }, `Test (${usd(state.config.prices.read)})`);
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      const r = await api(`/api/v1/gates/${enc(gate.id)}/test`, { method: 'POST', body: {} });
      if (r.delivered) flash('success', `“${gate.label}” answered HTTP ${r.status}${r.decision ? ` with “${r.decision}” (a test decides nothing)` : ''}.`);
      else flash('error', `“${gate.label}” did not answer: ${r.status ? `HTTP ${r.status}` : r.error || 'no answer'}. It must answer 2xx within 10 seconds, without redirecting.`);
      await refreshStrip();
    } catch (error) { flash('error', error.message); }
    finally { button.disabled = false; }
  });
  return button;
}

/** Page #gates: add, set up, test and delete gates; sign-in gates and recovery codes. */
export async function gatesView(_arg, current) {
  const [gates, devices] = await Promise.all([api('/api/v1/gates'), api('/api/v1/devices')]);
  const setup = h('div', { id: 'gate-setup' });
  const rows = gates.items.map(g => [
    [h('strong', {}, g.label), h('div', { class: 'small muted' }, GATE_KINDS[g.kind] || g.kind)],
    h('span', { class: 'mono small' }, g.id),
    g.builtin ? badge('active', 'built in') : badge(g.state === 'active' ? 'active' : 'pending', g.state),
    g.builtin ? '' : [g.kind === 'webhook' ? testGateButton(g) : null, confirmButton('Delete', `Delete gate “${g.label}”? Grants that name only this gate will deny.`, async () => {
      await api(`/api/v1/gates/${enc(g.id)}`, { method: 'DELETE' });
      flash('success', `Deleted gate “${g.label}”.`); await render();
    }, { confirmLabel: 'Yes, delete' })]
  ]);
  const label = (name, value) => h('label', {}, 'Label', h('input', { name, required: true, maxlength: 80, value }));
  const deviceForm = h('form', { class: 'stack', id: 'gate-device-form' },
    h('h3', {}, 'A device'),
    h('p', { class: 'muted small' }, 'One of your devices answers in its own app (the CLI, the SDK, the mobile sample). Its credential needs dba:approvals:answer.'),
    label('label', 'My phone'),
    h('label', {}, 'Device', h('select', { name: 'device_id', required: true }, devices.items.filter(d => !d.revoked_at).map(d => h('option', { value: d.id }, `${d.name || 'Unnamed device'} (${d.id})`)))),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Add device gate')));
  deviceForm.addEventListener('submit', event => {
    event.preventDefault();
    busy(deviceForm, async () => {
      try { const g = await api('/api/v1/gates', { method: 'POST', body: { kind: 'dba-device', label: field(deviceForm, 'label'), device_id: field(deviceForm, 'device_id') } }); flash('success', `Added gate ${g.id}.`); await render(); }
      catch (error) { flash('error', error.message); }
    });
  });
  const totpForm = h('form', { class: 'stack', id: 'gate-totp-form' },
    h('h3', {}, 'An authenticator app'),
    h('p', { class: 'muted small' }, 'Google Authenticator, Authy, 1Password, Microsoft Authenticator… Whoever holds it answers with its 6-digit code.'),
    label('label', 'Authenticator app'),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Add authenticator app')));
  totpForm.addEventListener('submit', event => {
    event.preventDefault();
    busy(totpForm, async () => {
      let g;
      try { g = await api('/api/v1/gates', { method: 'POST', body: { kind: 'totp', label: field(totpForm, 'label') } }); } catch (error) { flash('error', error.message); return; }
      const code = h('input', { name: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 6, required: true });
      const confirm = h('form', { class: 'row', id: 'gate-totp-confirm' }, h('label', {}, 'Code from the app', code), h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Finish')));
      confirm.addEventListener('submit', async e => {
        e.preventDefault();
        try { await api(`/api/v1/gates/${enc(g.id)}/activate`, { method: 'POST', body: { code: code.value.trim() } }); flash('success', `“${g.label}” is set up.`); await render(); }
        catch (error) { flash('error', error.message); }
      });
      replace(setup, notice('info',
        h('p', {}, h('strong', {}, 'Add this to your authenticator app now. '), 'It is shown only once. Scan the code with the app, or type the secret.'),
        h('div', { id: 'totp-qr' }, qrSvg(g.setup.otpauth_uri, { label: 'QR code for your authenticator app' })),
        h('p', {}, 'Secret: ', h('code', { id: 'totp-secret' }, g.setup.secret), ' ', copyButton('Copy', () => g.setup.secret)),
        h('p', {}, 'On a phone: ', h('a', { href: g.setup.otpauth_uri }, 'open in authenticator app')),
        confirm));
    });
  });
  const keyForm = h('form', { class: 'stack', id: 'gate-key-form' },
    h('h3', {}, 'A security key or passkey'),
    h('p', { class: 'muted small' }, 'YubiKey, Titan, or a passkey on this device. Whoever holds it answers by touching it.'),
    label('label', 'Security key'),
    h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'uv' }), 'Also require its PIN or biometric'),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Register security key')));
  keyForm.addEventListener('submit', event => {
    event.preventDefault();
    busy(keyForm, async () => {
      if (!window.PublicKeyCredential) { flash('error', 'This browser cannot use security keys.'); return; }
      try {
        const g = await api('/api/v1/gates', { method: 'POST', body: { kind: 'webauthn', label: field(keyForm, 'label'), user_verification: keyForm.elements.uv.checked ? 'required' : 'preferred' } });
        const o = g.setup.public_key;
        const made = await navigator.credentials.create({ publicKey: { ...o, challenge: unb64u(o.challenge), user: { ...o.user, id: unb64u(o.user.id) }, excludeCredentials: o.excludeCredentials.map(c => ({ ...c, id: unb64u(c.id) })) } });
        await api(`/api/v1/gates/${enc(g.id)}/activate`, { method: 'POST', body: { registration: { clientDataJSON: b64u(new Uint8Array(made.response.clientDataJSON)), attestationObject: b64u(new Uint8Array(made.response.attestationObject)) } } });
        flash('success', `“${g.label}” is registered.`); await render();
      } catch (error) { flash('error', error.name === 'NotAllowedError' ? 'The security key did not answer (cancelled or timed out).' : error.message); }
    });
  });
  const hookForm = h('form', { class: 'stack', id: 'gate-webhook-form' },
    h('h3', {}, 'Your approval service'),
    h('p', { class: 'muted small' }, 'An https endpoint you run. It receives each request signed by devicebasedauth.org and answers allow or deny (spec/events.md §6).'),
    label('label', 'Approval service'),
    h('label', {}, 'URL', h('input', { name: 'url', type: 'url', required: true, placeholder: 'https://approvals.example.com/dba' })),
    h('label', {}, 'Public key (JWK) for late answers', h('textarea', { name: 'public_jwk', rows: 3, required: true, spellcheck: 'false', placeholder: '{ "kty": "EC", "crv": "P-256", "x": "…", "y": "…" }' })),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Add approval service')));
  hookForm.addEventListener('submit', event => {
    event.preventDefault();
    busy(hookForm, async () => {
      let jwk; try { jwk = JSON.parse(field(hookForm, 'public_jwk')); } catch { flash('error', 'The public key must be a JSON JWK.'); return; }
      try { const g = await api('/api/v1/gates', { method: 'POST', body: { kind: 'webhook', label: field(hookForm, 'label'), url: field(hookForm, 'url'), public_jwk: jwk } }); flash('success', `Added gate ${g.id}.`); await render(); }
      catch (error) { flash('error', error.message); }
    });
  });
  // Duo Push and Okta Verify (STATUS B7 G8): the secret is sealed on the server and never shown again.
  const vendorForm = (id, title, intro, fields, kind, button) => {
    const form = h('form', { class: 'stack', id }, h('h3', {}, title), h('p', { class: 'muted small' }, intro), label('label', title), fields, h('div', { class: 'actions' }, h('button', { type: 'submit' }, button)));
    form.addEventListener('submit', event => {
      event.preventDefault();
      busy(form, async () => {
        const body = { kind, label: field(form, 'label') };
        for (const el of form.querySelectorAll('input[data-key]')) body[el.dataset.key] = el.value.trim();
        try { const g = await api('/api/v1/gates', { method: 'POST', body }); flash('success', `Added gate ${g.id}.`); await render(); }
        catch (error) { flash('error', error.message); }
      });
    });
    return form;
  };
  const input = (text, key, attrs = {}) => h('label', {}, text, h('input', { dataset: { key }, required: true, autocomplete: 'off', spellcheck: 'false', ...attrs }));
  const duoForm = vendorForm('gate-duo-form', 'Duo Push', 'A push to a Duo Mobile user, through a Duo Auth API application you create in the Duo Admin Panel.', [
    input('API hostname', 'api_host', { placeholder: 'api-XXXXXXXX.duosecurity.com' }),
    input('Integration key', 'integration_key', { placeholder: 'DI…' }),
    input('Secret key', 'secret_key', { type: 'password' }),
    input('Duo username', 'username')
  ], 'duo', 'Add Duo Push');
  const oktaForm = vendorForm('gate-okta-form', 'Okta Verify', 'A push to an Okta user\'s Okta Verify app, through an API token from your Okta org.', [
    input('Org URL', 'org_url', { type: 'url', placeholder: 'https://example.okta.com' }),
    input('API token', 'api_token', { type: 'password' }),
    input('User id', 'user_id', { placeholder: '00u…' }),
    input('Okta Verify push factor id', 'factor_id', { placeholder: 'opf…' })
  ], 'okta-verify', 'Add Okta Verify');
  const signIn = await api('/api/v1/settings/sign-in-gates');
  const settingsBox = h('textarea', { name: 'settings', rows: 8, spellcheck: 'false', value: JSON.stringify({ default: signIn.default, audiences: signIn.audiences, dashboard: signIn.dashboard }, null, 2) });
  const settingsForm = h('form', { class: 'stack', id: 'sign-in-gates-form' },
    h('label', {}, 'Sign-in gates (JSON)', h('span', { class: 'hint' }, ' — default and per site for Sign in with devicebasedauth.org, and dashboard for this dashboard; entries as in require.gates'), settingsBox),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Save sign-in gates')));
  settingsForm.addEventListener('submit', event => {
    event.preventDefault();
    busy(settingsForm, async () => {
      let body; try { body = JSON.parse(settingsBox.value); } catch { flash('error', 'Sign-in gates must be JSON.'); return; }
      try {
        const r = await api('/api/v1/settings/sign-in-gates', { method: 'PUT', body });
        // Loosening (removing gates, or letting more pass) waits for the current gates (202).
        if (r.status === 'pending') flash('info', `This change loosens your sign-in gates, so their current gates must approve it (request ${r.gate_request.id}, number ${r.gate_request.number ?? '—'})${r.gate_request.approve_url ? ' — your browsers were sent an approval link' : ''}. Save again once approved.`);
        else flash('success', 'Saved sign-in gates.');
      }
      catch (error) { flash('error', error.message); }
    });
  });
  const codesOut = h('div', { id: 'recovery-codes' });
  const makeCodes = h('button', { type: 'button', class: 'secondary', onclick: async () => {
    try {
      const r = await api('/api/v1/settings/recovery-codes', { method: 'POST', body: {} });
      replace(codesOut, notice('warn', h('p', {}, h('strong', {}, 'Save these now; they are shown only once. '), 'Each opens the dashboard once if your gate is lost.'), h('pre', { class: 'code' }, r.codes.join('\n')), copyButton('Copy codes', () => r.codes.join('\n'))));
    } catch (error) { flash('error', error.message); }
  } }, 'Make recovery codes');
  if (!current()) return [];
  return [
    h('h1', {}, 'Gates'),
    h('p', { class: 'muted' }, 'A gate approves or refuses uses of grants that name it in require.gates. Changing gates needs a recent sign-in and is announced to your browsers.'),
    table(['Gate', 'Id', 'State', ''], rows, { id: 'gate-list' }),
    setup,
    h('h2', {}, 'Add a gate'),
    h('div', { class: 'grid' }, deviceForm, totpForm, keyForm, hookForm, duoForm, oktaForm),
    h('h2', {}, 'Sign-in gates'),
    settingsForm,
    h('h3', {}, 'Recovery codes'),
    h('p', { class: 'muted small' }, 'A dashboard gate that denies on timeout needs recovery codes first, so a lost phone cannot lock you out.'),
    makeCodes, codesOut
  ];
}
