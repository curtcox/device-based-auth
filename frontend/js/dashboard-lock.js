/**
 * The dashboard's sign-in gate (STATUS B7): a new sign-in waits on this page until a gate confirms
 * it, or a recovery code opens it.
 */
import { api } from './api.js';
import { h, replace, notice } from './html.js';
import { state, flash, errorBox, refreshStrip, render } from './dashboard.js';

/** Page shown while the sign-in gate holds this session: polls it, takes TOTP codes and recovery codes. */
export async function lockView(current) {
  const out = h('div', { id: 'lock-status' });
  const seconds = n => n % 60 === 0 ? `${n / 60} minute${n === 60 ? '' : 's'}` : `${n} seconds`;
  const confirm = async answer => {
    let result;
    try { result = await api('/api/v1/session/confirm', { method: 'POST', body: answer || {} }); } catch (error) { if (answer) flash('error', error.message); else replace(out, errorBox(error)); return; }
    if (!current()) return;
    if (result.status === 'confirmed') { clearInterval(state.pollTimer); state.pollTimer = null; flash('success', 'Sign-in confirmed.'); await refreshStrip(); await render(); return; }
    if (result.status === 'denied') { clearInterval(state.pollTimer); replace(out, notice('error', 'This sign-in was refused. Sign out, or use a recovery code.')); return; }
    const req = result.gate_request; const factors = req.factors?.entries || [];
    // Polls change nothing on the page while the request still waits (a half-typed code stays).
    const shape = JSON.stringify([req.id, req.entries.map(e => e.outcome)]);
    if (shape === shown && !answer) return;
    shown = shape;
    replace(out,
      h('p', {}, 'Request number ', h('strong', { class: 'mono', id: 'lock-number' }, req.number), ' — the approver types this number.'),
      h('ul', {}, req.entries.map(e => h('li', {}, e.on_timeout === 'allow' ? `allowed if nobody answers within ${seconds(e.timeout_s)}` : `denied if nobody answers within ${seconds(e.timeout_s)}`))),
      req.entries.map((e, i) => e.outcome || e.on_timeout === 'allow' ? null : (factors[i]?.gates || []).filter(g => g.kind === 'totp').map(g => {
        const input = h('input', { inputmode: 'numeric', maxlength: 6, autocomplete: 'one-time-code', 'aria-label': `Code from ${g.label}` });
        const form = h('form', { class: 'row' }, h('label', {}, `Code from “${g.label}”`, input), h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Confirm with code')));
        form.addEventListener('submit', event => { event.preventDefault(); confirm({ entry: i, gate: g.id, totp: { code: input.value.trim() } }); });
        return form;
      })));
    if (!state.pollTimer) state.pollTimer = setInterval(() => { if (current()) confirm(); else clearInterval(state.pollTimer); }, Math.max(2, req.retry_after || 2) * 1000);
  };
  let shown = null;
  const code = h('input', { name: 'recovery', autocomplete: 'off', 'aria-label': 'Recovery code', placeholder: 'XXXX-XXXX-XXXX' });
  const recover = h('form', { class: 'row', id: 'recovery-form' }, h('label', {}, 'Recovery code', code), h('div', { class: 'actions' }, h('button', { type: 'submit', class: 'secondary' }, 'Use recovery code')));
  recover.addEventListener('submit', async event => {
    event.preventDefault();
    try { const r = await api('/api/v1/session/recover', { method: 'POST', body: { code: code.value.trim() } }); flash('warn', `Opened with a recovery code; ${r.recovery_codes_left} left. Make new ones soon.`); await refreshStrip(); await render(); }
    catch (error) { flash('error', error.message); }
  });
  await confirm();
  return [
    h('h1', {}, 'Confirm this sign-in'),
    h('p', { class: 'muted' }, 'Your account asks a gate to confirm every dashboard sign-in. Until it does, you can only revoke credentials (the panic button always works).'),
    out,
    h('h2', {}, 'Lost your gate?'),
    recover,
    h('p', {}, h('a', { href: '#panic', class: 'danger-link' }, 'Revoke everything'))
  ];
}
