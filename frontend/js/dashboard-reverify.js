/**
 * "Confirm it is you" for a dashboard signed in with this browser's own device credential
 * (STATUS B9, todo/clerk_free_accounts.md §3.4). Operations that need a recent sign-in (API keys,
 * devices with dba:* permissions, gates, recovery codes, raised limits) ask one of the owner's
 * gates instead of a password: a code from an authenticator app typed here, a passkey or security
 * key on the approval page, or another of the owner's devices typing the number shown here.
 */
import { api } from './api.js';
import { h, replace, notice } from './html.js';

/**
 * A panel that opens (or reads) a re-verification and polls it until a gate answers.
 * @param {{ onDone?: () => void }} options onDone runs once it is confirmed
 * @returns {Promise<HTMLElement>}
 */
export async function reverifyPanel({ onDone } = {}) {
  const panel = h('div', { class: 'stack', id: 'reverify-panel' });
  let timer = null; let shown = null;
  const stop = () => { clearInterval(timer); timer = null; };

  const ask = async answer => {
    if (!panel.isConnected && shown !== null) { stop(); return; }
    let result;
    try { result = await api('/api/v1/session/reverify', { method: 'POST', body: answer || {} }); }
    catch (error) {
      if (error.code === 'no_reverify_gate') { stop(); replace(panel, notice('warn', `${error.message}. `, h('a', { href: '#gates' }, 'Add one on the Gates page'), '.')); return; }
      if (answer) { replace(status, notice('error', error.message)); return; }
      stop(); replace(panel, notice('error', error.message)); return;
    }
    if (result.status === 'reverified') { stop(); replace(panel, notice('success', h('strong', {}, 'Confirmed. '), 'For the next 10 minutes this browser can do what needs a recent sign-in. Try again now.')); onDone?.(); return; }
    if (result.status === 'denied') { stop(); replace(panel, notice('error', 'Not confirmed: a gate refused, or nobody answered in time. ', h('button', { type: 'button', class: 'link', onclick: () => { shown = null; ask(); } }, 'Ask again'))); return; }
    const req = result.gate_request;
    const factors = req.factors?.entries?.[0]?.gates || [];
    // Polls leave the page alone while nothing changed, so a half-typed code stays.
    const shape = JSON.stringify([req.id, req.entries.map(e => e.outcome)]);
    if (shape === shown && !answer) return;
    shown = shape;
    const totp = factors.filter(g => g.kind === 'totp').map(g => {
      const input = h('input', { inputmode: 'numeric', maxlength: 6, autocomplete: 'one-time-code', 'aria-label': `Code from ${g.label}` });
      const form = h('form', { class: 'row' }, h('label', {}, `Code from “${g.label}”`, input), h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Confirm with code')));
      form.addEventListener('submit', event => { event.preventDefault(); ask({ gate: g.id, totp: { code: input.value.trim() } }); });
      return form;
    });
    const keys = factors.some(g => g.kind === 'webauthn') && req.approve_url
      ? h('p', {}, h('a', { href: req.approve_url, target: '_blank', rel: 'noopener' }, 'Confirm with a passkey or security key'), ` (opens the approval page; type the number ${req.number} there).`)
      : null;
    const devices = req.entries[0]?.gates.some(g => g.kind === 'dba-device')
      ? h('p', {}, 'Or approve on another of your devices, typing the number shown here.')
      : null;
    replace(panel,
      h('p', {}, 'Number ', h('strong', { class: 'mono', id: 'reverify-number' }, req.number), ' — whoever approves elsewhere types this number.'),
      ...totp, keys, devices, status);
    if (!timer) timer = setInterval(() => ask(), Math.max(2, req.retry_after || 2) * 1000);
  };
  const status = h('div', { class: 'reverify-status' });
  await ask();
  return panel;
}
