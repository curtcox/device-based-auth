/**
 * Dashboard pages for machine access: issuing a credential by API, account API keys and enrollment
 * tokens.
 */
import { api } from './api.js';
import { h, $, replace, usd, money, num, date, pretty, copyButton, badge, notice, table, field } from './html.js';
import { validateGrants } from '/lib/verify/index.js';
import { state, view, enc, flash, errorBox, confirmButton, busy, refreshStrip, render } from './dashboard.js';

/** Account API-key scopes (src/services/first-party.js DBA_SCOPES). */
const SCOPES = {
  'account:read': 'Read the account balance and monthly spend.',
  'transactions:read': 'Read the account ledger and audit trail.',
  'credentials:read': 'List and read devices, credentials and decisions.',
  'credentials:issue': 'Issue credentials (paid from the balance).',
  'credentials:revoke': 'Revoke credentials and devices.',
  'audiences:read': 'Read registered audiences.',
  'audiences:write': 'Register and change audiences you own.',
  authorize: 'Ask for online authorization decisions for audiences you own (paid from the balance).'
};

const DEVICE_KINDS = ['browser', 'phone', 'desktop', 'server', 'cli', 'agent', 'iot', 'other'];

// ---------------------------------------------------------------------------------------------
// Issue by API

/** Page #issue: issue a credential for a device public key, paid from the balance. */
export async function issue() {
  const audiences = (await api('/api/v1/audiences', { auth: false })).items;
  const example = pretty([{ actions: ['hashbin:content:write'], limits: { spend_usd_per_month: 5 } }]);
  const form = h('form', { class: 'stack', id: 'issue-form' },
    h('label', {}, 'Device public key (JWK)', h('span', { class: 'hint' }, ' — only the public key; the private key never leaves the device'),
      h('textarea', { name: 'public_jwk', rows: 5, required: true, placeholder: '{ "kty": "EC", "crv": "P-256", "x": "…", "y": "…" }', spellcheck: 'false' })),
    h('div', { class: 'row' },
      h('label', {}, 'Device name', h('input', { name: 'name', value: 'API-issued device', maxlength: 100 })),
      h('label', {}, 'Kind', h('select', { name: 'kind' }, DEVICE_KINDS.map(k => h('option', { value: k, selected: k === 'server' }, k)))),
      h('label', {}, 'Lifetime (days)', h('input', { name: 'days', type: 'number', min: '0.01', max: '400', step: 'any', value: '30' }))),
    h('fieldset', {}, h('legend', {}, 'Audiences'), audiences.map(a => h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'aud', value: a.name, checked: a.name === 'hashbin.org' }), a.name))),
    h('label', {}, 'Grants (JSON array)', h('span', { class: 'hint' }, ' — build one with the ', h('a', { href: '/tools/builder.html' }, 'grant builder')),
      h('textarea', { name: 'grants', rows: 8, required: true, spellcheck: 'false', value: example })),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, `Issue for ${usd(state.config.prices.issue)}`), h('span', { class: 'muted small' }, `${num(state.config.prices.issue)} µ$, including its revocation.`)));
  const result = h('div', { id: 'issue-result' });
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      replace(result);
      let jwk, grants;
      try { jwk = JSON.parse(field(form, 'public_jwk')); } catch { replace(result, notice('error', 'The public key is not valid JSON.')); return; }
      try { grants = JSON.parse(field(form, 'grants')); } catch { replace(result, notice('error', 'The grants are not valid JSON.')); return; }
      const problems = validateGrants(grants);
      if (problems.length) { replace(result, notice('error', h('strong', {}, 'The grants are not valid: '), h('ul', {}, problems.map(p => h('li', {}, p))))); return; }
      if (jwk.d) { replace(result, notice('error', 'That is a private key. Send only the public part (kty, crv, x, y).')); return; }
      const aud = [...form.querySelectorAll('input[name="aud"]:checked')].map(i => i.value);
      try {
        const issued = await api('/api/v1/credentials', { method: 'POST', body: { public_jwk: jwk, aud, grants, device: { name: field(form, 'name'), kind: field(form, 'kind') }, lifetime_seconds: Math.round(Number(field(form, 'days')) * 86400) } });
        replace(result, notice('success', h('p', {}, `Issued `, h('a', { href: `#credential/${enc(issued.cid)}` }, issued.cid), ` for ${money(issued.cost_microdollars)}.`),
          h('div', { class: 'actions' }, copyButton('Copy credential', () => issued.credential)), h('pre', { class: 'code wrap' }, issued.credential)));
        refreshStrip();
      } catch (error) { replace(result, errorBox(error)); }
    });
  });
  return [
    h('h1', {}, 'Issue a credential'),
    h('p', { class: 'muted' }, 'For servers, CI jobs and agents whose public key you already have. Devices that can open a browser should enroll themselves (browser SDK or ', h('code', {}, 'dba enroll'), ') so you approve them on the approval page.'),
    form, result
  ];
}


// ---------------------------------------------------------------------------------------------
// API keys

/** Page #keys: create and revoke account API keys. */
export async function keys() {
  const data = await api('/api/v1/keys');
  const created = h('div', { id: 'new-key' });
  const form = h('form', { class: 'stack', id: 'key-form' },
    h('label', {}, 'Name', h('input', { name: 'name', value: 'API key', maxlength: 64, required: true })),
    h('fieldset', {}, h('legend', {}, 'Scopes'), Object.entries(SCOPES).map(([scope, text]) =>
      h('label', { class: 'check', title: text }, h('input', { type: 'checkbox', name: 'scope', value: scope, checked: scope === 'credentials:read' }), h('code', {}, scope))),
    h('p', { class: 'hint' }, 'Reads made with an API key cost ', usd(state.config.prices.read), ' each; issuing and decisions cost their usual price.')),
    h('button', { type: 'submit' }, 'Create key'));
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      const scopes = [...form.querySelectorAll('input[name="scope"]:checked')].map(i => i.value);
      try {
        const key = await api('/api/v1/keys', { method: 'POST', body: { name: field(form, 'name'), scopes } });
        const list = await keys();
        replace(view, list);
        replace($('#new-key'), notice('warn', h('p', {}, h('strong', {}, 'Copy this secret now. '), 'It is shown once and only its digest is stored.'),
          h('div', { class: 'secret', id: 'key-secret' }, key.secret), h('div', { class: 'actions' }, copyButton('Copy secret', () => key.secret)),
          h('p', { class: 'small' }, 'Use it as ', h('code', {}, 'Authorization: ApiKey <secret>'), '.')));
      } catch (error) { replace(created, errorBox(error)); }
    });
  });
  const rows = data.items.map(k => [
    [h('strong', {}, k.name), k.kind === 'oauth' ? [' ', badge('active', 'connected app')] : null], h('span', { class: 'mono small' }, k.scopes.join(' ')), date(k.created_at),
    k.revoked_at ? badge('revoked') : confirmButton('Revoke', `Revoke “${k.name}”?`, async () => {
      await api(`/api/v1/keys/${enc(k.id)}`, { method: 'DELETE' });
      flash('success', `Revoked ${k.name}.`); await render();
    })
  ]);
  return [
    h('h1', {}, 'API keys'),
    h('p', { class: 'muted' }, 'Account API keys for servers and scripts that act for your account: listing credentials, issuing, revoking, and asking for online decisions for your audiences. For a key bound to one device, enroll the device instead. Apps you connected to the MCP server (OAuth) are listed here too; revoking one cuts it off at once.'),
    created,
    rows.length ? table(['Name', 'Scopes', 'Created', ''], rows) : h('p', { class: 'muted' }, 'No API keys yet.'),
    h('h2', {}, 'Create an API key'), form
  ];
}

// ---------------------------------------------------------------------------------------------
// Enrollment tokens (STATUS B2)

/** Page #tokens: create and revoke enrollment tokens (STATUS B2). */
export async function tokens() {
  const [data, audiences] = await Promise.all([api('/api/v1/enrollment-tokens'), api('/api/v1/audiences', { auth: false })]);
  const created = h('div', { id: 'new-token' });
  const form = h('form', { class: 'stack', id: 'token-form' },
    h('div', { class: 'row' },
      h('label', {}, 'Name', h('input', { name: 'name', value: 'Fleet', maxlength: 64, required: true })),
      h('label', {}, 'Devices (max uses)', h('input', { name: 'max_uses', type: 'number', min: '1', max: '10000', step: '1', value: '10', required: true })),
      h('label', {}, 'Valid for (days)', h('input', { name: 'days', type: 'number', min: '0.01', max: '90', step: 'any', value: '7', required: true })),
      h('label', {}, 'Credential lifetime (days)', h('input', { name: 'lifetime_days', type: 'number', min: '0.01', max: '400', step: 'any', value: '30', required: true }))),
    h('fieldset', {}, h('legend', {}, 'Audiences'), audiences.items.map(a => h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'aud', value: a.name, checked: a.name === 'hashbin.org' }), a.name))),
    h('label', {}, 'Grants (JSON array)', h('span', { class: 'hint' }, ' — every device gets these, or narrower ones it asks for; build them with the ', h('a', { href: '/tools/builder.html' }, 'grant builder')),
      h('textarea', { name: 'grants', rows: 6, required: true, spellcheck: 'false', value: pretty([{ actions: ['hashbin:content:write'] }]) })),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Create token'), h('span', { class: 'muted small' }, `Free to create; each device that enrolls costs ${usd(state.config.prices.issue)}.`)));
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      let grants;
      try { grants = JSON.parse(field(form, 'grants')); } catch { replace(created, notice('error', 'The grants are not valid JSON.')); return; }
      const problems = validateGrants(grants);
      if (problems.length) { replace(created, notice('error', h('strong', {}, 'The grants are not valid: '), h('ul', {}, problems.map(p => h('li', {}, p))))); return; }
      const aud = [...form.querySelectorAll('input[name="aud"]:checked')].map(i => i.value);
      try {
        const token = await api('/api/v1/enrollment-tokens', { method: 'POST', body: { name: field(form, 'name'), aud, grants, max_uses: Number(field(form, 'max_uses')), expires_in_days: Number(field(form, 'days')), lifetime_seconds: Math.round(Number(field(form, 'lifetime_days')) * 86400) } });
        replace(view, await tokens());
        replace($('#new-token'), notice('warn', h('p', {}, h('strong', {}, 'Copy this token now. '), 'It is shown once. Anyone holding it can enroll devices with these grants, charged to your balance, until it is used up, expires or you revoke it.'),
          h('div', { class: 'secret', id: 'token-secret' }, token.token), h('div', { class: 'actions' }, copyButton('Copy token', () => token.token)),
          h('p', { class: 'small' }, 'On each device: ', h('code', {}, 'DBA_ENROLLMENT_TOKEN=<token> dba enroll --name <device>'), ', or in a browser ', h('code', {}, 'dba.enroll({}, { enrollmentToken })'), '.')));
      } catch (error) { replace(created, errorBox(error)); }
    });
  });
  const rows = data.items.map(t => [
    h('strong', {}, t.name), h('span', { class: 'small' }, t.template.aud.join(', ')), `${num(t.uses)} / ${num(t.max_uses)}`, date(t.expires_at), badge(t.state === 'active' ? 'active' : 'revoked', t.state.replace('_', ' ')),
    t.state === 'active' ? confirmButton('Revoke', `Revoke “${t.name}”? Devices already enrolled keep their credentials.`, async () => {
      await api(`/api/v1/enrollment-tokens/${enc(t.id)}`, { method: 'DELETE' });
      flash('success', `Revoked ${t.name}.`); await render();
    }) : ''
  ]);
  return [
    h('h1', {}, 'Enrollment tokens'),
    h('p', { class: 'muted' }, 'Approve a fleet once: a token carries the audiences and grants you choose, for a number of devices, for a limited time. Each device still makes its own key and enrolls with the token instead of waiting for you to approve it.'),
    created,
    rows.length ? table(['Name', 'Audiences', 'Used', 'Expires', 'State', ''], rows, { class: 'token-list' }) : h('p', { class: 'muted' }, 'No enrollment tokens yet.'),
    h('h2', {}, 'Create an enrollment token'), form
  ];
}
