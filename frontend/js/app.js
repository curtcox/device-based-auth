/**
 * The dashboard: hash-routed sections over the account API. Everything the API returns about
 * devices and credentials is untrusted (device names, grants, audience descriptions), so the UI
 * is built with h(), which only ever sets text and attributes.
 */
import { api } from './api.js';
import { initAuth, renderSignIn, signOut, authMode, signedInLabel, enrollDashboardDevice, preloadSdk, currentDevice } from './auth.js';
import { h, $, replace, usd, money, num, date, relative, duration, pretty, jsonBlock, copyButton, badge, notice, table, dl, field, splitList } from './html.js';
import { inspectCredential, validateGrants, evaluateGrants } from '/lib/verify/index.js';

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
const enc = encodeURIComponent;

let config = null;
let accountInfo = null;
let renderToken = 0;
let pollTimer = null;
const credentialFilter = { status: '', audience: '' };
const view = $('#view');

// ---------------------------------------------------------------------------------------------
// Shell: flash messages, errors, the account strip and routing

/** Show a message above the current section until the next navigation. */
function flash(kind, ...children) { replace($('#flash'), notice(kind, ...children)); $('#flash').scrollIntoView?.({ block: 'nearest' }); }
function clearFlash() { replace($('#flash')); }

/** Render an API error, with a way forward for the common cases. */
function errorBox(error) {
  if (error.status === 402) {
    const needed = error.details?.needed_microdollars;
    return notice('error', h('strong', {}, 'Insufficient balance. '), needed ? `This needs ${money(needed)} more. ` : '', h('a', { href: '#account' }, 'Add credit on the Account page'), '.');
  }
  if (error.status === 401) return notice('error', `${error.message}. `, h('button', { type: 'button', class: 'link', onclick: () => location.reload() }, 'Sign in again'));
  return notice('error', error.message || String(error), error.code ? h('span', { class: 'muted small' }, ` (${error.code})`) : null);
}

/** Two-step confirmation: the first click reveals a confirm button. */
function confirmButton(label, question, onConfirm, { confirmLabel = `Yes, ${label.toLowerCase()}` } = {}) {
  const wrap = h('span', { class: 'confirm' });
  const start = h('button', { type: 'button', class: 'danger small' }, label);
  const reset = () => replace(wrap, start);
  start.addEventListener('click', () => {
    const yes = h('button', { type: 'button', class: 'danger small' }, confirmLabel);
    yes.addEventListener('click', async () => {
      yes.disabled = true;
      try { await onConfirm(); } catch (error) { flash('error', error.message); reset(); }
    });
    replace(wrap, h('span', { class: 'small' }, question, ' '), yes, ' ', h('button', { type: 'button', class: 'secondary small', onclick: reset }, 'Cancel'));
  });
  return replace(wrap, start);
}

/** Disable a form's buttons while an async submit runs. */
async function busy(form, fn) {
  const buttons = [...form.querySelectorAll('button')];
  buttons.forEach(b => { b.disabled = true; });
  try { return await fn(); } finally { buttons.forEach(b => { b.disabled = false; }); }
}

async function refreshStrip() {
  const strip = $('#account-strip');
  try { accountInfo = await api('/api/v1/account'); } catch (error) { accountInfo = null; replace(strip, errorBox(error)); strip.hidden = false; return; }
  const device = currentDevice();
  const useDevice = h('button', { type: 'button', class: 'secondary small', id: 'use-device' }, 'Use this browser as a device for the dashboard');
  useDevice.addEventListener('click', () => enrollThisBrowser(useDevice));
  replace(strip,
    h('strong', { id: 'balance' }, `Balance ${usd(accountInfo.balance_microdollars)}`),
    h('span', { class: 'muted small' }, `${num(accountInfo.balance_microdollars)} µ$`),
    h('span', { class: 'small', id: 'signed-in-as' }, signedInLabel()),
    h('span', { class: 'spacer' }),
    device ? badge('active', 'Signed in with this device') : useDevice,
    h('a', { href: '#account', class: 'small' }, 'Add credit'),
    h('button', { type: 'button', class: 'secondary small', id: 'sign-out', onclick: () => signOut() }, device ? 'Sign out (revokes this browser)' : 'Sign out'));
  strip.hidden = false;
}

/** Stage B dogfooding: enroll this browser for dba:session and use it for every call. */
async function enrollThisBrowser(button) {
  button.disabled = true;
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  flash('info', 'Approve this browser in the window that just opened. You can rename it there.');
  try {
    const dba = await enrollDashboardDevice(`Dashboard — ${browser}`);
    flash('success', `This browser is now a device (${dba.payload.cid}). The dashboard signs every request with its own key; revoking it signs this browser out.`);
    await refreshStrip(); await render();
  } catch (error) {
    flash('error', error.code === 'popup_blocked' ? 'The approval window was blocked. Allow pop-ups for this site and try again.' : error.message);
    button.disabled = false;
  }
}

function route() {
  const raw = location.hash.slice(1) || 'credentials';
  const [name, ...rest] = raw.split('/');
  return { name, arg: decodeURIComponent(rest.join('/')) };
}

function markNav(name) {
  for (const link of document.querySelectorAll('#app-nav a')) {
    if (link.hash === `#${name}`) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
  }
}

async function render() {
  clearInterval(pollTimer); pollTimer = null;
  const token = ++renderToken;
  const { name, arg } = route();
  const show = VIEWS[name] ? name : 'credentials';
  markNav(show === 'credential' ? 'credentials' : show);
  view.setAttribute('aria-busy', 'true');
  try {
    const content = await VIEWS[show](arg, () => token === renderToken);
    if (token === renderToken) replace(view, content);
  } catch (error) {
    if (token === renderToken) replace(view, h('h1', {}, 'Something went wrong'), errorBox(error));
  } finally { if (token === renderToken) view.removeAttribute('aria-busy'); }
}

// ---------------------------------------------------------------------------------------------
// Credentials

function credentialRows(items) {
  return items.map(c => [
    h('a', { href: `#credential/${enc(c.cid)}`, class: 'cred-link' }, c.device?.name || 'Unnamed device'),
    c.aud.join(', '),
    badge(c.state),
    h('span', { title: date(c.exp, true) }, c.state === 'revoked' ? date(c.revoked_at) : `${date(c.exp, true)} (${relative(c.exp)})`),
    h('span', { class: 'mono small' }, c.cid)
  ]);
}

async function credentials() {
  const query = new URLSearchParams(Object.entries(credentialFilter).filter(([, v]) => v));
  const data = await api(`/api/v1/credentials${query.size ? `?${query}` : ''}`);
  const headers = ['Device', 'Audiences', 'State', 'Expires / revoked', 'Credential id'];
  const body = h('div', { id: 'credential-list' });
  const filter = h('form', { class: 'row', id: 'credential-filter' },
    h('label', {}, 'State', h('select', { name: 'status' }, ['', 'active', 'expired', 'revoked'].map(s => h('option', { value: s, selected: s === credentialFilter.status }, s || 'Any')))),
    h('label', {}, 'Audience', h('input', { name: 'audience', value: credentialFilter.audience, placeholder: 'e.g. hashbin.org' })),
    h('div', { class: 'shrink' }, h('button', { type: 'submit', class: 'secondary' }, 'Filter')));
  filter.addEventListener('submit', event => {
    event.preventDefault();
    credentialFilter.status = field(filter, 'status'); credentialFilter.audience = field(filter, 'audience');
    render();
  });
  if (!data.items.length) replace(body, h('p', { class: 'muted' }, 'No credentials yet. Enroll a device with the browser SDK or the CLI, or ', h('a', { href: '#issue' }, 'issue one'), '.'));
  else {
    const t = table(headers, credentialRows(data.items));
    replace(body, t);
    let cursor = data.next_cursor;
    if (cursor) {
      const more = h('button', { type: 'button', class: 'secondary' }, 'Load more');
      more.addEventListener('click', async () => {
        const next = await api(`/api/v1/credentials?${new URLSearchParams({ ...Object.fromEntries(query), cursor })}`);
        const tbody = t.querySelector('tbody');
        for (const cells of credentialRows(next.items)) tbody.append(h('tr', {}, cells.map((cell, i) => h('td', { 'data-label': headers[i] }, cell))));
        cursor = next.next_cursor; if (!cursor) more.remove();
      });
      body.append(more);
    }
  }
  return [h('h1', {}, 'Credentials'), h('p', { class: 'muted' }, 'Every credential this account issued. Select one to read it, see its history, or revoke it.'), filter, body];
}

const EVENT_LABELS = { issued: 'Issued', renewed: 'Renewed', rotated: 'Rotated to a new key', revoked: 'Revoked' };

async function credential(cid) {
  const [cred, decisions] = await Promise.all([
    api(`/api/v1/credentials/${enc(cid)}`),
    api(`/api/v1/credentials/${enc(cid)}/decisions`).catch(() => ({ items: [] }))
  ]);
  let decoded = null;
  try { decoded = inspectCredential(cred.jws); } catch { decoded = null; }
  const name = cred.device?.name || 'Unnamed device';
  const revoke = cred.state === 'revoked'
    ? notice('error', `Revoked ${date(cred.revoked_at)}${cred.revoked_reason ? ` — ${cred.revoked_reason}` : ''}.`)
    : h('div', { class: 'actions', id: 'revoke-area' }, confirmButton('Revoke', `Revoke “${name}”? It stops working everywhere within about a minute. This cannot be undone.`, async () => {
      const result = await api(`/api/v1/credentials/${enc(cid)}`, { method: 'DELETE' });
      flash('success', `Revoked ${result.count} credential${result.count === 1 ? '' : 's'}: ${result.revoked.join(', ')}.`);
      await render();
    }, { confirmLabel: 'Yes, revoke it' }));

  const check = h('form', { class: 'row', id: 'check-action' },
    h('label', {}, 'Action', h('input', { name: 'action', placeholder: cred.grants[0]?.actions?.[0] || 'ns:verb', required: true })),
    h('label', {}, 'Resource (optional)', h('input', { name: 'resource' })),
    h('div', { class: 'shrink' }, h('button', { type: 'submit', class: 'secondary' }, 'Check now')));
  const checkResult = h('div', {});
  check.addEventListener('submit', event => {
    event.preventDefault();
    const result = evaluateGrants(cred.grants, { now: Math.floor(Date.now() / 1000), action: field(check, 'action'), resource: field(check, 'resource') || undefined, online: false });
    replace(checkResult, h('p', {}, h('span', { class: `verdict ${result.allow ? 'allow' : 'deny'}` }, result.allow ? 'Allowed' : 'Denied'), ' ',
      h('span', { class: 'muted small' }, result.allow ? `by grant ${result.grant_index + 1}` : result.reasons.map((r, i) => `grant ${i + 1}: ${r.join(', ')}`).join('; ')),
      cred.state !== 'active' ? h('span', { class: 'muted small' }, ` — but the credential is ${cred.state}.`) : null));
  });
  const toPlayground = h('a', { href: '/tools/playground.html', class: 'button secondary small' }, 'Open in the policy playground');
  toPlayground.addEventListener('click', () => { try { sessionStorage.setItem('dba-playground-credential', cred.jws); } catch { /* ignore */ } });
  const toInspector = h('a', { href: '/tools/inspector.html', class: 'button secondary small' }, 'Open in the inspector');
  toInspector.addEventListener('click', () => { try { sessionStorage.setItem('dba-inspector-credential', cred.jws); } catch { /* ignore */ } });

  return [
    h('p', {}, h('a', { href: '#credentials' }, '← All credentials')),
    h('h1', {}, name, ' ', badge(cred.state)),
    dl([
      ['Credential id', h('span', { class: 'mono' }, cred.cid)],
      ['Version', `${cred.version ?? 1} (${cred.jti})`],
      ['Device', [cred.device?.name || '—', h('span', { class: 'muted small' }, ` · ${cred.device?.kind || 'other'} · key: ${cred.device?.key_protection || 'unknown'}`)]],
      ['Device id', h('a', { href: '#devices', class: 'mono' }, cred.device_id)],
      ['Key thumbprint', h('span', { class: 'mono small' }, cred.jkt)],
      ['Audiences', cred.aud.join(', ')],
      ['Issued', `${date(cred.iat, true)} (${cred.source || 'unknown'})`],
      ['Expires', `${date(cred.exp, true)} (${relative(cred.exp)})`],
      ['Lifetime', duration(cred.lifetime)],
      cred.parent_cid ? ['Delegated by', h('a', { href: `#credential/${enc(cred.parent_cid)}`, class: 'mono' }, cred.parent_cid)] : null,
      ['Status list', h('span', { class: 'mono small' }, `${decoded?.payload?.status?.status_list?.uri ?? ''} #${cred.status?.idx ?? '?'}`)]
    ]),
    revoke,
    h('h2', {}, 'What it allows'),
    h('ul', { class: 'english', id: 'grant-descriptions' }, (cred.descriptions || []).map(text => h('li', {}, text))),
    h('details', {}, h('summary', {}, 'Grants as JSON'), jsonBlock(cred.grants)),
    h('h3', {}, 'What can this device do right now?'),
    h('p', { class: 'muted small' }, 'Evaluated here in your browser with the same evaluator verifiers use (offline: no location, no usage counters).'),
    check, checkResult,
    h('div', { class: 'actions' }, toPlayground, toInspector),
    h('h2', {}, 'The credential'),
    h('p', { class: 'muted small' }, 'Credentials are not secret — they are useless without the device\'s private key — but they do show device names and places to every site they are presented to.'),
    h('div', { class: 'actions' }, copyButton('Copy credential', () => cred.jws, { id: 'copy-jws' })),
    h('pre', { class: 'code wrap', id: 'raw-jws' }, cred.jws),
    decoded ? [h('h3', {}, 'Decoded header'), jsonBlock(decoded.header), h('h3', {}, 'Decoded payload'), jsonBlock(decoded.payload, { id: 'decoded-payload' })] : notice('warn', 'The stored credential could not be decoded.'),
    h('h2', {}, 'History'),
    table(['When', 'Event', 'Detail'], (cred.events || []).slice().reverse().map(e => [date(e.at), EVENT_LABELS[e.type] || e.type, e.reason || e.source || e.jti || ''])),
    h('h2', {}, 'Online decisions'),
    decisions.items.length
      ? table(['When', 'Audience', 'Action', 'Resource', 'Result'], decisions.items.map(d => [date(d.at), d.audience, h('span', { class: 'mono' }, d.action), d.resource ?? '—', [badge(d.allow ? 'allow' : 'deny'), h('span', { class: 'muted small' }, ` ${d.code}`)]]))
      : h('p', { class: 'muted' }, 'No online decisions in the last 90 days. Offline verification is never reported back here.')
  ];
}

// ---------------------------------------------------------------------------------------------
// Devices

async function devices() {
  const data = await api('/api/v1/devices');
  const rows = data.items.map(d => {
    const active = d.credentials.filter(c => c.state === 'active').length;
    return [
      [h('strong', {}, d.name || 'Unnamed device'), h('div', { class: 'muted small' }, `${d.kind || 'other'} · ${d.key_protection || 'software'}`)],
      [h('div', { class: 'mono small' }, d.id), h('div', { class: 'mono small muted', title: 'Key thumbprint' }, d.jkt)],
      [`${active} active of ${d.credentials.length}`, h('div', { class: 'small' }, d.credentials.map((c, i) => [i ? ', ' : '', h('a', { href: `#credential/${enc(c.cid)}` }, c.cid)]))],
      date(d.created_at),
      d.revoked_at ? badge('revoked') : confirmButton('Revoke device', `Revoke every credential of “${d.name}”?`, async () => {
        const result = await api(`/api/v1/devices/${enc(d.id)}/revoke`, { method: 'POST', body: {} });
        flash('success', `Revoked the device and ${result.count} credential${result.count === 1 ? '' : 's'}.`);
        await render();
      }, { confirmLabel: 'Yes, revoke all' })
    ];
  });
  return [
    h('h1', {}, 'Devices'),
    h('p', { class: 'muted' }, 'A device is one key pair. Revoking a device revokes every credential bound to its key.'),
    rows.length ? table(['Device', 'Id and key', 'Credentials', 'First seen', ''], rows) : h('p', { class: 'muted' }, 'No devices yet.')
  ];
}

// ---------------------------------------------------------------------------------------------
// Step-up approvals

async function approvals(_arg, current) {
  const list = h('div', { id: 'approval-list' });
  const load = async () => {
    let data;
    try { data = await api('/api/v1/step-ups'); } catch (error) { replace(list, errorBox(error)); return; }
    if (!current()) return;
    if (!data.items.length) { replace(list, h('p', { class: 'muted' }, 'Nothing is waiting for your approval.')); return; }
    replace(list, table(['Device', 'Wants to', 'Requested', 'Decision'], data.items.map(s => [
      [h('strong', {}, s.device_name || 'Unnamed device'), h('div', { class: 'small' }, h('a', { href: `#credential/${enc(s.cid)}` }, s.cid))],
      [h('span', { class: 'mono' }, s.action), h('div', { class: 'small muted' }, `on ${s.audience}${s.resource ? ` · resource ${s.resource}` : ''}`)],
      [relative(Math.floor(s.requested_at / 1000)), h('div', { class: 'small muted' }, s.approved_at ? `approved, usable until ${date(s.approved_until)}` : `expires ${relative(Math.floor(s.expires_at / 1000))}`)],
      s.approved_at ? badge('approved') : h('div', { class: 'actions' },
        h('button', { type: 'button', class: 'small', onclick: () => decide(s.id, true) }, 'Approve'),
        h('button', { type: 'button', class: 'secondary small', onclick: () => decide(s.id, false) }, 'Deny'))
    ])));
  };
  const decide = async (id, approve) => {
    try { await api(`/api/v1/step-ups/${enc(id)}/${approve ? 'approve' : 'deny'}`, { method: 'POST', body: {} }); flash('success', approve ? 'Approved for the next use (within 5 minutes).' : 'Denied.'); }
    catch (error) { flash('error', error.message); }
    await load();
  };
  await load();
  pollTimer = setInterval(() => { if (current()) load(); }, 10000);
  return [
    h('h1', {}, 'Approvals'),
    h('p', { class: 'muted' }, 'Grants with require.step_up ask you to approve each use. Requests expire after 10 minutes; this list refreshes every 10 seconds.'),
    list
  ];
}

// ---------------------------------------------------------------------------------------------
// Issue by API

async function issue() {
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
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, `Issue for ${usd(config.prices.issue)}`), h('span', { class: 'muted small' }, `${num(config.prices.issue)} µ$, including its revocation.`)));
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
// Account

async function accountView() {
  const a = await api('/api/v1/account'); accountInfo = a;
  const kinds = Object.keys(a.month?.by_kind || {});
  const aggregates = Object.entries(a.today?.aggregates || {});
  const deposit = config.local ? localDeposit() : cardDeposit();
  const device = currentDevice();
  return [
    h('h1', {}, 'Account'),
    dl([
      ['Account id', h('span', { class: 'mono', id: 'account-id' }, a.account)],
      ['Balance', h('strong', { id: 'account-balance' }, money(a.balance_microdollars))],
      ['Created', date(a.created_at)],
      ['Signed in as', signedInLabel()]
    ]),
    h('h2', {}, `Spend this month (${a.month?.period || ''})`),
    kinds.length
      ? table(['Kind', 'Count', 'Amount'], [...kinds.map(k => [k, num(a.month.counts?.[k]), money(a.month.by_kind[k])]), [h('strong', {}, 'Total'), '', h('strong', {}, money(a.month.spent_microdollars))]])
      : h('p', { class: 'muted' }, 'Nothing spent this month.'),
    h('h3', {}, `Today's small charges (${a.today?.period || ''})`),
    h('p', { class: 'muted small' }, 'Reads, decisions, token exchanges and sign-ins are summed per day and written to the ledger as one row each.'),
    aggregates.length ? table(['Kind', 'Count', 'Amount'], aggregates.map(([k, v]) => [k, num(v.count), money(v.amount)])) : h('p', { class: 'muted' }, 'None today.'),
    h('h2', {}, 'Add credit'), deposit,
    h('h2', {}, 'Sign in with this browser'),
    device
      ? h('p', {}, 'This browser is signed in with its own device credential ', h('a', { href: `#credential/${enc(device.payload.cid)}` }, device.payload.cid), '. Every request is signed with a key that never leaves this browser. Signing out revokes it.')
      : h('p', {}, 'Make this browser a device: it gets a non-extractable key and a credential for devicebasedauth.org with ', h('code', {}, 'dba:session'), `. After that, the dashboard signs each request with that key instead of your sign-in session, and revoking the credential signs this browser out everywhere. Costs ${money(config.prices.issue)}.`)
  ];
}

function localDeposit() {
  const form = h('form', { class: 'row', id: 'deposit-form' },
    h('label', {}, 'Development credit (USD)', h('input', { name: 'dollars', type: 'number', min: '0.000001', max: '100', step: 'any', value: '5', required: true })),
    h('div', { class: 'shrink' }, h('button', { type: 'submit' }, 'Add development credit')));
  const out = h('div', {});
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      try {
        const amount = Math.round(Number(field(form, 'dollars')) * 1_000_000);
        const result = await api('/api/v1/dev/deposit', { method: 'POST', body: { amount_microdollars: amount } });
        flash('success', `Added ${money(amount)}. Balance ${usd(result.balance_microdollars)}.`);
        await refreshStrip(); await render();
      } catch (error) { replace(out, errorBox(error)); }
    });
  });
  return [notice('info', 'Local development mode: credit is free and not real money.'), form, out];
}

function cardDeposit() {
  const minimum = config.minimum_deposit_cents / 100;
  const form = h('form', { class: 'row', id: 'deposit-form' },
    h('label', {}, 'Credit to add (USD)', h('input', { name: 'dollars', type: 'number', min: String(minimum), max: '1000', step: '0.01', value: String(minimum), required: true })),
    h('div', { class: 'shrink' }, h('button', { type: 'submit', class: 'secondary' }, 'Review deposit')));
  const out = h('div', {});
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      const credit = Math.round(Number(field(form, 'dollars')) * 100);
      try {
        const quote = await api('/api/v1/payments/checkout?dry_run=1', { method: 'POST', body: { credit_cents: credit } });
        const key = crypto.randomUUID();
        const pay = h('button', { type: 'button' }, `Pay ${usd(quote.total_cents * 10000)} with a card`);
        pay.addEventListener('click', async () => {
          pay.disabled = true;
          try { const session = await api('/api/v1/payments/checkout', { method: 'POST', body: { credit_cents: credit }, idempotencyKey: key }); location.assign(session.url); }
          catch (error) { replace(out, errorBox(error)); }
        });
        replace(out, h('div', { class: 'panel' }, dl([
          ['Credit', usd(quote.credit_cents * 10000)],
          ['Card payment cost', [usd(quote.card_cost_cents * 10000), h('span', { class: 'muted small' }, ' (itemized, non-refundable)')]],
          ['Total charged', h('strong', {}, usd(quote.total_cents * 10000))]
        ]), pay, h('p', { class: 'muted small' }, 'Payment is handled by Stripe. Credit appears once Stripe confirms the payment.')));
      } catch (error) { replace(out, errorBox(error)); }
    });
  });
  return [h('p', { class: 'muted' }, `Prepaid, no subscription. Minimum ${usd(config.minimum_deposit_cents * 10000)}; new accounts may add at most $20 per payment in their first week. Unused credit never expires while your account exists.`), form, out];
}

// ---------------------------------------------------------------------------------------------
// Transactions and audit trail

async function transactions(arg) {
  const tab = arg === 'audit' ? 'audit' : 'ledger';
  const path = tab === 'audit' ? '/api/v1/audit' : '/api/v1/transactions';
  const headers = tab === 'audit' ? ['When', 'Event', 'Details'] : ['When', 'Kind', 'Amount', 'Detail'];
  const rows = items => items.map(t => tab === 'audit'
    ? (({ id: _id, type, at, ...rest }) => [date(at), h('span', { class: 'mono' }, type), h('span', { class: 'mono small' }, Object.entries(rest).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' · '))])(t)
    : [date(t.created_at), t.kind, h('span', { class: t.amount_microdollars >= 0 ? 'badge badge-ok' : '' }, `${t.amount_microdollars >= 0 ? '+' : '−'}${money(Math.abs(t.amount_microdollars))}`),
      t.aggregate ? `${num(t.count)} × for ${t.period}` : t.detail ? Object.entries(t.detail).map(([k, v]) => `${k}: ${v}`).join(' · ') : t.id]);
  const first = await api(path);
  const t = table(headers, rows(first.items));
  const wrap = h('div', {}, first.items.length ? t : h('p', { class: 'muted' }, 'Nothing yet.'));
  let cursor = first.next_cursor;
  if (cursor) {
    const more = h('button', { type: 'button', class: 'secondary' }, 'Load older');
    more.addEventListener('click', async () => {
      const next = await api(`${path}?cursor=${enc(cursor)}`);
      const tbody = t.querySelector('tbody');
      for (const cells of rows(next.items)) tbody.append(h('tr', {}, cells.map((cell, i) => h('td', { 'data-label': headers[i] }, cell))));
      cursor = next.next_cursor; if (!cursor) more.remove();
    });
    wrap.append(more);
  }
  return [
    h('h1', {}, 'Transactions'),
    h('div', { class: 'tabs' },
      h('a', { href: '#transactions', class: `button small ${tab === 'ledger' ? '' : 'secondary'}` }, 'Ledger'),
      h('a', { href: '#transactions/audit', class: `button small ${tab === 'audit' ? '' : 'secondary'}` }, 'Audit trail')),
    h('p', { class: 'muted' }, tab === 'audit' ? 'Every issue, renewal, revocation, key change and approval, newest first.' : 'Deposits and charges in micro-dollars, newest first.'),
    wrap
  ];
}

// ---------------------------------------------------------------------------------------------
// API keys

async function keys() {
  const data = await api('/api/v1/keys');
  const created = h('div', { id: 'new-key' });
  const form = h('form', { class: 'stack', id: 'key-form' },
    h('label', {}, 'Name', h('input', { name: 'name', value: 'API key', maxlength: 64, required: true })),
    h('fieldset', {}, h('legend', {}, 'Scopes'), Object.entries(SCOPES).map(([scope, text]) =>
      h('label', { class: 'check', title: text }, h('input', { type: 'checkbox', name: 'scope', value: scope, checked: scope === 'credentials:read' }), h('code', {}, scope))),
    h('p', { class: 'hint' }, 'Reads made with an API key cost ', usd(config.prices.read), ' each; issuing and decisions cost their usual price.')),
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
    h('strong', {}, k.name), h('span', { class: 'mono small' }, k.scopes.join(' ')), date(k.created_at),
    k.revoked_at ? badge('revoked') : confirmButton('Revoke', `Revoke “${k.name}”?`, async () => {
      await api(`/api/v1/keys/${enc(k.id)}`, { method: 'DELETE' });
      flash('success', `Revoked ${k.name}.`); await render();
    })
  ]);
  return [
    h('h1', {}, 'API keys'),
    h('p', { class: 'muted' }, 'Account API keys for servers and scripts that act for your account: listing credentials, issuing, revoking, and asking for online decisions for your audiences. For a key bound to one device, enroll the device instead.'),
    created,
    rows.length ? table(['Name', 'Scopes', 'Created', ''], rows) : h('p', { class: 'muted' }, 'No API keys yet.'),
    h('h2', {}, 'Create an API key'), form
  ];
}

// ---------------------------------------------------------------------------------------------
// Audiences

async function myAudiences(all) {
  // GET /api/v1/audiences?mine=1 needs the caller's account; fall back to reading each audience.
  try { return (await api('/api/v1/audiences?mine=1')).items; } catch { /* fall back */ }
  accountInfo ||= await api('/api/v1/account');
  const details = await Promise.all(all.filter(a => !a.first_party).map(a => api(`/api/v1/audiences/${enc(a.name)}`, { auth: false }).catch(() => null)));
  return details.filter(a => a && a.owner === accountInfo.account);
}

/** Online decisions, sign-ins and their cost per month (GET /api/v1/audiences/:name/usage). */
function audienceUsage(usage) {
  if (!usage) return h('p', { class: 'muted small' }, 'Usage could not be loaded.');
  const months = usage.items.filter((m, i) => i === 0 || m.decisions || m.logins);
  return [
    h('h4', {}, 'Verification and spend'),
    table(['Month', 'Online decisions', 'Sign-ins', 'Spend'], months.map(m => [m.period, num(m.decisions), num(m.logins), usd(m.spent_microdollars)]), { class: 'audience-usage' }),
    h('p', { class: 'muted small' }, `Online decisions cost ${usd(config.prices.decision)} each and sign-ins ${usd(config.prices.login)}, paid by you as the site's owner. Offline verification is free and never reported here.`)
  ];
}

async function audiences() {
  const all = (await api('/api/v1/audiences', { auth: false })).items;
  const mine = await myAudiences(all);
  accountInfo ||= await api('/api/v1/account');
  const usage = await Promise.all(mine.map(a => api(`/api/v1/audiences/${enc(a.name)}/usage`).catch(() => null)));
  const form = h('form', { class: 'stack', id: 'audience-form' },
    h('div', { class: 'row' },
      h('label', {}, 'Domain name', h('input', { name: 'name', required: true, placeholder: 'example.com', autocomplete: 'off' })),
      h('label', {}, 'Action namespace', h('input', { name: 'namespace', required: true, placeholder: 'example', pattern: '[a-z0-9\\-]{1,32}' }))),
    h('label', {}, 'Description', h('input', { name: 'description', maxlength: 300, placeholder: 'What your site does, shown on approval pages' })),
    h('label', {}, 'Action catalog', h('span', { class: 'hint' }, ' — one per line: the action, a space, then what it allows'),
      h('textarea', { name: 'catalog', rows: 5, required: true, spellcheck: 'false', placeholder: 'example:session Sign in to example.com\nexample:notes:read Read notes\nexample:notes:write Write notes' })),
    h('label', {}, 'OpenID Connect redirect URIs', h('span', { class: 'hint' }, ' — optional, one per line, https only'),
      h('textarea', { name: 'redirect_uris', rows: 2, spellcheck: 'false', placeholder: 'https://example.com/auth/dba/callback' })),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, `Register for ${usd(config.prices.audience)}`)));
  const out = h('div', {});
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      const catalog = field(form, 'catalog').split('\n').map(line => line.trim()).filter(Boolean).map(line => { const [action, ...rest] = line.split(/\s+/); return { action, description: rest.join(' ') }; });
      try {
        const registered = await api('/api/v1/audiences', { method: 'POST', body: { name: field(form, 'name'), namespace: field(form, 'namespace'), description: field(form, 'description'), catalog, redirect_uris: splitList(field(form, 'redirect_uris')) } });
        flash('success', `Registered ${registered.name}.`); await refreshStrip(); await render();
      } catch (error) { replace(out, errorBox(error)); }
    });
  });
  return [
    h('h1', {}, 'Audiences'),
    h('p', { class: 'muted' }, 'An audience is a site or API that accepts devicebasedauth.org credentials. It owns an action namespace and publishes a catalog of actions that grants can name; its OpenID Connect client id is its domain name.'),
    h('h2', {}, 'Yours'),
    mine.length ? mine.map((a, i) => h('div', { class: 'panel', dataset: { audience: a.name } }, h('h3', {}, a.name, ' ', h('span', { class: 'muted small' }, `${a.namespace}:*`)), h('p', {}, a.description || ''),
      table(['Action', 'Allows'], (a.catalog || []).map(c => [h('code', {}, c.action), c.description])),
      a.redirect_uris?.length ? h('p', { class: 'small' }, 'Redirect URIs: ', a.redirect_uris.join(', ')) : null,
      audienceUsage(usage[i]))) : h('p', { class: 'muted' }, 'You have not registered an audience.'),
    h('h2', {}, 'Register an audience'),
    notice('info', h('p', {}, h('strong', {}, 'Prove you control the domain. '), 'Before registering, publish this JSON at ', h('code', {}, 'https://<your domain>/.well-known/devicebasedauth.json'), ':'),
      h('pre', { class: 'code' }, JSON.stringify({ account: accountInfo.account })),
      config.local ? h('p', { class: 'small' }, 'Local mode skips the check for localhost and *.localhost names.') : null),
    form, out,
    h('h2', {}, 'All audiences'),
    table(['Name', 'Namespace', 'Description'], all.map(a => [[h('strong', {}, a.name), a.first_party ? [' ', badge('active', 'first party')] : null], h('code', {}, `${a.namespace}:*`), a.description || '']))
  ];
}

// ---------------------------------------------------------------------------------------------
// Panic button

async function panic() {
  const form = h('form', { class: 'stack', id: 'panic-form' },
    h('label', {}, 'Only for one audience (optional)', h('input', { name: 'audience', placeholder: 'leave empty for every audience' })),
    h('label', {}, 'Type revoke-all to confirm', h('input', { name: 'confirm', autocomplete: 'off', required: true, spellcheck: 'false' })),
    h('button', { type: 'submit', class: 'danger', disabled: true, id: 'panic-button' }, 'Revoke everything'));
  const out = h('div', {});
  form.elements.confirm.addEventListener('input', () => { form.querySelector('#panic-button').disabled = form.elements.confirm.value.trim() !== 'revoke-all'; });
  form.addEventListener('submit', event => {
    event.preventDefault();
    if (field(form, 'confirm') !== 'revoke-all') return;
    busy(form, async () => {
      const audience = field(form, 'audience');
      try {
        const result = await api('/api/v1/revoke-all', { method: 'POST', body: { confirm: 'revoke-all', ...(audience ? { audience } : {}) } });
        replace(out, notice('success', `Revoked ${result.count} credential${result.count === 1 ? '' : 's'}. Online checks refuse them now; offline verifiers within about a minute plus their cache time.`));
        form.reset(); form.querySelector('#panic-button').disabled = true;
      } catch (error) { replace(out, errorBox(error)); }
    });
  });
  return [
    h('h1', {}, 'Revoke everything'),
    h('div', { class: 'panel danger-zone' },
      h('p', {}, 'Lost a laptop? Leaked a key? This revokes every credential on the account (or every credential for one audience) at once. Revocation is free and cannot be undone; devices must enroll again.'),
      authMode() === 'device' ? notice('warn', 'This browser is signed in with a device credential, which will be revoked too. You will need to sign in again.') : null,
      form, out)
  ];
}

const VIEWS = { credentials, credential, devices, approvals, issue, account: accountView, transactions, keys, audiences, panic };

// ---------------------------------------------------------------------------------------------
// Boot

async function signedIn() {
  replace($('#sign-in-area'));
  $('#app-layout').hidden = false;
  await refreshStrip();
  await render();
}

async function boot() {
  preloadSdk();
  const state = await initAuth();
  config = state.config;
  window.addEventListener('hashchange', () => { clearFlash(); render(); });
  if (state.mode) return signedIn();
  await renderSignIn($('#sign-in-area'), { title: 'Sign in to your dashboard', intro: 'See every device and credential you issued, approve requests, and revoke anything.', onSignedIn: signedIn });
}

boot().catch(error => replace($('#sign-in-area'), errorBox(error)));
