/**
 * Dashboard pages for what the account has issued: credentials (list, export, detail), devices and
 * the panic button that revokes everything at once.
 */
import { api } from './api.js';
import { authMode } from './auth.js';
import { h, replace, date, relative, duration, jsonBlock, copyButton, badge, notice, table, dl, field, describeKey } from './html.js';
import { inspectCredential, evaluateGrants } from '/lib/verify/index.js';
import { credentialsCsv, credentialsJson } from './export.js';
import { state, enc, flash, errorBox, confirmButton, busy, render } from './dashboard.js';

// The list filter outlives navigation, so returning to the list keeps it.
const credentialFilter = { status: '', audience: '' };

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

/** Every credential matching the filter, page by page (up to 50 pages of 200). */
async function allCredentials(query) {
  const items = []; let cursor = null;
  for (let page = 0; page < 50; page++) {
    const params = new URLSearchParams({ ...Object.fromEntries(query), ...(cursor ? { cursor } : {}) });
    const data = await api(`/api/v1/credentials${params.size ? `?${params}` : ''}`);
    items.push(...data.items); cursor = data.next_cursor;
    if (!cursor) break;
  }
  return items;
}

/** Save text as a file in the browser's downloads. */
function download(name, type, text) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h('a', { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportButtons(query) {
  const stamp = () => new Date().toISOString().slice(0, 10);
  const run = format => async event => {
    const button = event.currentTarget; button.disabled = true;
    try {
      const items = await allCredentials(query);
      if (format === 'csv') download(`credentials-${stamp()}.csv`, 'text/csv;charset=utf-8', credentialsCsv(items));
      else download(`credentials-${stamp()}.json`, 'application/json', credentialsJson(items, { account: state.accountInfo?.account, filter: Object.fromEntries(query) }));
    } catch (error) { flash('error', `Export failed: ${error.message}`); }
    finally { button.disabled = false; }
  };
  return h('div', { class: 'actions' },
    h('button', { type: 'button', class: 'secondary small', onclick: run('csv') }, 'Export CSV'),
    h('button', { type: 'button', class: 'secondary small', onclick: run('json') }, 'Export JSON'),
    h('span', { class: 'muted small' }, 'Exports every credential matching the filter (no private keys or signed credentials).'));
}

/** Page #credentials: filterable list of issued credentials with CSV/JSON export. */
export async function credentials() {
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
  return [h('h1', {}, 'Credentials'), h('p', { class: 'muted' }, 'Every credential this account issued. Select one to read it, see its history, or revoke it.'), filter, data.items.length ? exportButtons(query) : null, body];
}

const EVENT_LABELS = { issued: 'Issued', renewed: 'Renewed', rotated: 'Rotated to a new key', recovered: 'Renewed after an issuer key was withdrawn (free)', revoked: 'Revoked' };

/** Page #credential/{cid}: one credential, its grants, decisions, confirmation and revoke. */
export async function credential(cid) {
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

  // Periodic confirmation (STATUS B7): when it was last confirmed, and "stop trusting now".
  const confirmedUntil = cred.confirmed_until ? cred.confirmed_until / 1000 : 0;
  const confirmation = cred.confirm && cred.state === 'active'
    ? h('div', { class: 'panel', id: 'confirmation-area' },
      h('p', {}, h('strong', {}, 'Periodic confirmation: '), `every ${duration(cred.confirm.every_s)}, by ${cred.confirm.gates.map(e => e.any.join(' or ')).join(', then ')}. `,
        confirmedUntil > Date.now() / 1000 ? `Confirmed until ${date(confirmedUntil, true)} (${relative(confirmedUntil)})${cred.confirmed_by_timeout ? ', by timeout' : ''}.` : 'Not confirmed now: sites refuse it until its gates confirm it again.'),
      confirmedUntil > Date.now() / 1000
        ? h('div', { class: 'actions' }, confirmButton('Stop trusting now', `Stop trusting “${name}” until its gates confirm it again? Online checks refuse it at once; offline verifiers accept its last confirmation until ${date(confirmedUntil, true)}. Revoke it to stop those too.`, async () => {
          await api(`/api/v1/credentials/${enc(cid)}/unconfirm`, { method: 'POST', body: {} });
          flash('success', `Stopped trusting ${cid} until it is confirmed again.`);
          await render();
        }, { confirmLabel: 'Yes, stop trusting it' }))
        : null)
    : null;

  const check = h('form', { class: 'row', id: 'check-action' },
    h('label', {}, 'Action', h('input', { name: 'action', placeholder: cred.grants[0]?.actions?.[0] || 'ns:verb', required: true })),
    h('label', {}, 'Resource (optional)', h('input', { name: 'resource' })),
    h('div', { class: 'shrink' }, h('button', { type: 'submit', class: 'secondary' }, 'Check now')));
  const checkResult = h('div', {});
  check.addEventListener('submit', event => {
    event.preventDefault();
    const result = evaluateGrants(cred.grants, { now: Math.floor(Date.now() / 1000), action: field(check, 'action'), resource: field(check, 'resource') || undefined, online: false, attestation: cred.device?.attestation });
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
      ['Device', [cred.device?.name || '—', h('span', { class: 'muted small' }, ` · ${cred.device?.kind || 'other'} · key: ${describeKey(cred.device)}`)]],
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
    confirmation,
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
      ? table(['When', 'Audience', 'Action', 'Resource', 'Country', 'Result'], decisions.items.map(d => [date(d.at), d.audience, h('span', { class: 'mono' }, d.action), d.resource ?? '—', d.country ?? '—', [badge(d.allow ? 'allow' : 'deny'), h('span', { class: 'muted small' }, ` ${d.code}`)]]))
      : h('p', { class: 'muted' }, 'No online decisions in the last 90 days. Offline verification is never reported back here.')
  ];
}

// ---------------------------------------------------------------------------------------------
// Devices

/** Page #devices: enrolled devices, each revocable with all its credentials. */
export async function devices() {
  const data = await api('/api/v1/devices');
  const rows = data.items.map(d => {
    const active = d.credentials.filter(c => c.state === 'active').length;
    return [
      [h('strong', {}, d.name || 'Unnamed device'), h('div', { class: 'muted small' }, `${d.kind || 'other'} · ${describeKey(d)}`)],
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
// Panic button

/** Page #panic: revoke every credential on the account, or every one for one audience. */
export async function panic() {
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
