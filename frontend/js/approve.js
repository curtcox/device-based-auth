/**
 * Enrollment approval page, opened by a device (usually in a popup from the browser SDK, or a
 * link/QR code printed by the CLI). The signed enrollment ticket is the URL fragment, so it never
 * reaches server logs or Referer headers. Describing it is free and needs no sign-in; approving
 * or denying needs the account owner's session.
 */
import { api } from './api.js';
import { initAuth, renderSignIn, signedInLabel } from './auth.js';
import { h, $, replace, usd, money, date, relative, pretty, badge, notice, dl, field, describeKey } from './html.js';
import { validateGrants, describeGrant } from '/lib/verify/index.js';
import { preciseAreas, coarsenGrants, PRECISE_AREA_WARNING } from './places.js';

const ticket = location.hash.slice(1);
const root = $('#approve-root');
const signInArea = $('#approve-sign-in');
let info = null;

const UNITS = { minutes: 60, hours: 3600, days: 86400 };

function bestUnit(seconds) {
  if (seconds % 86400 === 0) return ['days', seconds / 86400];
  if (seconds % 3600 === 0) return ['hours', seconds / 3600];
  return ['minutes', Math.round(seconds / 60)];
}

/** Tell the page that opened us (the SDK listens for exactly this message). */
function tellOpener(status, result = {}) {
  if (!window.opener || !info?.return_origin) return false;
  try {
    window.opener.postMessage({ source: 'devicebasedauth', type: 'enrollment', status, credential: result.credential ?? null, cid: result.cid ?? null, enrollment_id: info.enrollment_id }, info.return_origin);
    return true;
  } catch { return false; }
}

function describe() {
  const catalog = new Map((info.audiences || []).flatMap(a => (a.actions || []).map(c => [c.action, c.description])));
  const [unit, amount] = bestUnit(info.lifetime_seconds);
  return h('div', { id: 'request-summary' },
    h('h2', {}, info.device?.name || 'Unnamed device', ' ', badge(info.status)),
    dl([
      ['Kind', info.device?.kind || 'other'],
      ['Key', describeKey(info.device)],
      ['Key thumbprint', h('span', { class: 'mono small' }, info.jkt)],
      ['Lifetime', `${amount} ${unit} (renewable)`],
      ['Price', h('strong', { id: 'price' }, money(info.price_microdollars))],
      ['Request expires', `${date(info.expires_at, true)} (${relative(info.expires_at)})`],
      info.return_origin ? ['Requested by', h('span', { class: 'mono' }, info.return_origin)] : null
    ]),
    h('h3', {}, 'For these sites'),
    info.audiences
      ? h('ul', {}, info.audiences.map(a => h('li', {}, h('strong', {}, a.name), a.first_party ? [' ', badge('active', 'first party')] : null, a.description ? ` — ${a.description}` : '')))
      : notice('error', `Unknown audience: ${info.unknown_audiences || info.aud.join(', ')}. Approving will fail until the site registers.`),
    h('h3', {}, 'It may'),
    h('ol', { class: 'english', id: 'grant-descriptions' }, info.grants.map((grant, i) => h('li', {},
      info.descriptions[i],
      h('ul', { class: 'small' }, grant.actions.map(action => h('li', {}, h('code', {}, action), catalog.get(action) ? ` — ${catalog.get(action)}` : action.endsWith(':*') ? ' — every action in this namespace' : '')))))),
    h('details', {}, h('summary', {}, 'Requested grants as JSON'), h('pre', { class: 'code' }, pretty(info.grants))));
}

function approvalForm() {
  const [unit, amount] = bestUnit(info.lifetime_seconds);
  const grantsText = pretty(info.grants);
  const preview = h('ul', { class: 'english', id: 'edited-descriptions' });
  const problems = h('div', { class: 'problems', role: 'alert' });
  const privacy = h('div', { id: 'area-privacy' });
  const form = h('form', { class: 'stack panel', id: 'approve-form' },
    h('h3', {}, 'Your decision'),
    h('p', { class: 'small muted' }, 'Signed in as ', signedInLabel(), '. The credential is charged to this account.'),
    h('label', {}, 'Device name', h('span', { class: 'hint' }, ' — shown in your dashboard and to the sites it visits'), h('input', { name: 'device_name', value: info.device?.name || '', maxlength: 100 })),
    h('div', { class: 'row' },
      h('label', {}, 'Lifetime', h('input', { name: 'lifetime', type: 'number', min: '1', step: '1', value: String(amount) })),
      h('label', {}, 'Unit', h('select', { name: 'unit' }, Object.keys(UNITS).map(u => h('option', { value: u, selected: u === unit }, u))))),
    h('details', {}, h('summary', {}, 'Edit the grants (narrow them, add limits)'),
      h('p', { class: 'hint' }, 'You can remove actions or add constraints such as time windows, places or a spend cap. The ', h('a', { href: '/tools/builder.html', target: '_blank', rel: 'noopener' }, 'grant builder'), ' writes them for you.'),
      h('textarea', { name: 'grants', rows: 10, spellcheck: 'false', value: grantsText }), problems, preview),
    privacy,
    confirmSection(),
    h('p', { class: 'small muted' }, 'The credential is readable by every site it is shown to, including the device name and any places in its grants.'),
    h('div', { class: 'actions' },
      h('button', { type: 'submit', name: 'decision', value: 'approve', id: 'approve-button' }, `Approve for ${usd(info.price_microdollars)}`),
      h('button', { type: 'button', class: 'secondary', id: 'deny-button' }, 'Deny')));
  const out = h('div', { id: 'approve-result' });
  const readGrants = () => {
    const text = form.elements.grants.value;
    if (text.trim() === grantsText.trim()) { replace(problems); replace(preview); return { grants: undefined }; }
    let grants;
    try { grants = JSON.parse(text); } catch { replace(problems, 'The grants are not valid JSON.'); replace(preview); return { error: true }; }
    const found = validateGrants(grants);
    replace(problems, found.length ? h('ul', {}, found.map(p => h('li', {}, p))) : null);
    replace(preview, found.length ? null : grants.map(g => h('li', {}, describeGrant(g))));
    return found.length ? { error: true } : { grants };
  };
  // Warn about circles small or precise enough to reveal a home or office, and offer coarser ones.
  const checkPlaces = () => {
    let grants; try { grants = JSON.parse(form.elements.grants.value); } catch { grants = null; }
    if (!preciseAreas(grants).length) { replace(privacy); return; }
    replace(privacy, notice('warn', h('p', {}, PRECISE_AREA_WARNING),
      h('button', { type: 'button', class: 'secondary small', id: 'coarsen-areas', onclick: () => {
        form.elements.grants.value = pretty(coarsenGrants(grants));
        form.querySelector('details').open = true;
        readGrants(); checkPlaces();
      } }, 'Use coarse areas (about 1 km)')));
  };
  form.elements.grants.addEventListener('input', () => { readGrants(); checkPlaces(); });
  checkPlaces();
  const finish = (status, result) => {
    const told = tellOpener(status, result);
    replace(root, describeOutcome(status, result, told));
  };
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const { grants, error } = readGrants();
    if (error) return;
    const lifetime = Math.round(Number(field(form, 'lifetime')) * UNITS[field(form, 'unit')]);
    const body = { request: ticket };
    const name = field(form, 'device_name');
    if (name && name !== info.device?.name) body.device_name = name;
    if (grants) body.grants = grants;
    if (lifetime !== info.lifetime_seconds) body.lifetime_seconds = lifetime;
    const confirm = readConfirm(form);
    if (confirm) body.confirm = confirm;
    for (const b of form.querySelectorAll('button')) b.disabled = true;
    try { finish('approved', await api('/api/v1/enrollments/approve', { method: 'POST', body })); }
    catch (err) { replace(out, failure(err)); for (const b of form.querySelectorAll('button')) b.disabled = false; }
  });
  form.querySelector('#deny-button').addEventListener('click', async () => {
    for (const b of form.querySelectorAll('button')) b.disabled = true;
    try { finish('denied', await api('/api/v1/enrollments/deny', { method: 'POST', body: { request: ticket } })); }
    catch (err) { replace(out, failure(err)); for (const b of form.querySelectorAll('button')) b.disabled = false; }
  });
  return [form, out];
}

/**
 * "Require periodic confirmation" (done/additional_gates.md §3.4): the owner may decide that this
 * device works only while one of their gates confirms it every so often. The gates are loaded
 * from the account; nothing is added unless the box is ticked.
 */
function confirmSection() {
  const select = h('select', { name: 'confirm_gate', id: 'confirm-gate', disabled: true }, h('option', { value: '' }, 'Loading your gates…'));
  const section = h('details', { id: 'confirm-section' }, h('summary', {}, 'Require periodic confirmation (optional)'),
    h('p', { class: 'hint' }, 'The device then works only while one of your gates has confirmed it recently: it asks, the gate approves, and sites check the confirmation, even offline. Each confirmation is charged to this account (see ', h('a', { href: '/pricing.html', target: '_blank', rel: 'noopener' }, 'Pricing'), '). Set up gates on the ', h('a', { href: '/app.html#gates', target: '_blank', rel: 'noopener' }, 'Gates page'), '.'),
    h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'confirm_on', id: 'confirm-on' }), ' Require confirmation'),
    h('label', {}, 'Confirmed by', select),
    h('div', { class: 'row' },
      h('label', {}, 'Every (hours)', h('input', { name: 'confirm_every', type: 'number', min: '1', max: '168', step: '1', value: '24' })),
      h('label', {}, 'Time to answer (minutes)', h('input', { name: 'confirm_timeout', type: 'number', min: '1', max: '60', step: '1', value: '5' })),
      h('label', {}, 'If nobody answers', h('select', { name: 'confirm_on_timeout' }, h('option', { value: 'deny' }, 'refuse'), h('option', { value: 'allow' }, 'confirm anyway')))));
  api('/api/v1/gates').then(({ items }) => {
    const usable = items.filter(g => (g.state ?? 'active') === 'active');
    replace(select, usable.map(g => h('option', { value: g.id }, `${g.label} (${g.kind})`)));
    select.disabled = false;
  }, () => { replace(select, h('option', { value: '' }, 'Could not load your gates')); });
  return section;
}

/** The confirm block from the form, or null when not asked for. */
function readConfirm(form) {
  if (!form.elements.confirm_on?.checked || !field(form, 'confirm_gate')) return null;
  const hours = Math.min(168, Math.max(1, Math.round(Number(field(form, 'confirm_every')) || 24)));
  const minutes = Math.min(60, Math.max(1, Math.round(Number(field(form, 'confirm_timeout')) || 5)));
  return { gates: [{ any: [field(form, 'confirm_gate')], timeout_s: minutes * 60, on_timeout: field(form, 'confirm_on_timeout') }], every_s: hours * 3600 };
}

function failure(error) {
  if (error.status === 402) {
    return notice('error', h('p', {}, h('strong', {}, 'Insufficient balance. '), `Approving costs ${money(error.details?.price_microdollars ?? info.price_microdollars)}`,
      error.details?.needed_microdollars ? `; you need ${money(error.details.needed_microdollars)} more` : '', '.'),
    h('p', {}, h('a', { href: '/app.html#account', target: '_blank', rel: 'noopener', id: 'add-credit' }, 'Add credit on your Account page'), ', then approve again. This request stays open until it expires.'));
  }
  if (error.status === 409) return notice('warn', h('strong', {}, 'Already decided. '), `${error.message}.`);
  if (error.status === 401) return notice('error', `${error.message}. Sign in again and retry.`);
  return notice('error', error.message, error.code ? h('span', { class: 'muted small' }, ` (${error.code})`) : null);
}

function describeOutcome(status, result, told) {
  if (status === 'approved') {
    return notice('success', h('h2', {}, 'Approved'),
      h('p', {}, told ? 'The device has its credential. You can close this window.' : 'Approved — the device will pick up its credential.'),
      h('p', { class: 'small' }, `Charged ${money(result.cost_microdollars ?? 0)}. `, h('a', { href: `/app.html#credential/${encodeURIComponent(result.cid)}` }, `View ${result.cid} in your dashboard`), '.'),
      told ? h('button', { type: 'button', class: 'secondary', onclick: () => window.close() }, 'Close window') : null);
  }
  return notice('warn', h('h2', {}, 'Denied'), h('p', {}, told ? 'The device was told. You can close this window.' : 'Denied. The device will not get a credential.'),
    told ? h('button', { type: 'button', class: 'secondary', onclick: () => window.close() }, 'Close window') : null);
}

async function boot() {
  if (!ticket) { replace(root, notice('error', 'This page needs an enrollment request. Open the link the device showed you.')); return; }
  const [{ mode }, described] = await Promise.all([initAuth(), api('/api/v1/enrollments/describe', { method: 'POST', body: { request: ticket }, auth: false }).catch(error => ({ error }))]);
  if (described.error) {
    replace(root, notice('error', described.error.code === 'invalid_enrollment' ? 'This enrollment request is invalid or has expired. Ask the device to start again.' : described.error.message));
    return;
  }
  info = described;
  const summary = describe();
  if (info.status !== 'pending') {
    replace(root, summary, notice('warn', `This request was already ${info.status}. Nothing more to do here.`));
    return;
  }
  const showForm = () => { replace(signInArea); replace(root, summary, approvalForm()); };
  if (mode) showForm();
  else {
    replace(root, summary);
    await renderSignIn(signInArea, { title: 'Sign in to approve', intro: 'Approving issues a credential from your account, so sign in first. This request stays open while you do.', onSignedIn: showForm });
  }
}

boot().catch(error => replace(root, notice('error', error.message)));
