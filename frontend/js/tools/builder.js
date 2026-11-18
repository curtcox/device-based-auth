/**
 * Grant builder: a form → one grant (spec/evaluation.md vocabulary v1), validated and described
 * live with the verify library, plus copyable JSON, `dba enroll` and browser SDK snippets.
 * Audience catalogs come from the public audience registry and are rendered as text only.
 */
import { api } from '../api.js';
import { h, $, replace, notice, copyButton, pretty } from '../html.js';
import { validateGrant, describeGrant, DAYS } from '/lib/verify/index.js';
import { timeZones, localZone, zonedToEpoch, listOrUndefined, numberOrUndefined } from './common.js';
import { isPreciseArea, coarsenArea, PRECISE_AREA_WARNING } from '../places.js';

const form = $('#builder-form');
const catalogBox = $('#catalog');
let audiences = [];
const catalogs = new Map();
const DAY_LABELS = { sun: 'Sun', mon: 'Mon', tue: 'Tue', wed: 'Wed', thu: 'Thu', fri: 'Fri', sat: 'Sat' };

function windowRow({ days = ['mon', 'tue', 'wed', 'thu', 'fri'], from = '09:00', to = '17:00' } = {}) {
  const row = h('div', { class: 'window-row' },
    h('div', { class: 'days' }, DAYS.map(d => h('label', {}, h('input', { type: 'checkbox', value: d, checked: days.includes(d), class: 'day' }), DAY_LABELS[d]))),
    h('label', {}, 'from ', h('input', { type: 'time', class: 'from', value: from, 'aria-label': 'From' })),
    h('label', {}, 'to ', h('input', { type: 'time', class: 'to', value: to, 'aria-label': 'To' })),
    h('button', { type: 'button', class: 'secondary small', onclick: () => { row.remove(); build(); } }, 'Remove'));
  return row;
}

function areaRow({ lat = '', lon = '', radius_m = 50000 } = {}) {
  const row = h('div', { class: 'window-row' },
    h('label', {}, 'Latitude ', h('input', { type: 'number', step: 'any', class: 'lat', value: lat, min: -90, max: 90 })),
    h('label', {}, 'Longitude ', h('input', { type: 'number', step: 'any', class: 'lon', value: lon, min: -180, max: 180 })),
    h('label', {}, 'Radius (m) ', h('input', { type: 'number', step: '1', class: 'radius', value: radius_m, min: 10 })),
    h('button', { type: 'button', class: 'secondary small', onclick: () => { row.remove(); build(); } }, 'Remove'));
  return row;
}

/** Read the form into one grant object. */
export function readGrant() {
  const actions = [...catalogBox.querySelectorAll('input[type="checkbox"]:checked')].map(i => i.value);
  for (const extra of listOrUndefined(form.elements.extra_actions.value) || []) if (!actions.includes(extra)) actions.push(extra);
  const grant = { actions };
  const resources = listOrUndefined(form.elements.resources.value);
  if (resources) grant.resources = resources;
  const tz = form.elements.tz.value;
  const when = {};
  if (form.elements.use_windows.checked) {
    const windows = [...document.querySelectorAll('#windows .window-row')].map(row => {
      const days = [...row.querySelectorAll('.day:checked')].map(i => i.value);
      const w = {};
      if (days.length !== 7) w.days = days;
      w.from = row.querySelector('.from').value; w.to = row.querySelector('.to').value === '00:00' ? '24:00' : row.querySelector('.to').value;
      return w;
    });
    if (windows.length) { when.tz = tz; when.windows = windows; }
  }
  const nb = zonedToEpoch(form.elements.not_before.value, tz); const na = zonedToEpoch(form.elements.not_after.value, tz);
  if (nb !== null) when.not_before = nb;
  if (na !== null) when.not_after = na;
  if (Object.keys(when).length) grant.when = when;
  const source = form.elements.source.value;
  if (source) {
    const where = { source };
    const countries = listOrUndefined(form.elements.countries.value.toUpperCase()); if (countries) where.countries = countries;
    const regions = listOrUndefined(form.elements.regions.value.toUpperCase()); if (regions) where.regions = regions;
    const areas = [...document.querySelectorAll('#areas .window-row')].map(row => ({ lat: numberOrUndefined(row.querySelector('.lat').value), lon: numberOrUndefined(row.querySelector('.lon').value), radius_m: numberOrUndefined(row.querySelector('.radius').value) }));
    if (areas.length) where.areas = areas;
    const networks = listOrUndefined(form.elements.networks.value); if (networks) where.networks = networks;
    grant.where = where;
  }
  const limits = {};
  const count = numberOrUndefined(form.elements.uses_count.value);
  if (count !== undefined) limits.uses = { count, per: form.elements.uses_per.value };
  const spend = numberOrUndefined(form.elements.spend.value);
  if (spend !== undefined) limits.spend_usd_per_month = spend;
  if (Object.keys(limits).length) grant.limits = limits;
  const require = {};
  if (form.elements.online.checked) require.online = true;
  if (form.elements.step_up.checked) require.step_up = true;
  if (form.elements.attestation.value) require.attestation = form.elements.attestation.value;
  if (form.elements.verified_boot.checked) require.verified_boot = true;
  if (Object.keys(require).length) grant.require = require;
  return grant;
}

/** The audiences a credential with this grant must name: one per action namespace. */
function audiencesFor(grant) {
  const names = new Set();
  for (const action of grant.actions) {
    const match = audiences.find(a => a.namespace === action.split(':')[0]);
    if (match) names.add(match.name);
  }
  if (!names.size && form.elements.audience.value) names.add(form.elements.audience.value);
  return [...names];
}

const areaOf = row => ({ lat: numberOrUndefined(row.querySelector('.lat').value), lon: numberOrUndefined(row.querySelector('.lon').value), radius_m: numberOrUndefined(row.querySelector('.radius').value) });

const preciseRows = () => form.elements.source.value ? [...document.querySelectorAll('#areas .window-row')].filter(row => isPreciseArea(areaOf(row))) : [];

/**
 * Warn about circles that pinpoint a place (they are readable by every site), and offer coarser
 * ones. Rendered only when the state changes, so a click is never lost to a re-render on blur.
 */
function showAreaPrivacy() {
  const box = $('#area-privacy');
  const precise = preciseRows().length > 0;
  if (precise === !!box.firstChild) return;
  if (!precise) { replace(box); return; }
  replace(box, notice('warn', h('p', {}, PRECISE_AREA_WARNING),
    h('button', { type: 'button', class: 'secondary small', id: 'coarsen-areas', onclick: () => {
      for (const row of preciseRows()) {
        const coarse = coarsenArea(areaOf(row));
        row.querySelector('.lat').value = coarse.lat; row.querySelector('.lon').value = coarse.lon; row.querySelector('.radius').value = coarse.radius_m;
      }
      build();
    } }, 'Use coarse areas (about 1 km)')));
}

const shellQuote = text => `'${text.replaceAll("'", "'\\''")}'`;

function build() {
  const grant = readGrant();
  const problems = validateGrant(grant, 'grant');
  const json = pretty(grant);
  $('#grant-json').textContent = json;
  replace($('#validation'), problems.length
    ? notice('error', h('strong', {}, 'Not valid yet: '), h('ul', { id: 'problems' }, problems.map(p => h('li', {}, p))))
    : notice('success', 'Valid grant.'));
  replace($('#english'), h('li', {}, describeGrant(grant)));
  showAreaPrivacy();
  const aud = audiencesFor(grant);
  const name = form.elements.device_name.value.trim() || 'My device';
  const days = Math.round(Number(form.elements.days.value) || 30);
  const lifetime = days * 86400;
  const origin = location.origin;
  const official = origin === 'https://devicebasedauth.org';
  $('#cli-command').textContent = `${official ? '' : `DBA_ORIGIN=${origin} `}dba enroll --aud ${aud.join(',') || 'SITE'} --grant ${shellQuote(JSON.stringify(grant))} --name ${shellQuote(name)} --lifetime ${lifetime}`;
  $('#sdk-snippet').textContent = [
    `import { DBA } from '${origin}/sdk/dba.js';`,
    '',
    `const dba = new DBA(${official ? '' : `{ origin: '${origin}' }`});`,
    '// Call enroll() from a click handler: it opens the approval window.',
    'if (!await dba.ready()) {',
    `  await dba.enroll({ aud: ${JSON.stringify(aud)}, grants: [${JSON.stringify(grant)}], device: { name: ${JSON.stringify(name)} }, lifetime_seconds: ${lifetime} });`,
    '}',
    `const response = await dba.fetch('https://${aud[0] || 'example.com'}/api/…');`
  ].join('\n');
  try { sessionStorage.setItem('dba-builder-grant', JSON.stringify(grant)); } catch { /* optional */ }
}

async function showCatalog(name) {
  replace(catalogBox, h('p', { class: 'muted small' }, 'Loading actions…'));
  try {
    if (!catalogs.has(name)) catalogs.set(name, await api(`/api/v1/audiences/${encodeURIComponent(name)}`, { auth: false }));
    const audience = catalogs.get(name);
    $('#audience-description').textContent = audience.description || '';
    replace(catalogBox,
      h('label', { class: 'check' }, h('input', { type: 'checkbox', value: `${audience.namespace}:*`, class: 'all-actions' }), h('span', {}, h('code', {}, `${audience.namespace}:*`), ' — every action, including future ones')),
      (audience.catalog || []).map(entry => h('label', { class: 'check catalog-action' }, h('input', { type: 'checkbox', value: entry.action }), h('span', {}, h('code', {}, entry.action), entry.description ? h('span', { class: 'hint' }, ` — ${entry.description}`) : null))));
  } catch (error) { replace(catalogBox, notice('warn', `Could not load the catalog: ${error.message}. Type actions under “Other actions”.`)); }
  build();
}

async function init() {
  replace(form.elements.tz, timeZones().map(z => h('option', { value: z }, z)));
  form.elements.tz.value = localZone();
  $('#windows').append(windowRow());
  $('#add-window').addEventListener('click', () => { $('#windows').append(windowRow()); form.elements.use_windows.checked = true; build(); });
  $('#add-area').addEventListener('click', () => { $('#areas').append(areaRow()); build(); });
  form.elements.source.addEventListener('change', () => { $('#where-fields').hidden = !form.elements.source.value; });
  form.addEventListener('input', build);
  form.addEventListener('change', build);
  form.addEventListener('submit', event => event.preventDefault());
  $('#copy-actions').append(
    copyButton('Copy JSON', () => $('#grant-json').textContent, { id: 'copy-json' }),
    copyButton('Copy dba enroll command', () => $('#cli-command').textContent, { id: 'copy-cli' }),
    copyButton('Copy SDK snippet', () => $('#sdk-snippet').textContent, { id: 'copy-sdk' }));
  $('#to-playground').addEventListener('click', () => { try { sessionStorage.setItem('dba-playground-credential', JSON.stringify([readGrant()])); } catch { /* optional */ } });
  try { audiences = (await api('/api/v1/audiences', { auth: false })).items; }
  catch (error) { audiences = []; replace(catalogBox, notice('warn', `Could not load audiences: ${error.message}`)); }
  replace(form.elements.audience, audiences.map(a => h('option', { value: a.name }, `${a.name} (${a.namespace}:…)`)));
  form.elements.audience.addEventListener('change', () => showCatalog(form.elements.audience.value));
  const preferred = audiences.find(a => a.name === 'hashbin.org') || audiences[0];
  if (preferred) { form.elements.audience.value = preferred.name; await showCatalog(preferred.name); } else build();
}

init();
