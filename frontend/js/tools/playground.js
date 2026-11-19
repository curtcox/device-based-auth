/**
 * Policy playground: evaluateGrants with a simulated clock and location. Runs entirely in the
 * browser; pasted grants and credentials are untrusted and only ever rendered as text.
 */
import { h, $, replace, badge, notice, table, pretty } from '../html.js';
import { evaluateGrants, describeGrant, validateGrants, inspectCredential } from '/lib/verify/index.js';
import { timeZones, localZone, zonedToEpoch, epochToZoned, describeInstant, explainReason, numberOrUndefined } from './common.js';

const form = $('#playground-form');
const result = $('#playground-result');
const WEEKDAYS = ['mon', 'tue', 'wed', 'thu', 'fri'];

export const PRESETS = [
  {
    id: 'office-hours', label: 'Office hours in Chicago',
    grants: [{ actions: ['hashbin:content:write'], when: { tz: 'America/Chicago', windows: [{ days: WEEKDAYS, from: '08:00', to: '18:00' }] } }],
    action: 'hashbin:content:write', time: '2026-11-18T10:00', tz: 'America/Chicago', network: {}, device: {}
  },
  {
    id: 'us-network', label: 'US only, from the office network',
    grants: [{ actions: ['cronly:run', 'cronly:read'], where: { source: 'network', countries: ['US'], networks: ['203.0.113.0/24'] } }],
    action: 'cronly:run', time: '2026-11-18T22:30', tz: 'UTC', network: { country: 'US', region: 'US-MO', ip: '203.0.113.7' }, device: {}
  },
  {
    id: 'agent', label: 'Agent: 100 uses a day, deletes need approval',
    grants: [
      { actions: ['hashbin:content:write'], limits: { uses: { count: 100, per: 'day' }, spend_usd_per_month: 2 } },
      { actions: ['hashbin:content:delete'], require: { step_up: true } }
    ],
    action: 'hashbin:content:write', time: '2026-11-18T03:00', tz: 'UTC', network: {}, device: {}
  },
  {
    id: 'confirmed', label: 'Works only while confirmed by a phone',
    grants: [{ actions: ['hashbin:content:write'], require: { confirmation: true } }],
    action: 'hashbin:content:write', time: '2026-11-18T10:00', tz: 'UTC', network: {}, device: {}, confirmed: true
  }
];

function setValue(name, value) { form.elements.namedItem(name).value = value ?? ''; }

function applyPreset(preset) {
  form.elements.grants.value = pretty(preset.grants);
  setValue('action', preset.action); setValue('resource', '');
  setValue('tz', preset.tz); setValue('time', preset.time);
  setValue('country', preset.network.country); setValue('region', preset.network.region); setValue('ip', preset.network.ip);
  setValue('net_lat', preset.network.lat); setValue('net_lon', preset.network.lon);
  setValue('dev_lat', preset.device.lat); setValue('dev_lon', preset.device.lon); setValue('dev_acc', preset.device.acc_m); setValue('dev_age', 0);
  form.elements.online.checked = false;
  form.elements.confirmed.checked = !!preset.confirmed;
  evaluate();
}

/** Grants from JSON (a list or one grant) or from a pasted credential. */
function readGrants() {
  const text = form.elements.grants.value.trim().replace(/^(DBA|Bearer)\s+/i, '');
  if (!text) return { error: 'Paste grants (a JSON list) or a credential.' };
  if (text.startsWith('[') || text.startsWith('{')) {
    try { const value = JSON.parse(text); return { grants: Array.isArray(value) ? value : [value], from: 'json' }; }
    catch (error) { return { error: `The grants are not valid JSON: ${error.message}` }; }
  }
  try {
    const { payload } = inspectCredential(text);
    return { grants: payload.grants, from: 'credential', payload };
  } catch { return { error: 'That is neither JSON nor a credential.' }; }
}

function location(now) {
  const network = { country: form.elements.country.value.trim().toUpperCase() || undefined, region: form.elements.region.value.trim().toUpperCase() || undefined, ip: form.elements.ip.value.trim() || undefined, lat: numberOrUndefined(form.elements.net_lat.value), lon: numberOrUndefined(form.elements.net_lon.value) };
  const lat = numberOrUndefined(form.elements.dev_lat.value); const lon = numberOrUndefined(form.elements.dev_lon.value);
  const device = lat === undefined || lon === undefined ? undefined : { lat, lon, acc_m: numberOrUndefined(form.elements.dev_acc.value), t: now - (numberOrUndefined(form.elements.dev_age.value) ?? 0) };
  return { network: Object.values(network).some(v => v !== undefined) ? network : undefined, device };
}

/** The simulated confirmation's { iat, exp, by_timeout }, as a verifier passes a verified one. */
function confirmation(now) {
  if (!form.elements.confirmed.checked) return undefined;
  const iat = now - Math.round((numberOrUndefined(form.elements.confirmed_ago.value) ?? 0) * 60);
  return { iat, exp: iat + Math.round((numberOrUndefined(form.elements.confirmed_for.value) ?? 0) * 3600), by_timeout: form.elements.confirmed_by_timeout.checked };
}

function evaluate() {
  const tz = form.elements.tz.value;
  const now = zonedToEpoch(form.elements.time.value, tz);
  $('#time-note').textContent = now === null ? '' : `${describeInstant(now, tz)} · ${new Date(now * 1000).toISOString().replace('.000Z', 'Z')} · ${now}`;
  const { grants, error, from, payload } = readGrants();
  $('#grants-note').textContent = from === 'credential' ? `Using the ${grants?.length ?? 0} grant(s) of credential ${payload.cid ?? ''} (its expiry and revocation are not checked here).` : '';
  if (error) { replace(result, notice('warn', error)); return; }
  const action = form.elements.action.value.trim();
  if (!action) { replace(result, notice('info', 'Enter an action to evaluate.')); return; }
  if (now === null) { replace(result, notice('info', 'Choose a date and time.')); return; }
  const outcome = evaluateGrants(grants, { now, action, resource: form.elements.resource.value.trim() || undefined, location: location(now), online: form.elements.online.checked, confirmation: confirmation(now) });
  const problems = validateGrants(grants);
  replace(result, h('div', { class: 'panel', id: 'verdict-panel' },
    h('p', {}, h('span', { class: `verdict ${outcome.allow ? 'allow' : 'deny'}`, id: 'verdict' }, outcome.allow ? 'Allow' : 'Deny'), ' ',
      h('span', { class: 'muted' }, outcome.allow ? `by grant ${outcome.grant_index + 1}` : outcome.online_required ? '— offline; ask online (POST /api/v1/authorize)' : '— no grant passed')),
    Object.keys(outcome.caveats || {}).length ? notice('info', `Caveat for the site to enforce: ${pretty(outcome.caveats)}`) : null,
    outcome.allow && Object.keys(outcome.online || {}).length ? notice('info', `Online checks still apply: ${pretty(outcome.online)}`) : null,
    problems.length ? notice('warn', h('strong', {}, 'Validation problems (an issuer would refuse these): '), h('ul', {}, problems.map(p => h('li', {}, p)))) : null,
    table(['Grant', 'In plain English', 'Result'], (Array.isArray(grants) ? grants : []).map((grant, i) => [
      String(i + 1), describeGrant(grant),
      outcome.reasons[i]?.length
        ? h('ul', { class: 'reasons' }, outcome.reasons[i].map(code => h('li', {}, h('code', { class: 'reason' }, code), ' ', h('span', { class: 'small muted' }, explainReason(code)))))
        : badge('allow', 'passes')
    ]), { id: 'grant-results' })));
}

function setNow() { setValue('time', epochToZoned(Math.floor(Date.now() / 1000), form.elements.tz.value)); evaluate(); }

function init() {
  replace(form.elements.tz, timeZones().map(z => h('option', { value: z }, z)));
  form.elements.tz.value = localZone();
  for (const preset of PRESETS) $('#presets').append(h('button', { type: 'button', class: 'secondary small', dataset: { preset: preset.id }, onclick: () => applyPreset(preset) }, preset.label));
  form.addEventListener('input', evaluate);
  form.addEventListener('change', evaluate);
  form.addEventListener('submit', event => { event.preventDefault(); evaluate(); });
  $('#now').addEventListener('click', setNow);
  let handed = null;
  try { handed = sessionStorage.getItem('dba-playground-credential'); sessionStorage.removeItem('dba-playground-credential'); } catch { handed = null; }
  if (handed) {
    form.elements.grants.value = handed;
    const first = readGrants().grants?.[0]?.actions?.[0];
    setValue('action', first && !first.endsWith('*') ? first : '');
    setNow();
  } else applyPreset(PRESETS[0]);
}

init();
