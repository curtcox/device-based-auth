/**
 * Credential inspector: decodes locally (works offline) with the verify library, then asks
 * POST /api/v1/inspect to check the signature against the live JWKS and the revocation bit.
 * The pasted credential is untrusted: everything is rendered as text.
 */
import { api } from '../api.js';
import { h, $, replace, date, relative, badge, notice, dl, jsonBlock, describeKey } from '../html.js';
import { inspectCredential, describeGrant, validateCredentialPayload } from '/lib/verify/index.js';

const form = $('#inspect-form');
const input = $('#credential');
const local = $('#local-result');
const server = $('#server-result');
let serverTimer = null;

function validity(payload) {
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(payload.exp)) return badge('invalid', 'no expiry');
  if (Number.isSafeInteger(payload.nbf) && now + 60 < payload.nbf) return [badge('pending', 'not yet valid'), ` — valid ${relative(payload.nbf)}`];
  if (now - 60 >= payload.exp) return [badge('expired'), ` — expired ${relative(payload.exp)}`];
  return [badge('valid', 'within its validity window'), ` — expires ${relative(payload.exp)}`];
}

function decode() {
  clearTimeout(serverTimer);
  replace(server);
  const text = input.value.trim().replace(/^(DBA|Bearer)\s+/i, '');
  if (!text) { replace(local); return null; }
  let decoded;
  try { decoded = inspectCredential(text); } catch {
    replace(local, notice('error', 'That is not a compact JWS (three base64url parts separated by dots, the first two JSON).'));
    return null;
  }
  const { header, payload } = decoded;
  if (header.typ === 'dba-confirmation+jwt') { replace(local, describeConfirmation(header, payload)); return null; }
  const kind = header.typ === 'dba-access+jwt' ? 'access' : header.typ === 'dba-device+jwt' ? 'device' : null;
  const problems = kind ? validateCredentialPayload(payload, { typ: header.typ }) : [`typ "${header.typ}" is not a devicebasedauth.org credential`];
  if (header.alg !== 'ES256') problems.unshift(`alg must be ES256, not ${header.alg}`);
  const grants = Array.isArray(payload.grants) ? payload.grants : [];
  replace(local,
    h('h2', {}, kind === 'access' ? 'Access token' : 'Device credential', ' ', h('span', { class: 'muted small' }, 'decoded locally — not verified yet')),
    dl([
      ['Type', h('code', {}, String(header.typ))],
      ['Signed by', [h('code', {}, String(header.kid)), ` (${header.alg})`]],
      ['Issuer', String(payload.iss ?? '—')],
      ['Account', h('span', { class: 'mono' }, String(payload.acct ?? '—'))],
      ['Device', payload.device ? `${payload.device.name} · ${payload.device.kind} · key: ${describeKey(payload.device)}` : '—'],
      ['Device id', h('span', { class: 'mono' }, String(payload.sub ?? '—'))],
      ['Audiences', Array.isArray(payload.aud) ? payload.aud.join(', ') : '—'],
      ['Credential id', h('span', { class: 'mono' }, `${payload.cid ?? '—'} (${payload.jti ?? '—'})`)],
      ['Issued', date(payload.iat, true)],
      ['Valid from', date(payload.nbf, true)],
      ['Expires', date(payload.exp, true)],
      ['Right now', h('span', { id: 'validity' }, validity(payload))],
      ['Bound to key', payload.cnf?.jkt ? h('span', { class: 'mono small' }, payload.cnf.jkt) : kind === 'access' ? 'no — a bearer token' : '—'],
      ['Status list', payload.status?.status_list ? h('span', { class: 'mono small' }, `${payload.status.status_list.uri} #${payload.status.status_list.idx}`) : '—'],
      payload.confirm ? ['Periodic confirmation', h('span', { id: 'confirm-summary' }, describeConfirm(payload.confirm))] : null
    ]),
    problems.length ? notice('error', h('strong', {}, 'Structural problems: '), h('ul', { id: 'problems' }, problems.map(p => h('li', {}, p)))) : null,
    h('h3', {}, 'Grants in plain English'),
    grants.length ? h('ol', { class: 'english', id: 'grant-descriptions' }, grants.map(g => h('li', {}, describeGrant(g)))) : h('p', { class: 'muted' }, 'No grants.'),
    h('h3', {}, 'Header'), jsonBlock(header, { id: 'decoded-header' }),
    h('h3', {}, 'Payload'), jsonBlock(payload, { id: 'decoded-payload' }));
  return text;
}

const seconds = s => (s % 86400 === 0 ? `${s / 86400} day${s === 86400 ? '' : 's'}` : s % 3600 === 0 ? `${s / 3600} hour${s === 3600 ? '' : 's'}` : `${Math.round(s / 60)} minutes`);

/** The confirm claim in words (spec/credential.md §9). Untrusted: rendered as text only. */
function describeConfirm(confirm) {
  const entries = Array.isArray(confirm?.gates) ? confirm.gates : [];
  const who = entries.map(e => (Array.isArray(e?.any) ? e.any.map(String).join(' or ') : '?')).join(', then ');
  return `Works only while ${who || '?'} confirmed the device in the last ${Number.isSafeInteger(confirm?.every_s) ? seconds(confirm.every_s) : '?'}; sites check a DBA-Confirmation header.`;
}

/** A dba-confirmation+jwt: decoded only (verifiers check it with the issuer's JWKS). */
function describeConfirmation(header, payload) {
  const gates = Array.isArray(payload.gates) ? payload.gates : [];
  return [
    h('h2', {}, 'Confirmation', ' ', h('span', { class: 'muted small' }, 'decoded locally — not verified')),
    dl([
      ['Type', h('code', {}, String(header.typ))],
      ['Signed by', [h('code', {}, String(header.kid)), ` (${header.alg})`]],
      ['Issuer', String(payload.iss ?? '—')],
      ['Credential id', h('span', { class: 'mono' }, String(payload.cid ?? '—'))],
      ['Device id', h('span', { class: 'mono' }, String(payload.sub ?? '—'))],
      ['Bound to key', h('span', { class: 'mono small' }, String(payload.cnf?.jkt ?? '—'))],
      ['Confirmed', date(payload.iat, true)],
      ['Until', date(payload.exp, true)],
      ['Right now', h('span', { id: 'validity' }, validity(payload))],
      ['How', h('span', { id: 'confirmation-how' }, payload.by_timeout ? 'by timeout: nobody answered and the gate allows that' : gates.map(g => `${String(g?.kind ?? '?')} (${String(g?.by ?? '?')})`).join(', ') || '—')]
    ]),
    h('p', { class: 'muted small' }, 'Send it as the DBA-Confirmation header beside the credential it names. Verifiers check its signature and that cid, sub and cnf.jkt match the credential.'),
    h('h3', {}, 'Payload'), jsonBlock(payload, { id: 'decoded-payload' })
  ];
}

async function check(text) {
  replace(server, h('p', { class: 'muted' }, 'Checking with the server…'));
  const audience = form.elements.audience.value.trim();
  try {
    const result = await api('/api/v1/inspect', { method: 'POST', body: { credential: text, ...(audience ? { audience } : {}) }, auth: false });
    replace(server, h('div', { class: 'panel', id: 'server-check' },
      h('h2', {}, 'Server check ', badge(result.valid ? 'valid' : 'invalid', result.valid ? 'valid' : 'not valid')),
      dl([
        ['Signature', result.signature_valid ? badge('valid', 'verifies with the issuer\'s key') : badge('invalid', 'does not verify')],
        ['Revoked', result.revoked === undefined ? 'unknown' : result.revoked ? badge('revoked', 'revoked') : badge('active', 'not revoked')]
      ]),
      result.problems.length ? h('ul', { class: 'problems' }, result.problems.map(p => h('li', {}, `${p.message} (${p.code})`))) : null));
  } catch (error) {
    replace(server, notice('warn', `The server check is unavailable (${error.message}). The decoded view above still works offline.`));
  }
}

input.addEventListener('input', () => {
  const text = decode();
  if (text) serverTimer = setTimeout(() => check(text), 400);
});
form.addEventListener('submit', event => { event.preventDefault(); const text = decode(); if (text) check(text); });

let initial = null;
try { initial = sessionStorage.getItem('dba-inspector-credential'); sessionStorage.removeItem('dba-inspector-credential'); } catch { initial = null; }
if (initial) { input.value = initial; const text = decode(); if (text) check(text); }
