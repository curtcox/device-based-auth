/**
 * API explorer: every operation in /openapi.json (generated from API_ROUTES, so it cannot list a
 * route that does not exist), with inputs for its path, query and body, sent from this page as
 * the signed-in user, with a pasted API key, or anonymously. Billable operations default to
 * ?dry_run=1 so exploring costs nothing until the user unticks it.
 *
 * Responses are untrusted (device names, grants, audience descriptions), so they are only ever
 * shown as text through h().
 */
import { h, $, replace, notice, copyButton, jsonBlock, money, dl } from '../html.js';
import { initAuth, authHeaders, signedInLabel, authMode } from '../auth.js';

const form = $('#explorer-form');
const out = $('#explorer-result');
const select = $('#operation');
/** What each x-access value (src/auth/scopes.js) means for the caller. */
const ACCESS_NOTE = {
  public: 'Public: no sign-in needed.',
  session: 'Dashboard only: a signed-in session (or this browser\'s dashboard device credential). API keys are refused.',
  device: 'Device only: a device credential and a DPoP proof. Use `dba curl` or the browser SDK; this page can send it only if you signed in to the dashboard with this browser as a device.',
  authenticated: 'Any sign-in: session, API key or device credential.'
};
let operations = [];
let apiKey = '';

/** Operations from the spec, in route-table order, skipping pages that are not JSON APIs. */
function listOperations(spec) {
  const list = [];
  for (const [path, methods] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(methods)) {
      if (path === '/oauth/authorize' && method === 'get') continue; // a redirect to the consent page
      list.push({ path, method: method.toUpperCase(), op });
    }
  }
  return list;
}

/** A section name for the drop-down: the first path segment after /api/v1. */
function section(path) {
  const parts = path.split('/').filter(Boolean);
  if (parts[0] === 'api' && parts[1] === 'v1') return parts[2] || 'api';
  if (parts[0] === 'api') return parts[1] || 'api';
  return parts[0] === '.well-known' ? 'well-known' : parts[0];
}

/** Charging operations say so in their summary; those get a dry-run box, ticked. */
const billable = op => /charges/i.test(op.summary || '');

/** A starting body from the schema: required members only, with harmless placeholders. */
function skeleton(schema) {
  if (!schema) return undefined;
  if (schema.$ref?.endsWith('/Grant')) return { actions: ['hashbin:content:write'] };
  if (schema.const !== undefined) return schema.const;
  switch (schema.type) {
    case 'object': {
      const value = {};
      for (const name of schema.required || []) value[name] = skeleton(schema.properties?.[name]);
      return value;
    }
    case 'array': return schema.items ? [skeleton(schema.items)] : [];
    case 'integer': return schema.minimum ?? 0;
    case 'number': return 0;
    case 'boolean': return false;
    default: return '';
  }
}

function currentOperation() { return operations[Number(select.value)] || operations[0]; }

function renderOperation() {
  const { path, method, op } = currentOperation();
  const access = op['x-access'];
  const pathParams = (op.parameters || []).filter(p => p.in === 'path');
  const queryParams = (op.parameters || []).filter(p => p.in === 'query');
  const body = op.requestBody?.content?.['application/json']?.schema;
  replace($('#operation-detail'),
    h('p', {}, h('code', { id: 'operation-line' }, `${method} ${path}`), ' — ', op.summary || ''),
    h('p', { class: 'small muted', id: 'operation-access' }, ACCESS_NOTE[access] || `Needs scope ${access}: an API key with it, a signed-in session, or a device credential holding dba:${access}.`));
  const fields = [];
  for (const param of pathParams) fields.push(h('label', {}, `${param.name} (path)`, h('input', { name: `path:${param.name}`, required: true, spellcheck: 'false' })));
  for (const param of queryParams) fields.push(h('label', {}, `${param.name} (query${param.required ? ', required' : ''})`, h('input', { name: `query:${param.name}`, required: !!param.required, spellcheck: 'false' })));
  if (body) {
    fields.push(h('label', {}, 'JSON body', h('textarea', { name: 'body', rows: 8, spellcheck: 'false' }, JSON.stringify(skeleton(body), null, 2))));
    fields.push(h('details', {}, h('summary', {}, 'Body schema'), jsonBlock(body)));
  }
  if (billable(op)) fields.push(h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'dry_run', checked: true }), 'Dry run: show the price, charge nothing'));
  replace($('#parameters'), fields);
}

function renderAuth() {
  const mode = form.elements.auth.value;
  const detail = $('#auth-detail');
  if (mode === 'apikey') {
    const input = h('input', { name: 'api_key', type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: 'dbak_…', value: apiKey });
    input.addEventListener('input', () => { apiKey = input.value.trim(); });
    replace(detail, h('label', {}, 'API key', input), h('p', { class: 'small muted' }, 'Kept only in this tab\'s memory and sent only to this site. Make a key with just the scopes you are trying in the dashboard\'s API keys section.'));
  } else if (mode === 'session') {
    replace(detail, authMode()
      ? h('p', { class: 'small', id: 'signed-in-as' }, `Signed in as ${signedInLabel()}.`)
      : notice('warn', 'You are not signed in. ', h('a', { href: '/app.html' }, 'Sign in to the dashboard'), ', then come back.'));
  } else replace(detail, h('p', { class: 'small muted' }, 'No Authorization header: only public endpoints will answer.'));
}

/** The URL for the current inputs, or throws with a message for the user. */
function buildUrl() {
  const { path, op } = currentOperation();
  const filled = path.replace(/\{([a-z_]+)\}/g, (_, name) => {
    const value = form.elements[`path:${name}`]?.value.trim();
    if (!value) throw new Error(`Fill in ${name}.`);
    return encodeURIComponent(value);
  });
  const url = new URL(filled, location.origin);
  for (const param of (op.parameters || []).filter(p => p.in === 'query')) {
    const value = form.elements[`query:${param.name}`]?.value.trim();
    if (value) url.searchParams.set(param.name, value);
  }
  if (form.elements.dry_run?.checked) url.searchParams.set('dry_run', '1');
  return url.href;
}

const quote = text => `'${text.replaceAll("'", "'\\''")}'`;

/** A curl command a developer can run with their own key (never with this page's sign-in). */
function curlCommand(method, url, body) {
  const parts = ['curl', '-sS'];
  if (method !== 'GET') parts.push('-X', method);
  if (form.elements.auth.value !== 'none') parts.push('-H', '"Authorization: ApiKey $DBA_API_KEY"');
  if (body !== undefined) parts.push('-H', quote('Content-Type: application/json'), '-d', quote(JSON.stringify(body)));
  parts.push(quote(url));
  return parts.join(' ');
}

async function send(event) {
  event.preventDefault();
  const { method } = currentOperation();
  let url; let body;
  try {
    url = buildUrl();
    const text = form.elements.body?.value.trim();
    if (text) { try { body = JSON.parse(text); } catch { throw new Error('The body is not valid JSON.'); } }
  } catch (error) { replace(out, notice('error', error.message)); return; }

  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['Idempotency-Key'] = crypto.randomUUID();
  const mode = form.elements.auth.value;
  if (mode === 'apikey') {
    if (!apiKey) { replace(out, notice('error', 'Paste an API key, or choose another way to call.')); return; }
    headers.Authorization = `ApiKey ${apiKey}`;
  } else if (mode === 'session') Object.assign(headers, await authHeaders(method, url));

  replace(out, notice('info', 'Sending…'));
  const started = performance.now();
  let response; let text;
  try {
    response = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    text = await response.text();
  } catch (error) { replace(out, notice('error', `The request failed: ${error.message}`)); return; }
  const elapsed = Math.round(performance.now() - started);
  let shown = text;
  try { shown = JSON.stringify(JSON.parse(text), null, 2); } catch { /* not JSON: show as text */ }
  const cost = response.headers.get('X-DBA-Cost-Microdollars');
  const sent = { ...headers };
  if (sent.Authorization) sent.Authorization = `${sent.Authorization.split(' ')[0]} …`;
  replace(out, h('div', { class: 'panel' },
    h('h2', {}, 'Response'),
    dl([
      ['Status', h('span', { id: 'response-status' }, `${response.status} ${response.statusText}`.trim())],
      ['Time', `${elapsed} ms`],
      ['Charged', h('span', { id: 'response-cost' }, cost === null ? 'nothing (no cost header)' : money(Number(cost)))]
    ]),
    h('pre', { class: 'code', id: 'response-body' }, shown || '(empty)'),
    h('div', { class: 'actions' }, copyButton('Copy response', () => text), copyButton('Copy as curl', () => curlCommand(method, url, body))),
    h('details', {}, h('summary', {}, 'Request'), h('pre', { class: 'code wrap' }, `${method} ${url}\n${Object.entries(sent).map(([k, v]) => `${k}: ${v}`).join('\n')}${body === undefined ? '' : `\n\n${JSON.stringify(body, null, 2)}`}`))));
}

async function start() {
  const [specResponse] = await Promise.all([fetch('/openapi.json'), initAuth().catch(() => null)]);
  operations = listOperations(await specResponse.json());
  const groups = new Map();
  operations.forEach((entry, index) => {
    const name = section(entry.path);
    if (!groups.has(name)) groups.set(name, h('optgroup', { label: name }));
    groups.get(name).append(h('option', { value: String(index) }, `${entry.method} ${entry.path}`));
  });
  replace(select, [...groups.values()]);
  // #GET/api/v1/whoami selects an operation, so docs can link straight to one.
  const wanted = decodeURIComponent(location.hash.slice(1));
  const found = operations.findIndex(o => `${o.method}${o.path}` === wanted);
  select.value = String(found === -1 ? Math.max(0, operations.findIndex(o => o.path === '/api/v1/whoami')) : found);
  renderAuth(); renderOperation();
  select.addEventListener('change', () => { history.replaceState(null, '', `#${currentOperation().method}${currentOperation().path}`); renderOperation(); replace(out); });
  for (const radio of form.elements.auth) radio.addEventListener('change', renderAuth);
  form.addEventListener('submit', send);
}

start().catch(error => replace(out, notice('error', `Could not load the API description: ${error.message}`)));
