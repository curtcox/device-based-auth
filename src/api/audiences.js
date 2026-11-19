import { assert, readJson, ApiError } from '../utils/errors.js';
import { cleanRedirectUri } from './mcp-oauth.js';
import { rpc } from '../utils/rpc.js';
import { price } from '../utils/pricing.js';
import { AUDIENCE_NAME } from '../durable-objects/registry-do.js';
import { authenticate } from '../auth/middleware.js';
import { canAccess, paysForReads } from '../auth/scopes.js';
import { cleanWebhookUrl, signEvent, postEvent } from '../services/webhooks.js';
import { GATE_KINDS } from '../../packages/verify/src/grants.js';

const ACTION_SUFFIX = /^[a-z0-9_.-]{1,64}(?::[a-z0-9_.-]{1,64})*$/;

function cleanCatalog(namespace, catalog) {
  assert(Array.isArray(catalog) && catalog.length >= 1 && catalog.length <= 200, 'invalid_catalog', 'catalog must list 1–200 actions');
  const seen = new Set();
  return catalog.map((entry, i) => {
    const action = String(entry?.action ?? '');
    assert(action.startsWith(`${namespace}:`) && ACTION_SUFFIX.test(action.slice(namespace.length + 1)), 'invalid_catalog', `catalog[${i}].action must look like "${namespace}:verb"`);
    assert(!seen.has(action), 'invalid_catalog', `catalog[${i}] duplicates ${action}`); seen.add(action);
    const gates = entry.gates === undefined || entry.gates === null ? undefined : cleanGatePolicy(entry.gates, `catalog[${i}].gates`);
    return { action, description: String(entry.description ?? '').replace(/[\p{Cc}\p{Cf}]/gu, '').slice(0, 300), ...(gates ? { gates } : {}) };
  });
}

/**
 * An action's gate policy (spec/evaluation.md §3.8): `require` gates (of `kinds`, if listed) on
 * every grant used for it, and `fail_open: false` to refuse allows by timeout.
 */
export function cleanGatePolicy(policy, path) {
  assert(policy && typeof policy === 'object' && !Array.isArray(policy), 'invalid_catalog', `${path} must be an object`);
  for (const key of Object.keys(policy)) assert(['require', 'kinds', 'fail_open'].includes(key), 'invalid_catalog', `${path}.${key} is not a gate policy member (require, kinds, fail_open)`);
  assert(policy.require === undefined || typeof policy.require === 'boolean', 'invalid_catalog', `${path}.require must be true or false`);
  assert(policy.fail_open === undefined || typeof policy.fail_open === 'boolean', 'invalid_catalog', `${path}.fail_open must be true or false`);
  const kinds = policy.kinds;
  assert(kinds === undefined || (Array.isArray(kinds) && kinds.length >= 1 && kinds.every(k => GATE_KINDS.includes(k)) && new Set(kinds).size === kinds.length), 'invalid_catalog', `${path}.kinds must list different gate kinds from ${GATE_KINDS.join(', ')}`);
  assert(kinds === undefined || policy.require === true, 'invalid_catalog', `${path}.kinds only applies with require: true`);
  const clean = {};
  if (policy.require) clean.require = true;
  if (kinds) clean.kinds = [...kinds];
  if (policy.fail_open === false) clean.fail_open = false;
  return Object.keys(clean).length ? clean : undefined;
}

/**
 * OpenID Connect redirect URIs: https, or http on a loopback address, as for MCP clients. Any other
 * scheme is refused: the consent page navigates to the redirect, so `javascript://localhost/…`
 * (which once passed a hostname-only check) would run script on devicebasedauth.org itself.
 */
function cleanRedirects(uris = []) {
  assert(Array.isArray(uris) && uris.length <= 10, 'invalid_redirect_uris', 'redirect_uris must list at most 10 URLs');
  return uris.map(uri => {
    try { return cleanRedirectUri(uri); } catch (error) { if (error instanceof ApiError) assert(false, 'invalid_redirect_uris', `${String(uri).slice(0, 100)}: ${error.message}`); throw error; }
  });
}

/**
 * Prove control of a domain: https://<name>/.well-known/devicebasedauth.json must contain
 * {"account": "<your account id>"}. Local development skips this for *.localhost names.
 */
async function verifyDomain(env, name, account) {
  if (env.ENVIRONMENT === 'local' && (name === 'localhost' || name.endsWith('.localhost') || name.startsWith('localhost:'))) return true;
  const fetcher = env.DOMAIN_FETCH || fetch;
  let body;
  try {
    const response = await fetcher(`https://${name}/.well-known/devicebasedauth.json`, { redirect: 'error', signal: AbortSignal.timeout(5000) });
    body = response.ok ? await response.json() : null;
  } catch { body = null; }
  assert(body?.account === account, 'domain_unverified', `Publish {"account":"${account}"} at https://${name}/.well-known/devicebasedauth.json, then try again`, 403);
  return true;
}

/** Online decisions, sign-ins and spend per month for an audience the caller owns. */
export async function audienceUsage(route, request, env, auth) {
  const current = await rpc(env.REGISTRY, 'global', 'get', { name: route.params.name });
  assert(current.owner === auth.account, 'forbidden', 'You do not own this audience', 403);
  return rpc(env.ACCOUNTS, auth.account, 'audience-usage', { audience: current.name });
}

/**
 * Send a signed webhook.test event to the audience's revocation webhook now and report the
 * response, so an owner can check their endpoint. Metered at the read price.
 */
export async function audienceWebhookTest(route, request, env, auth) {
  const current = await rpc(env.REGISTRY, 'global', 'get', { name: route.params.name });
  assert(current.owner === auth.account, 'forbidden', 'You do not own this audience', 403);
  assert(current.revocation_webhook, 'no_webhook', 'Set revocation_webhook on the audience first', 409);
  await rpc(env.ACCOUNTS, auth.account, 'charge', { kind: 'read', amount: price('read'), aggregate: true, detail: { audience: current.name } });
  const event = await signEvent(env, current.name, 'webhook.test');
  const result = await postEvent(env, current.revocation_webhook, event.jws);
  return { url: current.revocation_webhook, event_id: event.jti, delivered: result.ok, status: result.status, ...(result.error ? { error: result.error } : {}) };
}

/** Public audience record: the webhook URL is the owner's business. */
function publicAudience({ revocation_webhook: _hook, ...audience }) { return audience; }

export async function audiences(route, request, env, auth) {
  if (request.method === 'GET' && route.params.name) return publicAudience(await rpc(env.REGISTRY, 'global', 'get', { name: route.params.name }));
  if (request.method === 'GET') {
    if (new URL(request.url).searchParams.get('mine') !== '1') return rpc(env.REGISTRY, 'global', 'list', {});
    // The public list route authenticates only when asked for "my audiences", so it checks the
    // scope and meters the read itself (full records, webhook URLs included).
    const caller = auth || await authenticate(request, env);
    assert(canAccess(caller, 'audiences:read'), 'insufficient_scope', 'Credential does not allow this operation', 403);
    const paid = paysForReads(caller) ? await rpc(env.ACCOUNTS, caller.account, 'charge', { kind: 'read', amount: price('read'), aggregate: true }) : null;
    return { ...(await rpc(env.REGISTRY, 'global', 'list', { owner: caller.account })), cost_microdollars: paid?.charged ?? 0 };
  }
  const body = await readJson(request, 65536);
  if (request.method === 'POST') {
    const name = String(body.name ?? '').toLowerCase();
    assert(AUDIENCE_NAME.test(name), 'invalid_audience', 'name must be a lower-case domain name you control');
    const namespace = String(body.namespace ?? '');
    const record = { name, namespace, description: String(body.description ?? '').slice(0, 300), catalog: cleanCatalog(namespace, body.catalog), redirect_uris: cleanRedirects(body.redirect_uris), accept_access_tokens: body.accept_access_tokens !== false, verified: true };
    if (body.sign_in_gates) record.sign_in_gates = cleanGatePolicy(body.sign_in_gates, 'sign_in_gates');
    if (body.revocation_webhook) record.revocation_webhook = cleanWebhookUrl(body.revocation_webhook, name, env);
    await verifyDomain(env, name, auth.account);
    const paid = await rpc(env.ACCOUNTS, auth.account, 'charge', { id: `audience-${name}`, kind: 'audience', amount: price('audience') });
    return { ...(await rpc(env.REGISTRY, 'global', 'register', { audience: record, owner: auth.account })), cost_microdollars: paid.duplicate ? 0 : paid.charged, balance_microdollars: paid.balance_microdollars };
  }
  const current = await rpc(env.REGISTRY, 'global', 'get', { name: route.params.name });
  assert(current.owner === auth.account, 'forbidden', 'You do not own this audience', 403);
  const changes = {};
  if (body.description !== undefined) changes.description = String(body.description).slice(0, 300);
  if (body.catalog !== undefined) changes.catalog = cleanCatalog(current.namespace, body.catalog);
  if (body.redirect_uris !== undefined) changes.redirect_uris = cleanRedirects(body.redirect_uris);
  if (body.accept_access_tokens !== undefined) changes.accept_access_tokens = body.accept_access_tokens !== false;
  // The site's own demand for sign-in gates (done/additional_gates.md §6); null removes it.
  if (body.sign_in_gates !== undefined) changes.sign_in_gates = body.sign_in_gates === null ? null : cleanGatePolicy(body.sign_in_gates, 'sign_in_gates') ?? null;
  if (body.revocation_webhook !== undefined) changes.revocation_webhook = cleanWebhookUrl(body.revocation_webhook, current.name, env);
  const paid = await rpc(env.ACCOUNTS, auth.account, 'charge', { id: `audience-${current.name}-${Date.now()}`, kind: 'audience', amount: price('audience') });
  return { ...(await rpc(env.REGISTRY, 'global', 'update', { name: current.name, owner: auth.account, changes })), cost_microdollars: paid.duplicate ? 0 : paid.charged, balance_microdollars: paid.balance_microdollars };
}
