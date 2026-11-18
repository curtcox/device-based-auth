import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { price } from '../utils/pricing.js';
import { AUDIENCE_NAME } from '../durable-objects/registry-do.js';
import { authenticate } from '../auth/middleware.js';

const ACTION_SUFFIX = /^[a-z0-9_.-]{1,64}(?::[a-z0-9_.-]{1,64})*$/;

function cleanCatalog(namespace, catalog) {
  assert(Array.isArray(catalog) && catalog.length >= 1 && catalog.length <= 200, 'invalid_catalog', 'catalog must list 1–200 actions');
  const seen = new Set();
  return catalog.map((entry, i) => {
    const action = String(entry?.action ?? '');
    assert(action.startsWith(`${namespace}:`) && ACTION_SUFFIX.test(action.slice(namespace.length + 1)), 'invalid_catalog', `catalog[${i}].action must look like "${namespace}:verb"`);
    assert(!seen.has(action), 'invalid_catalog', `catalog[${i}] duplicates ${action}`); seen.add(action);
    return { action, description: String(entry.description ?? '').replace(/[\p{Cc}\p{Cf}]/gu, '').slice(0, 300) };
  });
}

function cleanRedirects(uris = []) {
  assert(Array.isArray(uris) && uris.length <= 10, 'invalid_redirect_uris', 'redirect_uris must list at most 10 URLs');
  return uris.map(uri => {
    let u; try { u = new URL(uri); } catch { assert(false, 'invalid_redirect_uris', `${uri} is not a URL`); }
    assert(u.protocol === 'https:' || u.hostname === 'localhost', 'invalid_redirect_uris', 'redirect URIs must use https (or localhost)');
    assert(!u.hash, 'invalid_redirect_uris', 'redirect URIs cannot have fragments');
    return u.toString();
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

export async function audiences(route, request, env, auth) {
  if (request.method === 'GET' && route.params.name) return rpc(env.REGISTRY, 'global', 'get', { name: route.params.name });
  if (request.method === 'GET') {
    if (new URL(request.url).searchParams.get('mine') !== '1') return rpc(env.REGISTRY, 'global', 'list', {});
    // The public list route authenticates only when asked for "my audiences".
    const caller = auth || await authenticate(request, env);
    return rpc(env.REGISTRY, 'global', 'list', { owner: caller.account });
  }
  const body = await readJson(request, 65536);
  if (request.method === 'POST') {
    const name = String(body.name ?? '').toLowerCase();
    assert(AUDIENCE_NAME.test(name), 'invalid_audience', 'name must be a lower-case domain name you control');
    const namespace = String(body.namespace ?? '');
    const record = { name, namespace, description: String(body.description ?? '').slice(0, 300), catalog: cleanCatalog(namespace, body.catalog), redirect_uris: cleanRedirects(body.redirect_uris), accept_access_tokens: body.accept_access_tokens !== false, verified: true };
    await verifyDomain(env, name, auth.account);
    await rpc(env.ACCOUNTS, auth.account, 'charge', { id: `audience-${name}`, kind: 'audience', amount: price('audience') });
    return rpc(env.REGISTRY, 'global', 'register', { audience: record, owner: auth.account });
  }
  const current = await rpc(env.REGISTRY, 'global', 'get', { name: route.params.name });
  assert(current.owner === auth.account, 'forbidden', 'You do not own this audience', 403);
  const changes = {};
  if (body.description !== undefined) changes.description = String(body.description).slice(0, 300);
  if (body.catalog !== undefined) changes.catalog = cleanCatalog(current.namespace, body.catalog);
  if (body.redirect_uris !== undefined) changes.redirect_uris = cleanRedirects(body.redirect_uris);
  if (body.accept_access_tokens !== undefined) changes.accept_access_tokens = body.accept_access_tokens !== false;
  await rpc(env.ACCOUNTS, auth.account, 'charge', { id: `audience-${current.name}-${Date.now()}`, kind: 'audience', amount: price('audience') });
  return rpc(env.REGISTRY, 'global', 'update', { name: current.name, owner: auth.account, changes });
}
