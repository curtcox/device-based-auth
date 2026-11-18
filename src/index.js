import { PUBLIC, SESSION, DEVICE, AUTHENTICATED, canAccess } from './auth/scopes.js';
import { authenticate } from './auth/middleware.js';
import { clerkWebhook } from './auth/clerk-webhook.js';
import { checkout, stripeWebhook } from './api/payments.js';
import { keys } from './api/keys.js';
import { startEnrollment, describeEnrollment, approveEnrollment, denyEnrollment, pollEnrollment, attestationChallenge } from './api/enrollments.js';
import { enrollmentTokens, redeemEnrollmentToken } from './api/enrollment-tokens.js';
import { caBundle, deviceCertificateFor } from './api/certificates.js';
import { createCredential, listCredentials, getCredential, credentialDecisions, revoke, revokeSelf, renew, token, whoami } from './api/credentials.js';
import { authorize } from './api/authorize.js';
import { audiences, audienceUsage, audienceWebhookTest } from './api/audiences.js';
import { accountSettings } from './api/settings.js';
import { statusList, republishStatusLists } from './api/status.js';
import { inspect } from './api/inspect.js';
import { oidcConfiguration, oidcAuthorize, oidcToken, oidcUserinfo } from './api/oidc.js';
import { mcp } from './api/mcp.js';
import { runCostMonitor, brakeActive } from './services/cost-monitor.js';
import { jwks, issuerName, appAudience } from './services/issuer.js';
import { money } from './durable-objects/ledger.js';
import { errorResponse, assert, readJson } from './utils/errors.js';
import { rpc } from './utils/rpc.js';
import { price, priceTable, PRICES, MINIMUM_DEPOSIT_CENTS } from './utils/pricing.js';
export { AccountDO } from './durable-objects/account-do.js';
export { StatusListDO } from './durable-objects/status-list-do.js';
export { RegistryDO } from './durable-objects/registry-do.js';
export { EnrollmentDO } from './durable-objects/enrollment-do.js';
export { SafetyDO } from './durable-objects/safety-do.js';

const V1 = '/api/v1';
// The route table is the only dispatch source: an undeclared endpoint cannot execute.
// `free: true` marks public routes stopped by the cost-safety brake.
export const API_ROUTES = [
  { method: 'GET', path: '/health', access: PUBLIC, handler: 'health' },
  { method: 'GET', path: '/.well-known/jwks.json', access: PUBLIC, handler: 'jwks' },
  { method: 'GET', path: '/.well-known/openid-configuration', access: PUBLIC, handler: 'oidc-configuration' },
  { method: 'GET', path: '/.well-known/dba-ca.pem', access: PUBLIC, handler: 'ca-bundle' },
  { method: 'GET', path: '/status/v1/lists/:shard', access: PUBLIC, handler: 'status-list' },
  { method: 'GET', path: '/api/public/config', access: PUBLIC, handler: 'public-config' },
  { method: 'GET', path: `${V1}/quote`, access: PUBLIC, handler: 'quote' },
  { method: 'POST', path: `${V1}/inspect`, access: PUBLIC, handler: 'inspect', free: true },
  { method: 'POST', path: `${V1}/enrollments`, access: PUBLIC, handler: 'enroll-start', free: true },
  { method: 'POST', path: `${V1}/enrollments/describe`, access: PUBLIC, handler: 'enroll-describe', free: true },
  { method: 'POST', path: `${V1}/enrollments/attestation-challenge`, access: PUBLIC, handler: 'attestation-challenge', free: true },
  { method: 'GET', path: `${V1}/enrollments/:id`, access: PUBLIC, handler: 'enroll-poll' },
  { method: 'POST', path: `${V1}/enrollments/approve`, access: SESSION, handler: 'enroll-approve' },
  { method: 'POST', path: `${V1}/enrollments/deny`, access: SESSION, handler: 'enroll-deny' },
  { method: 'POST', path: `${V1}/enrollments/redeem`, access: PUBLIC, handler: 'enroll-redeem' },
  { method: 'GET', path: `${V1}/enrollment-tokens`, access: 'credentials:issue', handler: 'enrollment-tokens' },
  { method: 'POST', path: `${V1}/enrollment-tokens`, access: 'credentials:issue', handler: 'enrollment-tokens' },
  { method: 'DELETE', path: `${V1}/enrollment-tokens/:id`, access: 'credentials:issue', handler: 'enrollment-tokens' },
  { method: 'GET', path: `${V1}/whoami`, access: AUTHENTICATED, handler: 'whoami' },
  { method: 'GET', path: `${V1}/account`, access: 'account:read', handler: 'account' },
  { method: 'GET', path: `${V1}/account/settings`, access: SESSION, handler: 'account-settings' },
  { method: 'PATCH', path: `${V1}/account/settings`, access: SESSION, handler: 'account-settings' },
  { method: 'GET', path: `${V1}/transactions`, access: 'transactions:read', handler: 'transactions' },
  { method: 'GET', path: `${V1}/audit`, access: 'transactions:read', handler: 'audit' },
  { method: 'GET', path: `${V1}/credentials`, access: 'credentials:read', handler: 'credentials-list' },
  { method: 'POST', path: `${V1}/credentials`, access: 'credentials:issue', handler: 'credentials-create' },
  { method: 'GET', path: `${V1}/credentials/:cid`, access: 'credentials:read', handler: 'credentials-get' },
  { method: 'DELETE', path: `${V1}/credentials/:cid`, access: 'credentials:revoke', handler: 'revoke-credential' },
  { method: 'GET', path: `${V1}/credentials/:cid/decisions`, access: 'credentials:read', handler: 'credentials-decisions' },
  { method: 'POST', path: `${V1}/credentials/:cid/renew`, access: DEVICE, handler: 'renew' },
  { method: 'GET', path: `${V1}/devices`, access: 'credentials:read', handler: 'devices-list' },
  { method: 'GET', path: `${V1}/devices/:id`, access: 'credentials:read', handler: 'devices-get' },
  { method: 'POST', path: `${V1}/devices/:id/revoke`, access: 'credentials:revoke', handler: 'revoke-device' },
  { method: 'POST', path: `${V1}/revoke-all`, access: 'credentials:revoke', handler: 'revoke-all' },
  { method: 'POST', path: `${V1}/self/revoke`, access: DEVICE, handler: 'revoke-self' },
  { method: 'POST', path: `${V1}/token`, access: DEVICE, handler: 'token' },
  { method: 'POST', path: `${V1}/certificate`, access: DEVICE, handler: 'certificate' },
  { method: 'POST', path: `${V1}/authorize`, access: 'authorize', handler: 'authorize' },
  { method: 'GET', path: `${V1}/step-ups`, access: SESSION, handler: 'step-ups' },
  { method: 'POST', path: `${V1}/step-ups/:id/approve`, access: SESSION, handler: 'step-up-decide' },
  { method: 'POST', path: `${V1}/step-ups/:id/deny`, access: SESSION, handler: 'step-up-decide' },
  { method: 'GET', path: `${V1}/audiences`, access: PUBLIC, handler: 'audiences' },
  { method: 'GET', path: `${V1}/audiences/:name`, access: PUBLIC, handler: 'audiences' },
  { method: 'GET', path: `${V1}/audiences/:name/usage`, access: 'audiences:read', handler: 'audience-usage' },
  { method: 'POST', path: `${V1}/audiences`, access: 'audiences:write', handler: 'audiences' },
  { method: 'PATCH', path: `${V1}/audiences/:name`, access: 'audiences:write', handler: 'audiences' },
  { method: 'POST', path: `${V1}/audiences/:name/webhook-test`, access: 'audiences:write', handler: 'audience-webhook-test' },
  { method: 'GET', path: `${V1}/keys`, access: SESSION, handler: 'keys' },
  { method: 'POST', path: `${V1}/keys`, access: SESSION, handler: 'keys' },
  { method: 'DELETE', path: `${V1}/keys/:id`, access: SESSION, handler: 'keys' },
  { method: 'POST', path: `${V1}/payments/checkout`, access: SESSION, handler: 'checkout' },
  { method: 'POST', path: `${V1}/dev/deposit`, access: SESSION, handler: 'dev-deposit' },
  { method: 'GET', path: '/oauth/authorize', access: PUBLIC, handler: 'oidc-authorize-page' },
  { method: 'POST', path: '/oauth/authorize', access: SESSION, handler: 'oidc-authorize' },
  { method: 'POST', path: '/oauth/token', access: PUBLIC, handler: 'oidc-token' },
  { method: 'GET', path: '/oauth/userinfo', access: PUBLIC, handler: 'oidc-userinfo' },
  { method: 'POST', path: '/mcp', access: AUTHENTICATED, handler: 'mcp' },
  { method: 'POST', path: '/webhooks/clerk', access: PUBLIC, handler: 'clerk-webhook' },
  { method: 'POST', path: '/webhooks/stripe', access: PUBLIC, handler: 'stripe-webhook' }
];

/** Match declared routes with named segments only. */
export function matchRoute(method, path) {
  for (const route of API_ROUTES) {
    if (route.method !== method) continue;
    const names = [];
    const pattern = route.path.split('/').map(part => { if (part.startsWith(':')) { names.push(part.slice(1)); return '([^/]+)'; } return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }).join('/');
    const match = path.match(new RegExp(`^${pattern}$`));
    if (match) {
      try { return { ...route, params: Object.fromEntries(names.map((name, i) => [name, decodeURIComponent(match[i + 1])])) }; } catch { return null; }
    }
  }
  return null;
}

const WORKER_PATHS = ['/api/', '/status/', '/.well-known/', '/oauth/', '/webhooks/'];
const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Authorization, DPoP, Content-Type, Idempotency-Key', 'Access-Control-Expose-Headers': 'X-DBA-Cost-Microdollars, DPoP-Nonce', 'Access-Control-Max-Age': '86400' };

async function handle(route, request, env, auth) {
  const url = new URL(request.url);
  const dryRun = url.searchParams.get('dry_run') === '1';
  switch (route.handler) {
    case 'health': return { status: 'ok', environment: env.ENVIRONMENT, git_sha: env.GIT_SHA || 'local' };
    case 'jwks': return new Response(JSON.stringify(jwks(env)), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600', ...CORS } });
    case 'status-list': return statusList(route, env);
    case 'public-config': return { local: env.ENVIRONMENT === 'local', environment: env.ENVIRONMENT, issuer: issuerName(env), audience: appAudience(env), app_origin: env.APP_ORIGIN, status_origin: env.STATUS_ORIGIN, clerk_publishable_key: env.CLERK_PUBLISHABLE_KEY || null, prices: PRICES, price_table: priceTable(), minimum_deposit_cents: MINIMUM_DEPOSIT_CENTS };
    case 'quote': {
      const op = url.searchParams.get('op');
      assert(Object.hasOwn(PRICES, op || ''), 'invalid_operation', `op must be one of ${Object.keys(PRICES).join(', ')}`);
      return { op, quote_microdollars: price(op) };
    }
    case 'inspect': return inspect(request, env);
    case 'enroll-start': return startEnrollment(request, env);
    case 'enroll-describe': return describeEnrollment(request, env);
    case 'attestation-challenge': return attestationChallenge(env);
    case 'enroll-poll': return pollEnrollment(route, request, env);
    case 'enroll-approve': return approveEnrollment(request, env, auth);
    case 'enroll-deny': return denyEnrollment(request, env, auth);
    case 'enroll-redeem': return redeemEnrollmentToken(request, env);
    case 'enrollment-tokens': return enrollmentTokens(route, request, env, auth);
    case 'whoami': return whoami(env, auth);
    case 'account': return rpc(env.ACCOUNTS, auth.account, 'account');
    case 'transactions': return rpc(env.ACCOUNTS, auth.account, 'list', { prefix: 'ledger:', cursor: url.searchParams.get('cursor') || undefined });
    case 'audit': return rpc(env.ACCOUNTS, auth.account, 'list', { prefix: 'audit:', cursor: url.searchParams.get('cursor') || undefined });
    case 'credentials-list': return listCredentials(request, env, auth);
    case 'credentials-create': return createCredential(request, env, auth);
    case 'credentials-get': return getCredential(route, env, auth);
    case 'credentials-decisions': return credentialDecisions(route, env, auth);
    case 'devices-list': return rpc(env.ACCOUNTS, auth.account, 'list-devices', { cursor: url.searchParams.get('cursor') || undefined });
    case 'devices-get': return rpc(env.ACCOUNTS, auth.account, 'get-device', { id: route.params.id });
    case 'revoke-credential': case 'revoke-device': case 'revoke-all': return revoke(route, request, env, auth);
    case 'revoke-self': return revokeSelf(env, auth);
    case 'renew': return renew(route, request, env, auth);
    case 'token': return token(request, env, auth);
    case 'certificate': return deviceCertificateFor(request, env, auth);
    case 'ca-bundle': return caBundle(env);
    case 'authorize': return authorize(request, env, auth);
    case 'step-ups': return rpc(env.ACCOUNTS, auth.account, 'list-step-ups');
    case 'step-up-decide': return rpc(env.ACCOUNTS, auth.account, 'decide-step-up', { id: route.params.id, approve: url.pathname.endsWith('/approve') });
    case 'audiences': return audiences(route, request, env, auth);
    case 'audience-usage': return audienceUsage(route, request, env, auth);
    case 'audience-webhook-test': return audienceWebhookTest(route, request, env, auth);
    case 'account-settings': return accountSettings(route, request, env, auth);
    case 'keys': return keys(route, request, env, auth);
    case 'checkout': return checkout(request, env, auth, dryRun);
    case 'dev-deposit': {
      assert(env.ENVIRONMENT === 'local', 'not_found', 'Not found', 404);
      const body = await readJson(request); money(body.amount_microdollars);
      assert(body.amount_microdollars <= 100_000_000, 'invalid_money', 'At most $100 of development credit at a time');
      return rpc(env.ACCOUNTS, auth.account, 'deposit', { id: request.headers.get('Idempotency-Key') || crypto.randomUUID(), amount: body.amount_microdollars, kind: 'development credit' });
    }
    case 'oidc-configuration': return oidcConfiguration(env);
    case 'oidc-authorize-page': return Response.redirect(`${env.APP_ORIGIN}/authorize.html${url.search}`, 302);
    case 'oidc-authorize': return oidcAuthorize(request, env, auth);
    case 'oidc-token': return oidcToken(request, env);
    case 'oidc-userinfo': return oidcUserinfo(request, env);
    case 'mcp': return mcp(request, env, auth, (path, method, body) => worker.fetch(new Request(new URL(path, request.url), { method, headers: forwardHeaders(request), body: body === undefined ? undefined : JSON.stringify(body) }), env));
    case 'clerk-webhook': return clerkWebhook(request, env);
    case 'stripe-webhook': return stripeWebhook(request, env);
  }
  assert(false, 'not_found', 'Not found', 404);
}

function forwardHeaders(request) {
  const headers = { 'Content-Type': 'application/json', 'Idempotency-Key': request.headers.get('Idempotency-Key') || crypto.randomUUID() };
  for (const name of ['Authorization', 'DPoP', 'CF-Connecting-IP']) if (request.headers.get(name)) headers[name] = request.headers.get(name);
  return headers;
}

/** True when the caller should pay for a read: API keys and non-dashboard devices. */
function meteredRead(request, auth) {
  return request.method === 'GET' && auth && (auth.kind === 'key' || (auth.kind === 'device' && !canAccess({ ...auth, session: false }, SESSION)));
}

const worker = {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(republishStatusLists(env));
    if (new Date(event.scheduledTime ?? Date.now()).getUTCHours() === 2) ctx.waitUntil(runCostMonitor(env));
  },
  async fetch(request, env) {
    const url = new URL(request.url); const path = url.pathname;
    try {
      if (request.method === 'OPTIONS' && WORKER_PATHS.some(p => path.startsWith(p))) return new Response(null, { status: 204, headers: CORS });
      if (env.PUBLIC_LIMITER && (WORKER_PATHS.some(p => path.startsWith(p)) || path === '/mcp')) {
        const limit = await env.PUBLIC_LIMITER.limit({ key: request.headers.get('CF-Connecting-IP') || 'local' });
        assert(limit.success, 'rate_limited', 'Request rate exceeded', 429);
      }
      const idempotency = request.headers.get('Idempotency-Key');
      assert(!idempotency || idempotency.length <= 128, 'invalid_idempotency_key', 'Idempotency-Key must be at most 128 characters');
      const route = matchRoute(request.method, path);
      if (!route && env.ASSETS && request.method === 'GET' && !path.startsWith('/api/')) return env.ASSETS.fetch(request);
      assert(route, 'not_found', 'Not found', 404);
      if (route.free) assert(!(await brakeActive(env)), 'cost_brake', 'This free endpoint is paused by the cost-safety brake; paid endpoints keep working', 503);
      const auth = route.access === PUBLIC ? null : await authenticate(request, env, { anyAudience: route.access === DEVICE || route.access === AUTHENTICATED, recovery: route.handler === 'renew' });
      assert(canAccess(auth, route.access), 'insufficient_scope', 'Credential does not allow this operation', 403);
      let cost = 0;
      if (auth) await rpc(env.ACCOUNTS, auth.account, 'rate-limit', { id: auth.key_id || auth.device?.payload.cid || 'session', limit: auth.session ? 300 : 120 });
      if (meteredRead(request, auth)) cost = (await rpc(env.ACCOUNTS, auth.account, 'charge', { kind: 'read', amount: price('read'), aggregate: true })).charged;
      const data = await handle(route, request, env, auth);
      if (data instanceof Response) return data;
      const total = cost + (data?.cost_microdollars ?? 0);
      return Response.json({ ...data, cost_microdollars: total }, { headers: { ...CORS, 'X-DBA-Cost-Microdollars': String(total) } });
    } catch (error) {
      const response = errorResponse(error);
      for (const [k, v] of Object.entries(CORS)) response.headers.set(k, v);
      if (error.status === 401 && request.headers.get('DPoP')) response.headers.set('WWW-Authenticate', `DPoP error="${error.code || 'invalid_token'}"`);
      return response;
    }
  }
};

export default worker;
