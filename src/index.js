import { PUBLIC, SESSION, DEVICE, AUTHENTICATED, canAccess, paysForReads, isDashboardSession, UNLOCKED_WHILE_GATED } from './auth/scopes.js';
import { authenticate } from './auth/middleware.js';
import { clerkWebhook } from './auth/clerk-webhook.js';
import { checkout, stripeWebhook } from './api/payments.js';
import { keys } from './api/keys.js';
import { startEnrollment, describeEnrollment, approveEnrollment, denyEnrollment, pollEnrollment, attestationChallenge, tpmActivation } from './api/enrollments.js';
import { enrollmentTokens, redeemEnrollmentToken } from './api/enrollment-tokens.js';
import { caBundle, deviceCertificateFor } from './api/certificates.js';
import { createCredential, listCredentials, getCredential, credentialDecisions, revoke, revokeSelf, renew, token, whoami, confirmCredential, unconfirmCredential } from './api/credentials.js';
import { authorize } from './api/authorize.js';
import { audiences, audienceUsage, audienceWebhookTest } from './api/audiences.js';
import { accountSettings } from './api/settings.js';
import { gates, gateRequests, gateLinks } from './api/gates.js';
import { signInGates, dashboardSession, recoveryCodes } from './api/sign-in-gates.js';
import { pushSubscriptions, pushPublicKey } from './api/push.js';
import { emailConfigured } from './services/email.js';
import { statusList, republishStatusLists, alertStatusCapacity } from './api/status.js';
import { inspect } from './api/inspect.js';
import { oidcConfiguration, oidcAuthorize, oidcToken, oidcUserinfo } from './api/oidc.js';
import { mcp } from './api/mcp.js';
import { protectedResourceMetadata, registerClient, describeClient, resourceMetadataUrl } from './api/mcp-oauth.js';
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
// `free: true` marks public routes stopped by the cost-safety brake. `billable` names the price a
// route charges; `?dry_run=1` on it quotes that price and does nothing else (master plan §7.1).
// `idempotent: true` marks routes that honour an Idempotency-Key: a retry with the same key
// returns what the first request made (src/idempotency.test.js).
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
  { method: 'POST', path: `${V1}/enrollments/tpm-activation`, access: PUBLIC, handler: 'tpm-activation', free: true },
  { method: 'GET', path: `${V1}/enrollments/:id`, access: PUBLIC, handler: 'enroll-poll' },
  { method: 'POST', path: `${V1}/enrollments/approve`, access: SESSION, handler: 'enroll-approve', billable: 'issue' },
  { method: 'POST', path: `${V1}/enrollments/deny`, access: SESSION, handler: 'enroll-deny' },
  { method: 'POST', path: `${V1}/enrollments/redeem`, access: PUBLIC, handler: 'enroll-redeem', billable: 'issue' },
  { method: 'GET', path: `${V1}/enrollment-tokens`, access: 'credentials:issue', handler: 'enrollment-tokens' },
  { method: 'POST', path: `${V1}/enrollment-tokens`, access: 'credentials:issue', handler: 'enrollment-tokens' },
  { method: 'DELETE', path: `${V1}/enrollment-tokens/:id`, access: 'credentials:issue', handler: 'enrollment-tokens' },
  { method: 'GET', path: `${V1}/whoami`, access: AUTHENTICATED, handler: 'whoami' },
  { method: 'GET', path: `${V1}/account`, access: 'account:read', handler: 'account' },
  { method: 'GET', path: `${V1}/account/settings`, access: SESSION, handler: 'account-settings' },
  { method: 'PATCH', path: `${V1}/account/settings`, access: SESSION, handler: 'account-settings' },
  { method: 'GET', path: `${V1}/push-subscriptions`, access: SESSION, handler: 'push-subscriptions' },
  { method: 'POST', path: `${V1}/push-subscriptions`, access: SESSION, handler: 'push-subscriptions' },
  { method: 'DELETE', path: `${V1}/push-subscriptions/:id`, access: SESSION, handler: 'push-subscriptions' },
  { method: 'GET', path: `${V1}/transactions`, access: 'transactions:read', handler: 'transactions' },
  { method: 'GET', path: `${V1}/audit`, access: 'transactions:read', handler: 'audit' },
  { method: 'GET', path: `${V1}/credentials`, access: 'credentials:read', handler: 'credentials-list' },
  { method: 'POST', path: `${V1}/credentials`, access: 'credentials:issue', handler: 'credentials-create', billable: 'issue', idempotent: true },
  { method: 'GET', path: `${V1}/credentials/:cid`, access: 'credentials:read', handler: 'credentials-get' },
  { method: 'DELETE', path: `${V1}/credentials/:cid`, access: 'credentials:revoke', handler: 'revoke-credential' },
  { method: 'GET', path: `${V1}/credentials/:cid/decisions`, access: 'credentials:read', handler: 'credentials-decisions' },
  { method: 'POST', path: `${V1}/credentials/:cid/renew`, access: DEVICE, handler: 'renew', billable: 'renew' },
  { method: 'POST', path: `${V1}/credentials/:cid/confirm`, access: DEVICE, handler: 'confirm', billable: 'confirm' },
  { method: 'POST', path: `${V1}/credentials/:cid/unconfirm`, access: 'credentials:revoke', handler: 'unconfirm' },
  { method: 'GET', path: `${V1}/devices`, access: 'credentials:read', handler: 'devices-list' },
  { method: 'GET', path: `${V1}/devices/:id`, access: 'credentials:read', handler: 'devices-get' },
  { method: 'POST', path: `${V1}/devices/:id/revoke`, access: 'credentials:revoke', handler: 'revoke-device' },
  { method: 'POST', path: `${V1}/revoke-all`, access: 'credentials:revoke', handler: 'revoke-all' },
  { method: 'POST', path: `${V1}/self/revoke`, access: DEVICE, handler: 'revoke-self' },
  { method: 'POST', path: `${V1}/token`, access: DEVICE, handler: 'token', billable: 'token' },
  { method: 'POST', path: `${V1}/certificate`, access: DEVICE, handler: 'certificate', billable: 'token' },
  { method: 'POST', path: `${V1}/authorize`, access: 'authorize', handler: 'authorize', billable: 'decision' },
  { method: 'GET', path: `${V1}/step-ups`, access: SESSION, handler: 'step-ups' },
  { method: 'POST', path: `${V1}/step-ups/:id/approve`, access: SESSION, handler: 'step-up-decide' },
  { method: 'POST', path: `${V1}/step-ups/:id/deny`, access: SESSION, handler: 'step-up-decide' },
  { method: 'GET', path: `${V1}/gates`, access: 'gates:read', handler: 'gates' },
  { method: 'POST', path: `${V1}/gates`, access: 'gates:write', handler: 'gates' },
  { method: 'POST', path: `${V1}/gates/:id/activate`, access: 'gates:write', handler: 'gates' },
  { method: 'POST', path: `${V1}/gates/:id/test`, access: 'gates:write', handler: 'gates' },
  { method: 'DELETE', path: `${V1}/gates/:id`, access: 'gates:write', handler: 'gates' },
  { method: 'GET', path: `${V1}/gate-links/:token`, access: PUBLIC, handler: 'gate-links', free: true },
  { method: 'POST', path: `${V1}/gate-links/:token/answer`, access: PUBLIC, handler: 'gate-links', free: true },
  { method: 'POST', path: `${V1}/gate-links/:token/callback`, access: PUBLIC, handler: 'gate-links', free: true },
  { method: 'GET', path: `${V1}/session`, access: SESSION, handler: 'dashboard-session' },
  { method: 'POST', path: `${V1}/session/confirm`, access: SESSION, handler: 'dashboard-session' },
  { method: 'POST', path: `${V1}/session/recover`, access: SESSION, handler: 'dashboard-session' },
  { method: 'POST', path: `${V1}/settings/recovery-codes`, access: SESSION, handler: 'recovery-codes' },
  { method: 'GET', path: `${V1}/settings/sign-in-gates`, access: 'gates:read', handler: 'sign-in-gates' },
  { method: 'PUT', path: `${V1}/settings/sign-in-gates`, access: 'gates:write', handler: 'sign-in-gates' },
  { method: 'GET', path: `${V1}/gate-requests`, access: AUTHENTICATED, handler: 'gate-requests' },
  { method: 'GET', path: `${V1}/gate-requests/:id`, access: AUTHENTICATED, handler: 'gate-requests' },
  { method: 'POST', path: `${V1}/gate-requests/:id/answer`, access: AUTHENTICATED, handler: 'gate-requests' },
  { method: 'GET', path: `${V1}/audiences`, access: PUBLIC, handler: 'audiences' },
  { method: 'GET', path: `${V1}/audiences/:name`, access: PUBLIC, handler: 'audiences' },
  { method: 'GET', path: `${V1}/audiences/:name/usage`, access: 'audiences:read', handler: 'audience-usage' },
  { method: 'POST', path: `${V1}/audiences`, access: 'audiences:write', handler: 'audiences', billable: 'audience' },
  { method: 'PATCH', path: `${V1}/audiences/:name`, access: 'audiences:write', handler: 'audiences', billable: 'audience' },
  { method: 'POST', path: `${V1}/audiences/:name/webhook-test`, access: 'audiences:write', handler: 'audience-webhook-test' },
  { method: 'GET', path: `${V1}/keys`, access: SESSION, handler: 'keys' },
  { method: 'POST', path: `${V1}/keys`, access: SESSION, handler: 'keys' },
  { method: 'DELETE', path: `${V1}/keys/:id`, access: SESSION, handler: 'keys' },
  { method: 'POST', path: `${V1}/payments/checkout`, access: SESSION, handler: 'checkout', idempotent: true },
  { method: 'POST', path: `${V1}/dev/deposit`, access: SESSION, handler: 'dev-deposit' },
  { method: 'GET', path: '/.well-known/oauth-authorization-server', access: PUBLIC, handler: 'oidc-configuration' },
  { method: 'GET', path: '/.well-known/oauth-protected-resource', access: PUBLIC, handler: 'oauth-resource' },
  { method: 'GET', path: '/.well-known/oauth-protected-resource/mcp', access: PUBLIC, handler: 'oauth-resource' },
  { method: 'POST', path: '/oauth/register', access: PUBLIC, handler: 'oauth-register', free: true },
  { method: 'GET', path: '/oauth/client', access: PUBLIC, handler: 'oauth-client', free: true },
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
const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Authorization, DPoP, Content-Type, Idempotency-Key', 'Access-Control-Expose-Headers': 'X-DBA-Cost-Microdollars, X-DBA-Balance-Microdollars, DPoP-Nonce', 'Access-Control-Max-Age': '86400' };

/**
 * The price a dry run quotes. A renewal with new_key_proof rotates (the issue price); a recovery
 * renewal (withdrawn issuer key, no rotation) is free.
 */
async function dryRunPrice(route, request, auth) {
  if (route.handler !== 'renew') return { op: route.billable, price: price(route.billable) };
  const body = await request.clone().json().catch(() => ({}));
  if (body?.new_key_proof) return { op: 'issue', price: price('issue') };
  return { op: 'renew', price: auth?.device?.recovery ? 0 : price('renew') };
}

/**
 * Callers see the paying account's balance only if they may read the account: a device whose
 * grants cover one site does not learn its owner's balance. Every payer here is auth.account.
 */
const seesBalance = auth => !!auth && canAccess(auth, 'account:read');

async function handle(route, request, env, auth) {
  const url = new URL(request.url);
  const dryRun = url.searchParams.get('dry_run') === '1';
  switch (route.handler) {
    case 'health': return { status: 'ok', environment: env.ENVIRONMENT, git_sha: env.GIT_SHA || 'local' };
    case 'jwks': return new Response(JSON.stringify(jwks(env)), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600', ...CORS } });
    case 'status-list': return statusList(route, env);
    case 'public-config': return { local: env.ENVIRONMENT === 'local', environment: env.ENVIRONMENT, issuer: issuerName(env), audience: appAudience(env), app_origin: env.APP_ORIGIN, status_origin: env.STATUS_ORIGIN, clerk_publishable_key: env.CLERK_PUBLISHABLE_KEY || null, prices: PRICES, price_table: priceTable(), minimum_deposit_cents: MINIMUM_DEPOSIT_CENTS, push_public_key: await pushPublicKey(env), security_email: emailConfigured(env) };
    case 'quote': {
      const op = url.searchParams.get('op');
      assert(Object.hasOwn(PRICES, op || ''), 'invalid_operation', `op must be one of ${Object.keys(PRICES).join(', ')}`);
      return { op, quote_microdollars: price(op) };
    }
    case 'inspect': return inspect(request, env);
    case 'enroll-start': return startEnrollment(request, env);
    case 'enroll-describe': return describeEnrollment(request, env);
    case 'attestation-challenge': return attestationChallenge(env);
    case 'tpm-activation': return tpmActivation(request, env);
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
    case 'confirm': return confirmCredential(route, env, auth);
    case 'unconfirm': return unconfirmCredential(route, env, auth);
    case 'token': return token(request, env, auth);
    case 'certificate': return deviceCertificateFor(request, env, auth);
    case 'ca-bundle': return caBundle(env);
    case 'authorize': return authorize(request, env, auth);
    case 'step-ups': return rpc(env.ACCOUNTS, auth.account, 'list-step-ups');
    case 'step-up-decide': return rpc(env.ACCOUNTS, auth.account, 'decide-step-up', { id: route.params.id, approve: url.pathname.endsWith('/approve'), approver_device: auth.device?.payload.sub });
    case 'gates': return gates(route, request, env, auth);
    case 'gate-requests': return gateRequests(route, request, env, auth);
    case 'gate-links': return gateLinks(route, request, env);
    case 'sign-in-gates': return signInGates(route, request, env, auth);
    case 'dashboard-session': return dashboardSession(route, request, env, auth);
    case 'recovery-codes': return recoveryCodes(request, env, auth);
    case 'audiences': return audiences(route, request, env, auth);
    case 'audience-usage': return audienceUsage(route, request, env, auth);
    case 'audience-webhook-test': return audienceWebhookTest(route, request, env, auth);
    case 'account-settings': return accountSettings(route, request, env, auth);
    case 'push-subscriptions': return pushSubscriptions(route, request, env, auth);
    case 'keys': return keys(route, request, env, auth);
    case 'checkout': return checkout(request, env, auth, dryRun);
    case 'dev-deposit': {
      assert(env.ENVIRONMENT === 'local', 'not_found', 'Not found', 404);
      const body = await readJson(request); money(body.amount_microdollars);
      assert(body.amount_microdollars <= 100_000_000, 'invalid_money', 'At most $100 of development credit at a time');
      return rpc(env.ACCOUNTS, auth.account, 'deposit', { id: request.headers.get('Idempotency-Key') || crypto.randomUUID(), amount: body.amount_microdollars, kind: 'development credit' });
    }
    case 'oidc-configuration': return oidcConfiguration(env);
    case 'oauth-resource': return protectedResourceMetadata(env);
    case 'oauth-register': return registerClient(request, env);
    case 'oauth-client': return describeClient(request, env);
    case 'oidc-authorize-page': return Response.redirect(`${env.APP_ORIGIN}/authorize.html${url.search}`, 302);
    case 'oidc-authorize': return oidcAuthorize(request, env, auth);
    case 'oidc-token': return oidcToken(request, env);
    case 'oidc-userinfo': return oidcUserinfo(request, env);
    case 'mcp': return mcp(request, env, auth, (path, method, body) => {
      const inner = new Request(new URL(path, request.url), { method, headers: forwardHeaders(request), body: body === undefined ? undefined : JSON.stringify(body) });
      // The tool call acts as the caller already authenticated (and rate-limited) for /mcp.
      authenticated.set(inner, auth);
      return worker.fetch(inner, env);
    });
    case 'clerk-webhook': return clerkWebhook(request, env);
    case 'stripe-webhook': return stripeWebhook(request, env);
  }
  assert(false, 'not_found', 'Not found', 404);
}

// Requests made inside this Worker for an MCP tool call, mapped to the caller's authentication.
// Only code holding the Request object can add one, so no client can claim an entry.
const authenticated = new WeakMap();

function forwardHeaders(request) {
  const headers = { 'Content-Type': 'application/json', 'Idempotency-Key': request.headers.get('Idempotency-Key') || crypto.randomUUID() };
  for (const name of ['Authorization', 'DPoP', 'CF-Connecting-IP']) if (request.headers.get(name)) headers[name] = request.headers.get(name);
  return headers;
}

const meteredRead = (request, auth) => request.method === 'GET' && paysForReads(auth);

const worker = {
  async scheduled(event, env, ctx) {
    const daily = new Date(event.scheduledTime ?? Date.now()).getUTCHours() === 2;
    ctx.waitUntil(republishStatusLists(env).then(capacity => daily ? alertStatusCapacity(env, capacity) : false));
    if (daily) ctx.waitUntil(runCostMonitor(env));
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
      const auth = route.access === PUBLIC ? null : authenticated.get(request) ?? await authenticate(request, env, { anyAudience: route.access === DEVICE || route.access === AUTHENTICATED, recovery: route.handler === 'renew' });
      assert(canAccess(auth, route.access), 'insufficient_scope', 'Credential does not allow this operation', 403);
      // The dashboard's sign-in gate (STATUS B7): an unconfirmed dashboard session can only confirm
      // itself, ask who it is, and revoke.
      assert(!(auth?.dashboard === 'locked' && isDashboardSession(auth) && !UNLOCKED_WHILE_GATED.has(route.handler)), 'sign_in_gate_required', 'Confirm this sign-in first: your dashboard sign-in gate has not approved it yet (POST /api/v1/session/confirm)', 403);
      let cost = 0; let balance;
      // Authentication normally checks the caller's request limit in the same call (auth.rated).
      if (auth && !auth.rated) await rpc(env.ACCOUNTS, auth.account, 'rate-limit', { id: auth.key_id || auth.device?.payload.cid || 'session', limit: auth.session ? 300 : 120 });
      if (route.billable && url.searchParams.get('dry_run') === '1') {
        // Quote only: nothing is validated, reserved or charged. Reading the balance is a read, and
        // costs what a read costs this caller (free from the dashboard).
        const quote = await dryRunPrice(route, request, auth);
        const data = { dry_run: true, op: quote.op, price_microdollars: quote.price };
        if (seesBalance(auth)) {
          if (paysForReads(auth)) ({ charged: cost, balance_microdollars: balance } = await rpc(env.ACCOUNTS, auth.account, 'charge', { kind: 'read', amount: price('read'), aggregate: true }));
          else balance = (await rpc(env.ACCOUNTS, auth.account, 'account')).balance_microdollars;
          Object.assign(data, { balance_microdollars: balance, sufficient: balance >= quote.price });
        }
        return Response.json({ ...data, cost_microdollars: cost }, { headers: { ...CORS, 'X-DBA-Cost-Microdollars': String(cost), ...(balance === undefined ? {} : { 'X-DBA-Balance-Microdollars': String(balance) }) } });
      }
      if (meteredRead(request, auth)) ({ charged: cost, balance_microdollars: balance } = await rpc(env.ACCOUNTS, auth.account, 'charge', { kind: 'read', amount: price('read'), aggregate: true }));
      const data = await handle(route, request, env, auth);
      if (data instanceof Response) return data;
      const total = cost + (data?.cost_microdollars ?? 0);
      const { balance_microdollars: reported, ...rest } = data ?? {};
      balance = reported ?? balance;
      const shown = balance !== undefined && seesBalance(auth);
      return Response.json({ ...rest, ...(shown ? { balance_microdollars: balance } : {}), cost_microdollars: total }, { headers: { ...CORS, 'X-DBA-Cost-Microdollars': String(total), ...(shown ? { 'X-DBA-Balance-Microdollars': String(balance) } : {}) } });
    } catch (error) {
      const response = errorResponse(error);
      for (const [k, v] of Object.entries(CORS)) response.headers.set(k, v);
      if (error.status === 401 && request.headers.get('DPoP')) response.headers.set('WWW-Authenticate', `DPoP error="${error.code || 'invalid_token'}"`);
      // MCP clients discover how to get a token from this header (MCP authorization, RFC 9728 §5.1).
      else if (error.status === 401 && path === '/mcp') response.headers.set('WWW-Authenticate', `Bearer resource_metadata="${resourceMetadataUrl(env)}"${request.headers.get('Authorization') ? ', error="invalid_token"' : ''}`);
      return response;
    }
  }
};

export default worker;
