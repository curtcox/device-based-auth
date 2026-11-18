import { signJws } from '../../packages/verify/src/jose.js';
import { EVENT_TYP } from '../../packages/verify/src/events.js';
import { activeSigner, issuerName } from './issuer.js';
import { assert } from '../utils/errors.js';
import { randomId } from '../utils/ids.js';

/** Credentials per event; a bulk revocation is split into several events. */
export const EVENT_BATCH = 100;
/** Delivery rounds before a revocation event is dropped (status lists remain authoritative). */
export const WEBHOOK_ATTEMPTS = 4;
/** Delay before round n+1 (after round n failed). */
export const WEBHOOK_BACKOFF_MS = [60000, 600000, 3600000];
const TIMEOUT_MS = 5000;

const isLocalHost = host => host === 'localhost' || host.endsWith('.localhost') || host === '127.0.0.1';

/**
 * Validate a revocation webhook URL for an audience. It must be https on the audience's own
 * (verified) domain or a subdomain of it, on the default port, so the service can never be
 * pointed at someone else's host. Local development also allows http on localhost.
 * Returns the normalized URL or null to remove the webhook.
 */
export function cleanWebhookUrl(value, audience, env) {
  if (value === null || value === '') return null;
  let u; try { u = new URL(String(value)); } catch { assert(false, 'invalid_webhook', 'revocation_webhook must be a URL'); }
  const local = env.ENVIRONMENT === 'local' && isLocalHost(u.hostname);
  assert(u.protocol === 'https:' || (local && u.protocol === 'http:'), 'invalid_webhook', 'revocation_webhook must use https');
  assert(!u.username && !u.password && !u.hash, 'invalid_webhook', 'revocation_webhook cannot contain credentials or a fragment');
  const domain = audience.replace(/:\d+$/, '');
  assert(local || (!u.port && (u.hostname === domain || u.hostname.endsWith(`.${domain}`))), 'invalid_webhook', `revocation_webhook must be on ${domain} or one of its subdomains, on the default port`);
  assert(u.toString().length <= 2048, 'invalid_webhook', 'revocation_webhook is too long');
  return u.toString();
}

/** Sign one event for an audience (spec/events.md). */
export async function signEvent(env, audience, type, body = {}, now = Date.now()) {
  const signer = await activeSigner(env);
  const payload = { iss: issuerName(env), aud: audience, iat: Math.floor(now / 1000), jti: randomId('evt', 16), type, ...body };
  return { jti: payload.jti, jws: await signJws({ typ: EVENT_TYP, kid: signer.kid }, payload, signer.key) };
}

/**
 * POST a signed event. Never follows redirects; any 2xx is success. Returns { ok, status }.
 * env.WEBHOOK_FETCH replaces fetch in tests and local mode.
 */
export async function postEvent(env, url, jws) {
  const fetcher = env.WEBHOOK_FETCH || fetch;
  try {
    const response = await fetcher(url, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/jwt', 'User-Agent': 'devicebasedauth.org-webhooks/1' }, body: jws, signal: AbortSignal.timeout(TIMEOUT_MS) });
    try { await response.body?.cancel(); } catch { /* ignore */ }
    return { ok: response.status >= 200 && response.status < 300, status: response.status };
  } catch (error) {
    return { ok: false, status: 0, error: error.name === 'TimeoutError' ? 'timeout' : 'network_error' };
  }
}
