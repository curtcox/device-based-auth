/**
 * Push MFA vendors as gates (STATUS B7, done/additional_gates.md §4.2, phase G8): Duo Push through
 * the Duo Auth API, and Okta Verify push through the Okta Factors API. DBA starts a push when a
 * gate request opens, then polls its status (at most every POLL_INTERVAL_MS, for at most
 * MAX_POLLS polls); answers are never taken from a client. Vendor hosts are pinned to the vendors'
 * own domains so a gate cannot point DBA at anything else.
 */
import { assert } from '../utils/errors.js';

export const POLL_INTERVAL_MS = 5000;
export const MAX_POLLS = 24;
const TIMEOUT_MS = 10000;
const encoder = new TextEncoder();

const DUO_HOST = /^api-[a-z0-9]{1,32}\.duosecurity\.com$/;
const OKTA_HOST = /^[a-z0-9][a-z0-9-]{0,62}\.(okta|oktapreview|okta-emea|okta-gov)\.com$/;
const OKTA_ID = /^[A-Za-z0-9]{15,30}$/;

/** Clean the vendor part of a new gate. Returns { config (stored), secret (to seal) }. */
export function cleanVendorInput(body) {
  if (body.kind === 'duo') {
    const host = String(body.api_host ?? '').toLowerCase();
    assert(DUO_HOST.test(host), 'invalid_gate', 'api_host must be your Duo API hostname (api-XXXXXXXX.duosecurity.com)');
    assert(/^DI[A-Z0-9]{18}$/.test(String(body.integration_key ?? '')), 'invalid_gate', 'integration_key must be the Auth API application\'s integration key (DI…, 20 characters)');
    assert(typeof body.secret_key === 'string' && /^[A-Za-z0-9]{40}$/.test(body.secret_key), 'invalid_gate', 'secret_key must be the Auth API application\'s 40-character secret key');
    assert(typeof body.username === 'string' && body.username.length >= 1 && body.username.length <= 100, 'invalid_gate', 'username must be the Duo user to push to');
    return { config: { api_host: host, integration_key: body.integration_key, username: body.username }, secret: body.secret_key };
  }
  let url;
  try { url = new URL(String(body.org_url ?? '')); } catch { assert(false, 'invalid_gate', 'org_url must be your Okta org URL'); }
  assert(url.protocol === 'https:' && !url.port && OKTA_HOST.test(url.hostname) && (url.pathname === '/' || url.pathname === ''), 'invalid_gate', 'org_url must be https://<your org>.okta.com (or oktapreview.com, okta-emea.com)');
  assert(typeof body.api_token === 'string' && body.api_token.length >= 20 && body.api_token.length <= 200 && /^[\x21-\x7e]+$/.test(body.api_token), 'invalid_gate', 'api_token must be an Okta API token');
  assert(OKTA_ID.test(String(body.user_id ?? '')) && OKTA_ID.test(String(body.factor_id ?? '')), 'invalid_gate', 'user_id and factor_id must be the Okta user and its Okta Verify push factor');
  return { config: { org_url: url.origin, user_id: body.user_id, factor_id: body.factor_id }, secret: body.api_token };
}

const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
// RFC 3986 encoding, as Duo canonicalizes parameters.
const rfc3986 = value => encodeURIComponent(value).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/**
 * Sign a Duo API request (Duo's documented v2 canonical request: date, method, host, path and
 * the sorted, RFC 3986-encoded parameters, one per line, HMAC-SHA1 with the secret key, hex):
 * returns the Date and Authorization headers and the encoded parameters.
 */
export async function duoSign({ method, host, path, params, ikey, skey, date }) {
  const body = Object.keys(params).sort().map(k => `${rfc3986(k)}=${rfc3986(params[k])}`).join('&');
  const canonical = [date, method.toUpperCase(), host.toLowerCase(), path, body].join('\n');
  const key = await crypto.subtle.importKey('raw', encoder.encode(skey), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const signature = hex(await crypto.subtle.sign('HMAC', key, encoder.encode(canonical)));
  return { body, headers: { Date: date, Authorization: `Basic ${btoa(`${ikey}:${signature}`)}` } };
}

async function call(fetcher, url, init) {
  const response = await fetcher(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
  let json = null;
  try { json = await response.json(); } catch { json = null; }
  return { status: response.status, json };
}

/**
 * Start a push. Returns { token } to poll with ({ txid } for Duo, { poll } for Okta), or
 * { failed: reason }. `what` describes the request for the approver's push screen.
 */
export async function startPush(gate, secret, what, { fetcher, now = Date.now() }) {
  try {
    if (gate.kind === 'duo') {
      const date = new Date(now).toUTCString().replace('GMT', '-0000');
      const params = { username: gate.username, factor: 'push', device: 'auto', async: '1', type: 'devicebasedauth.org', pushinfo: new URLSearchParams(what).toString() };
      const signed = await duoSign({ method: 'POST', host: gate.api_host, path: '/auth/v2/auth', params, ikey: gate.integration_key, skey: secret, date });
      const r = await call(fetcher, `https://${gate.api_host}/auth/v2/auth`, { method: 'POST', headers: { ...signed.headers, 'Content-Type': 'application/x-www-form-urlencoded' }, body: signed.body });
      if (r.status === 200 && r.json?.stat === 'OK' && typeof r.json.response?.txid === 'string') return { token: { txid: r.json.response.txid } };
      return { failed: `duo ${r.status} ${r.json?.message ?? r.json?.stat ?? ''}`.trim() };
    }
    const r = await call(fetcher, `${gate.org_url}/api/v1/users/${gate.user_id}/factors/${gate.factor_id}/verify`, { method: 'POST', headers: { Authorization: `SSWS ${secret}`, Accept: 'application/json', 'Content-Type': 'application/json' }, body: '{}' });
    const poll = r.json?._links?.poll?.href;
    if ((r.status === 200 || r.status === 201) && r.json?.factorResult === 'WAITING' && typeof poll === 'string' && poll.startsWith(`${gate.org_url}/api/v1/users/${gate.user_id}/factors/${gate.factor_id}/transactions/`)) return { token: { poll } };
    return { failed: `okta ${r.status} ${r.json?.errorCode ?? r.json?.factorResult ?? ''}`.trim() };
  } catch (error) {
    return { failed: error.name === 'TimeoutError' ? 'timeout' : 'network error' };
  }
}

/** Poll a push: 'allow', 'deny', or null while it waits (or when the vendor cannot say). */
export async function pollPush(gate, secret, token, { fetcher, now = Date.now() }) {
  try {
    if (gate.kind === 'duo') {
      const date = new Date(now).toUTCString().replace('GMT', '-0000');
      const signed = await duoSign({ method: 'GET', host: gate.api_host, path: '/auth/v2/auth_status', params: { txid: token.txid }, ikey: gate.integration_key, skey: secret, date });
      const r = await call(fetcher, `https://${gate.api_host}/auth/v2/auth_status?${signed.body}`, { method: 'GET', headers: signed.headers });
      const result = r.json?.response?.result;
      return result === 'allow' ? 'allow' : result === 'deny' ? 'deny' : null;
    }
    const r = await call(fetcher, token.poll, { method: 'GET', headers: { Authorization: `SSWS ${secret}`, Accept: 'application/json' } });
    const result = r.json?.factorResult;
    return result === 'SUCCESS' ? 'allow' : result === 'REJECTED' ? 'deny' : null;
  } catch {
    return null;
  }
}
