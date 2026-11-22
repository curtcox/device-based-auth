/** The HTTP client every command uses to talk to devicebasedauth.org. */
import { ApiError } from './errors.js';
import { deviceHeaders } from './device-key.js';

/**
 * A small client for the devicebasedauth.org API. `device` ({ key, credential }) authenticates a
 * request with the credential and a fresh DPoP proof for that exact method and URL.
 * Failures throw ApiError with the server's { error, code }.
 *
 * DPoP nonces (RFC 9449 §8, STATUS D15): an account object that started less than a minute ago
 * answers 401 use_dpop_nonce with its nonce; the request is sent once more with it, and the nonce
 * goes into later proofs to the same origin.
 */
export function createClient({ origin, fetch = (...args) => globalThis.fetch(...args) }) {
  const nonces = new Map();
  async function send(method, url, { body, device, apiKey }) {
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (apiKey) headers.Authorization = `ApiKey ${apiKey}`;
    else if (device) Object.assign(headers, await deviceHeaders({ ...device, method, url, nonce: nonces.get(new URL(url).origin) }));
    let response;
    try { response = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }); }
    catch (error) { throw new ApiError(`Could not reach ${new URL(url).origin}: ${error.cause?.message || error.message}`, 'network_error'); }
    const text = await response.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON; reported below */ }
    const nonce = response.headers.get('DPoP-Nonce') || (typeof json?.dpop_nonce === 'string' ? json.dpop_nonce : null);
    const challenged = response.status === 401 && json?.code === 'use_dpop_nonce' && !!nonce && nonce !== nonces.get(new URL(url).origin);
    if (nonce && device) nonces.set(new URL(url).origin, nonce);
    return { response, json, challenged };
  }

  async function request(method, path, { body, device, apiKey, retryNonce = true } = {}) {
    const url = new URL(path, origin).toString();
    let { response, json, challenged } = await send(method, url, { body, device, apiKey });
    if (challenged && retryNonce) ({ response, json } = await send(method, url, { body, device, apiKey }));
    if (!response.ok) throw new ApiError(json?.error || `HTTP ${response.status}`, json?.code || 'http_error', response.status, json);
    if (json === null) throw new ApiError(`Expected JSON from ${url}`, 'invalid_response', response.status);
    return json;
  }

  /**
   * The DPoP nonce to put in a proof for `url`, for commands that hand the proof to another
   * program and cannot send twice (`dba curl`, `dba headers`, `dba sign`): only for this origin,
   * from POST /api/v1/dpop-nonce (free; a just-started object answers it with the challenge, which
   * carries the same nonce). undefined for other sites.
   */
  async function nonceFor(device, url) {
    const target = new URL(url).origin;
    if (target !== new URL(origin).origin) return nonces.get(target);
    try { await request('POST', '/api/v1/dpop-nonce', { device, retryNonce: false }); }
    catch (error) { if (error.code !== 'use_dpop_nonce') throw error; }
    return nonces.get(target);
  }

  return { origin, request, nonceFor };
}
