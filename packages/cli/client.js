/** The HTTP client every command uses to talk to devicebasedauth.org. */
import { ApiError } from './errors.js';
import { deviceHeaders } from './device-key.js';

/**
 * A small client for the devicebasedauth.org API. `device` ({ key, credential }) authenticates a
 * request with the credential and a fresh DPoP proof for that exact method and URL.
 * Failures throw ApiError with the server's { error, code }.
 */
export function createClient({ origin, fetch = (...args) => globalThis.fetch(...args) }) {
  async function request(method, path, { body, device, apiKey } = {}) {
    const url = new URL(path, origin).toString();
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (apiKey) headers.Authorization = `ApiKey ${apiKey}`;
    else if (device) Object.assign(headers, await deviceHeaders({ ...device, method, url }));
    let response;
    try { response = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }); }
    catch (error) { throw new ApiError(`Could not reach ${new URL(url).origin}: ${error.cause?.message || error.message}`, 'network_error'); }
    const text = await response.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON; reported below */ }
    if (!response.ok) throw new ApiError(json?.error || `HTTP ${response.status}`, json?.code || 'http_error', response.status, json);
    if (json === null) throw new ApiError(`Expected JSON from ${url}`, 'invalid_response', response.status);
    return json;
  }
  return { origin, request };
}
