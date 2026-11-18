/**
 * JSON transport for the same-origin API. Adds the signed-in user's Authorization (and, for
 * device sign-in, a DPoP proof bound to this exact method and URL) and turns the
 * `{ error, code, ... }` envelope into an ApiError.
 */
import { authHeaders, handleUnauthorized } from './auth.js';

/** An API failure carrying the server's machine-readable code and HTTP status. */
export class ApiError extends Error {
  constructor(message, { code, status, details } = {}) { super(message); this.name = 'ApiError'; this.code = code; this.status = status; this.details = details || {}; }
}

/**
 * Call the API.
 * @param {string} path e.g. "/api/v1/credentials?status=active"
 * @param {{ method?: string, body?: unknown, auth?: boolean, idempotencyKey?: string }} [options]
 * @returns {Promise<any>} parsed JSON; billable responses include cost_microdollars
 */
export async function api(path, { method = 'GET', body, auth = true, idempotencyKey } = {}) {
  const url = new URL(path, location.origin).href;
  const send = async () => {
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (method !== 'GET') headers['Idempotency-Key'] = idempotencyKey || crypto.randomUUID();
    if (auth) Object.assign(headers, await authHeaders(method, url));
    return fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  };
  let response = await send();
  // A revoked dashboard device credential falls back to another sign-in, once.
  if (response.status === 401 && auth && await handleUnauthorized()) response = await send();
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text.slice(0, 200) || `HTTP ${response.status}` }; }
  if (!response.ok) {
    const { error, code, ...details } = data || {};
    throw new ApiError(error || data?.error_description || `HTTP ${response.status}`, { code: code || data?.error || 'http_error', status: response.status, details });
  }
  return data;
}
