import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { requireRecentSignIn } from '../auth/reverify.js';
import { validateGrant, grantGates } from '../../packages/verify/src/grants.js';
import { AUDIENCE_NAME } from '../durable-objects/registry-do.js';

/**
 * Gate entries for sign-in (todo/additional_gates.md §3.3): the same shape as require.gates.
 * The owner gate cannot gate a sign-in: the owner is the one signing in.
 */
export function cleanSignInEntries(entries, path) {
  if (entries === null) return null;
  const problems = validateGrant({ actions: ['x:y'], require: { gates: entries } }, path).map(p => p.replace(`${path}.require.gates`, path));
  assert(!problems.length, 'invalid_gates', problems.join('; '));
  assert(!entries.some(e => e.any.includes('owner')), 'invalid_gates', `${path}: the owner gate cannot gate a sign-in (the owner is who signs in); use a device, an authenticator app, a security key or a webhook`);
  return grantGates({ require: { gates: entries } });
}

/**
 * GET/PUT /api/v1/settings/sign-in-gates: { default, audiences: { <client>: entries }, dashboard }.
 * Changing them needs a recent sign-in and is announced (plan §3.3, §8).
 */
export async function signInGates(route, request, env, auth) {
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'get-sign-in-gates');
  requireRecentSignIn(auth, 'change your sign-in gates');
  const body = await readJson(request, 16384);
  for (const key of Object.keys(body)) assert(['default', 'audiences', 'dashboard'].includes(key), 'invalid_gates', `${key} is not a sign-in gate setting (default, audiences, dashboard)`);
  const settings = {};
  if (body.default !== undefined) settings.default = cleanSignInEntries(body.default, 'default');
  if (body.dashboard !== undefined) settings.dashboard = cleanSignInEntries(body.dashboard, 'dashboard');
  if (body.audiences !== undefined) {
    assert(body.audiences && typeof body.audiences === 'object' && !Array.isArray(body.audiences) && Object.keys(body.audiences).length <= 50, 'invalid_gates', 'audiences maps up to 50 site names to gate entries');
    settings.audiences = {};
    for (const [name, entries] of Object.entries(body.audiences)) {
      assert(AUDIENCE_NAME.test(name), 'invalid_gates', `audiences: ${name.slice(0, 80)} is not a site name`);
      settings.audiences[name] = cleanSignInEntries(entries, `audiences["${name}"]`);
    }
  }
  return rpc(env.ACCOUNTS, auth.account, 'put-sign-in-gates', { settings });
}
