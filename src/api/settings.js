import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { SETTINGS_LIMITS, SETTINGS_CHOICES } from '../durable-objects/account-do.js';
import { requireRecentSignIn } from '../auth/reverify.js';

/**
 * Account budget guards and security emails (dashboard only): GET returns them, PATCH changes
 * the members given. A limit is a whole number in its range; the renewal cap may also be null (no
 * cap). security_email is one of SETTINGS_CHOICES.security_email, fewest emails first.
 */
export async function accountSettings(route, request, env, auth) {
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'get-settings');
  const body = await readJson(request, 4096);
  const changes = {};
  for (const [name, value] of Object.entries(body)) {
    const choices = SETTINGS_CHOICES[name];
    if (choices) { assert(choices.includes(value), 'invalid_setting', `${name} must be one of ${choices.join(', ')}`); changes[name] = value; continue; }
    const range = SETTINGS_LIMITS[name];
    assert(range, 'invalid_setting', `Unknown setting ${name}`);
    if (value === null && name === 'max_renewals_per_credential_per_month') { changes[name] = null; continue; }
    assert(Number.isSafeInteger(value) && value >= range[0] && value <= range[1], 'invalid_setting', `${name} must be a whole number from ${range[0]} to ${range[1]}${name === 'max_renewals_per_credential_per_month' ? ', or null for no cap' : ''}`);
    changes[name] = value;
  }
  assert(Object.keys(changes).length, 'invalid_setting', 'Give at least one setting to change');
  // Lowering a limit is always allowed; raising one is what a thief would do, and so is silencing
  // the security emails that would tell the owner.
  const current = await rpc(env.ACCOUNTS, auth.account, 'get-settings');
  const raises = Object.entries(changes).some(([name, value]) => SETTINGS_LIMITS[name] && current[name] !== null && (value === null || value > current[name]));
  if (raises) requireRecentSignIn(auth, 'raise a budget limit');
  const levels = SETTINGS_CHOICES.security_email;
  if (changes.security_email && levels.indexOf(changes.security_email) < levels.indexOf(current.security_email)) requireRecentSignIn(auth, 'turn security emails down');
  return rpc(env.ACCOUNTS, auth.account, 'update-settings', { changes });
}
