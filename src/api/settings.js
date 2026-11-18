import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { SETTINGS_LIMITS } from '../durable-objects/account-do.js';

/**
 * Account budget guards (dashboard only): GET returns them, PATCH changes the members given.
 * A limit is a whole number in its range; the renewal cap may also be null (no cap).
 */
export async function accountSettings(route, request, env, auth) {
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'get-settings');
  const body = await readJson(request, 4096);
  const changes = {};
  for (const [name, value] of Object.entries(body)) {
    const range = SETTINGS_LIMITS[name];
    assert(range, 'invalid_setting', `Unknown setting ${name}`);
    if (value === null && name === 'max_renewals_per_credential_per_month') { changes[name] = null; continue; }
    assert(Number.isSafeInteger(value) && value >= range[0] && value <= range[1], 'invalid_setting', `${name} must be a whole number from ${range[0]} to ${range[1]}${name === 'max_renewals_per_credential_per_month' ? ', or null for no cap' : ''}`);
    changes[name] = value;
  }
  assert(Object.keys(changes).length, 'invalid_setting', 'Give at least one setting to change');
  return rpc(env.ACCOUNTS, auth.account, 'update-settings', { changes });
}
