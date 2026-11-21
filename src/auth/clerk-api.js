import { assert } from '../utils/errors.js';

/**
 * Name (or with null, forget) the devicebasedauth.org account a Clerk user signs in to, in the
 * user's public metadata (done/clerk_free_accounts.md §3.6, STATUS B9). Clerk puts it in the
 * session token as `dba_account` once the session token is customized (docs/ops/deployment.md §3).
 * Only this backend can write public metadata. env.CLERK_FETCH replaces fetch in tests only.
 */
export async function setClerkAccountLink(env, userId, account) {
  assert(env.CLERK_SECRET_KEY, 'clerk_unavailable', 'This server has no password sign-in', 503);
  const doFetch = typeof env.CLERK_FETCH === 'function' ? env.CLERK_FETCH : fetch;
  let response;
  try {
    response = await doFetch(`https://api.clerk.com/v1/users/${encodeURIComponent(userId)}/metadata`, {
      method: 'PATCH', headers: { Authorization: `Bearer ${env.CLERK_SECRET_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ public_metadata: { dba_account: account } }), signal: AbortSignal.timeout(10000)
    });
  } catch { response = null; }
  assert(response?.ok, 'clerk_unavailable', 'The sign-in service did not take the change; try again', 502);
}
