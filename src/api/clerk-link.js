import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { requireRecentSignIn } from '../auth/reverify.js';
import { verifyClerkSession, clerkAccount } from '../auth/middleware.js';
import { setClerkAccountLink } from '../auth/clerk-api.js';

/**
 * POST /api/v1/account/clerk-link { session_token }: let the Clerk user who holds that session sign
 * in to this account (done/clerk_free_accounts.md §3.6, STATUS B9). Refused when that user already
 * opens another account, or has its own account with money or credentials. DELETE: stop it; needs
 * another way in (a dashboard device, recovery codes, a passkey, a verified address). Both need a
 * recent sign-in: a sign-in is a way into the account.
 */
export async function clerkLink(request, env, auth) {
  if (request.method === 'DELETE') {
    requireRecentSignIn(auth, 'unlink a sign-in from your account');
    const { sub } = await rpc(env.ACCOUNTS, auth.account, 'clerk-unlink', {});
    await setClerkAccountLink(env, sub, null);
    return { linked: false };
  }
  requireRecentSignIn(auth, 'link a sign-in to your account');
  assert(env.CLERK_SECRET_KEY, 'clerk_unavailable', 'This server has no password sign-in', 503);
  const body = await readJson(request, 16384);
  assert(typeof body.session_token === 'string' && body.session_token.length <= 8192, 'invalid_request', 'session_token is the Clerk session token of the sign-in to link');
  const claims = await verifyClerkSession(env, body.session_token);
  assert(claims.sub !== auth.account, 'already_linked', 'That sign-in is this account\'s own', 409);
  assert(clerkAccount(claims) === claims.sub || clerkAccount(claims) === auth.account, 'clerk_user_linked', 'That sign-in already opens another account', 409);
  const { has_history: used } = await rpc(env.ACCOUNTS, claims.sub, 'clerk-history', { for_account: auth.account });
  assert(!used, 'clerk_user_has_account', 'That sign-in already has its own devicebasedauth.org account with a balance or credentials; use another sign-in', 409);
  // The account first: if Clerk's update then fails, nothing opens it yet and linking again works.
  await rpc(env.ACCOUNTS, auth.account, 'clerk-link', { sub: claims.sub });
  await rpc(env.ACCOUNTS, claims.sub, 'clerk-mark-linked', { account: claims.sub, linked_to: auth.account });
  await setClerkAccountLink(env, claims.sub, auth.account);
  return { linked: true };
}
