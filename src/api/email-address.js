import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { digest, verifyToken } from '../auth/tokens.js';
import { requireRecentSignIn } from '../auth/reverify.js';

// An address devicebasedauth.org verifies itself, for security email and recovery by email
// (todo/clerk_free_accounts.md §3.5, §3.7, STATUS B9). The registry maps each verified address
// (hashed) to the one account it recovers.

/** How the registry knows an address: SHA-256 of it lower-cased, so it never stores the address. */
export const emailHash = address => digest(`dba-email\n${String(address).trim().toLowerCase()}`);

/**
 * POST /api/v1/account/email { email }: email a verification link there (charged the notice price;
 * the address changes once the link is used). DELETE: stop using the address. Both need a recent
 * sign-in: the address can recover the account.
 */
export async function accountEmail(request, env, auth) {
  if (request.method === 'DELETE') {
    requireRecentSignIn(auth, 'remove your security email address');
    const removed = await rpc(env.ACCOUNTS, auth.account, 'email-remove', {});
    if (removed.removed && removed.source === 'verified') await rpc(env.REGISTRY, 'global', 'email-release', { hash: await emailHash(removed.removed), account: auth.account });
    return { removed: !!removed.removed };
  }
  requireRecentSignIn(auth, 'change your security email address');
  const body = await readJson(request, 1024);
  return rpc(env.ACCOUNTS, auth.account, 'email-verify-start', { address: body.email, account: auth.account });
}

/**
 * POST /api/v1/account/email/verify { token } (from the emailed link, on /email-link.html): the
 * address becomes the account's security email and recovery address. 409 email_in_use when
 * another account recovers by that address already.
 */
export async function verifyEmail(request, env) {
  const body = await readJson(request, 4096);
  const data = await verifyToken(body.token || '', 'emv_', env.TOKEN_SIGNING_KEY);
  assert(data, 'invalid_link', 'This link is not valid any more; ask for a new one on the Account page', 410);
  const check = await rpc(env.ACCOUNTS, data.a, 'email-verify-check', { nonce: data.n });
  const hash = await emailHash(check.address);
  await rpc(env.REGISTRY, 'global', 'email-claim', { hash, account: data.a });
  const done = await rpc(env.ACCOUNTS, data.a, 'email-verify-finish', { nonce: data.n });
  if (check.previous && (await emailHash(check.previous)) !== hash) await rpc(env.REGISTRY, 'global', 'email-release', { hash: await emailHash(check.previous), account: data.a });
  return { status: 'verified', ...done };
}
