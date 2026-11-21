import { verifyWebhook } from '@clerk/backend/webhooks';
import { assert, readText } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';

/**
 * Clerk verifies Svix signatures and timestamps. user.created/user.updated create the account (or
 * update the one the user is linked to, `public_metadata.dba_account`, which must name the user
 * back: account/clerk-link.js) and carry the address Clerk verified. user.deleted never closes an
 * account: it forgets the link and the address that came from Clerk (STATUS B9).
 */
export async function clerkWebhook(request, env) {
  let event; const payload = await readText(request);
  const bounded = new Request(request.url, { method: 'POST', headers: request.headers, body: payload });
  try { event = await verifyWebhook(bounded, { signingSecret: env.CLERK_WEBHOOK_SECRET }); }
  catch { assert(false, 'invalid_signature', 'Invalid webhook signature', 400); }
  const user = event.data?.id;
  if (event.type === 'user.created' || event.type === 'user.updated') {
    // The primary address Clerk verified is where security emails go (STATUS S8); none clears it.
    const primary = (event.data.email_addresses || []).find(e => e.id === event.data.primary_email_address_id);
    const verified = primary?.verification?.status === 'verified' ? primary.email_address : null;
    const linked = event.data.public_metadata?.dba_account;
    const account = typeof linked === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(linked) ? linked : user;
    try { await rpc(env.ACCOUNTS, account, 'init', { account, email: verified, ...(account !== user ? { link_sub: user } : {}) }); }
    catch (error) {
      // A link the account no longer names back (unlinked while Clerk kept the metadata): ignore
      // it rather than have Clerk retry for days.
      if (error.code !== 'invalid_auth') throw error;
      return { received: true, ignored: 'stale link' };
    }
  }
  if (event.type === 'user.deleted' && typeof user === 'string') {
    const own = await rpc(env.ACCOUNTS, user, 'clerk-gone', { sub: user });
    if (own.linked_to) await rpc(env.ACCOUNTS, own.linked_to, 'clerk-gone', { sub: user });
  }
  return { received: true };
}
