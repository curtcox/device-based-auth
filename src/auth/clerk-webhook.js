import { verifyWebhook } from '@clerk/backend/webhooks';
import { assert, readText } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
/** Clerk verifies Svix signatures and timestamps before creating an account. */
export async function clerkWebhook(request, env) {
  let event; const payload = await readText(request);
  const bounded = new Request(request.url, { method: 'POST', headers: request.headers, body: payload });
  try { event = await verifyWebhook(bounded, { signingSecret: env.CLERK_WEBHOOK_SECRET }); }
  catch { assert(false, 'invalid_signature', 'Invalid webhook signature', 400); }
  if (event.type === 'user.created' || event.type === 'user.updated') await rpc(env.ACCOUNTS, event.data.id, 'init', { account: event.data.id });
  return { received: true };
}
