import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { randomId } from '../utils/ids.js';
import { cleanSubscription, vapidKeys, noticeText } from '../services/push.js';

/**
 * Browsers that get security notices (master plan §10). Signed-in owners only; free, at most
 * MAX_SUBSCRIPTIONS per account. Adding one sends it a first notice; removing one tells them all.
 */
export async function pushSubscriptions(route, request, env, auth) {
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'push-list');
  if (request.method === 'DELETE') return rpc(env.ACCOUNTS, auth.account, 'push-unsubscribe', { id: route.params.id });
  assert(await vapidKeys(env), 'push_unavailable', 'Security notices are not configured on this server', 503);
  const body = await readJson(request);
  const subscription = cleanSubscription(body.subscription, env);
  const name = noticeText(body.name) || 'Browser';
  return rpc(env.ACCOUNTS, auth.account, 'push-subscribe', { id: randomId('psh', 12), subscription, name });
}

/** The VAPID public key browsers subscribe with (null when push is not configured). */
export async function pushPublicKey(env) {
  return (await vapidKeys(env))?.publicKey ?? null;
}
