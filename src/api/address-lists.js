import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { requireRecentSignIn } from '../auth/reverify.js';
import { ADDRESS_LIST_ID } from '../../packages/verify/src/net.js';
import { cleanAddressListInput, addressListKey } from '../services/address-lists.js';

// 10,000 ranges of up to 43 characters each, quoted and separated.
const BODY_LIMIT = 600 * 1024;

/**
 * Named address lists (STATUS B10 N3, todo/network_constraints.md §4). GET lists or reads them;
 * POST creates one; PUT replaces its ranges (and name); DELETE publishes a tombstone. Replacing
 * and deleting need a recent sign-in, as gate changes do: widening a list widens every grant that
 * names it, and deleting one stops them all.
 */
export async function addressLists(route, request, env, auth) {
  const id = route.params.id;
  assert(id === undefined || ADDRESS_LIST_ID.test(id), 'not_found', 'Address list not found', 404);
  if (request.method === 'GET') return id ? rpc(env.ACCOUNTS, auth.account, 'get-address-list', { id }) : rpc(env.ACCOUNTS, auth.account, 'list-address-lists');
  if (request.method === 'POST') return rpc(env.ACCOUNTS, auth.account, 'create-address-list', { input: cleanAddressListInput(await readJson(request, BODY_LIMIT), { create: true }) });
  if (request.method === 'PUT') {
    requireRecentSignIn(auth, 'change an address list');
    return rpc(env.ACCOUNTS, auth.account, 'replace-address-list', { id, input: cleanAddressListInput(await readJson(request, BODY_LIMIT), { create: false }) });
  }
  requireRecentSignIn(auth, 'delete an address list');
  return rpc(env.ACCOUNTS, auth.account, 'delete-address-list', { id });
}

const HEADERS = { 'Content-Type': 'application/jwt', 'Cache-Control': 'public, max-age=60', 'Access-Control-Allow-Origin': '*' };

/**
 * GET /status/v1/addresses/:id: a published list through the Worker (production verifiers fetch
 * status.devicebasedauth.org, the same R2 object behind the CDN; local mode uses this route).
 */
export async function publishedAddressList(route, env) {
  assert(ADDRESS_LIST_ID.test(route.params.id), 'not_found', 'Unknown address list', 404);
  const object = await env.STATUS_BUCKET.get(addressListKey(route.params.id));
  assert(object, 'not_found', 'Unknown address list', 404);
  return new Response(await object.text(), { headers: HEADERS });
}
