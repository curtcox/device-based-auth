import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { randomId } from '../utils/ids.js';
import { parseScopes } from '../auth/scopes.js';
import { signToken, digest } from '../auth/tokens.js';
import { API_KEY_PREFIX } from '../auth/middleware.js';

/** Account API keys (session only). The secret is shown once; only its digest is stored. */
export async function keys(route, request, env, auth) {
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'list-keys');
  if (request.method === 'DELETE') return rpc(env.ACCOUNTS, auth.account, 'revoke-key', { id: route.params.id });
  const body = await readJson(request);
  const scopes = parseScopes(body.scopes);
  assert(scopes, 'invalid_scopes', 'scopes must list known scopes');
  const name = String(body.name ?? 'API key').replace(/[\p{Cc}\p{Cf}]/gu, '').slice(0, 64) || 'API key';
  const id = randomId('key', 12);
  const secret = await signToken(API_KEY_PREFIX, { account: auth.account, id }, env.TOKEN_SIGNING_KEY);
  const key = await rpc(env.ACCOUNTS, auth.account, 'create-key', { id, name, scopes, hash: await digest(secret) });
  return { ...key, secret };
}
