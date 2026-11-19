import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { canAccess, SESSION } from '../auth/scopes.js';
import { requireRecentSignIn } from '../auth/reverify.js';
import { cleanGateInput } from '../durable-objects/gates.js';

/**
 * The account's gates (STATUS B7): GET lists them (with the built-in owner gate), POST adds one,
 * DELETE removes one. Changing gates needs a recent sign-in (plan §8): a stolen session must not
 * be able to swap a phone's gate for its own device.
 */
export async function gates(route, request, env, auth) {
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'list-gates');
  requireRecentSignIn(auth, 'change your gates');
  if (request.method === 'DELETE') return rpc(env.ACCOUNTS, auth.account, 'delete-gate', { id: route.params.id });
  const input = cleanGateInput(await readJson(request, 4096));
  return rpc(env.ACCOUNTS, auth.account, 'create-gate', { input });
}

/**
 * Who is asking about gate requests: the account owner (a signed-in browser, or a dashboard device
 * with dba:session), or a device answering as a dba-device gate (dba:approvals:answer). API keys
 * neither see nor answer them: a gate is a person or a device, never a script holding a key.
 */
function answerer(auth) {
  if (auth.kind !== 'key' && canAccess(auth, SESSION)) return { kind: 'owner', device_id: auth.device?.payload.sub ?? null };
  if (auth.device && canAccess(auth, 'approvals:answer')) return { kind: 'device', device_id: auth.device.payload.sub };
  assert(false, 'insufficient_scope', 'Gate requests are seen and answered by the account owner or by a device holding dba:approvals:answer', 403);
}

/** GET /gate-requests, GET /gate-requests/:id, POST /gate-requests/:id/answer. */
export async function gateRequests(route, request, env, auth) {
  const who = answerer(auth);
  const device_id = who.kind === 'device' ? who.device_id : undefined;
  if (request.method === 'GET' && !route.params.id) return rpc(env.ACCOUNTS, auth.account, 'list-gate-requests', { device_id });
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'get-gate-request', { id: route.params.id, device_id });
  const body = await readJson(request, 4096);
  assert(body.entry === undefined || (Number.isSafeInteger(body.entry) && body.entry >= 0 && body.entry < 3), 'invalid_answer', 'entry must be 0, 1 or 2');
  assert(typeof body.gate === 'string' && body.gate.length <= 80, 'invalid_answer', 'gate is required ("owner" or a gate id)');
  assert(body.decision === 'allow' || body.decision === 'deny', 'invalid_answer', 'decision must be "allow" or "deny"');
  return rpc(env.ACCOUNTS, auth.account, 'answer-gate-request', { id: route.params.id, entry: body.entry, gate: body.gate, decision: body.decision, answerer: who });
}
