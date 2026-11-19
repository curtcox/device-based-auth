import { assert, readJson, readText } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { canAccess, SESSION } from '../auth/scopes.js';
import { requireRecentSignIn } from '../auth/reverify.js';
import { cleanGateInput, signGateTest, postGateEvent } from '../durable-objects/gates.js';
import { price } from '../utils/pricing.js';
import { verifyToken } from '../auth/tokens.js';

/**
 * The account's gates (STATUS B7): GET lists them (with the built-in owner gate), POST adds one,
 * DELETE removes one. Changing gates needs a recent sign-in (plan §8): a stolen session must not
 * be able to swap a phone's gate for its own device.
 */
export async function gates(route, request, env, auth) {
  if (request.method === 'GET') return rpc(env.ACCOUNTS, auth.account, 'list-gates');
  if (new URL(request.url).pathname.endsWith('/test')) return testGate(route, env, auth);
  requireRecentSignIn(auth, 'change your gates');
  if (request.method === 'DELETE') return rpc(env.ACCOUNTS, auth.account, 'delete-gate', { id: route.params.id });
  if (route.params.id) return rpc(env.ACCOUNTS, auth.account, 'activate-gate', { id: route.params.id, body: await readJson(request, 16384), account: auth.account });
  const input = cleanGateInput(await readJson(request, 8192), env);
  return rpc(env.ACCOUNTS, auth.account, 'create-gate', { input, account: auth.account });
}

/**
 * POST /api/v1/gates/:id/test: send a webhook gate a signed gate.test message now and report what
 * its service answered (read price). No recent sign-in: it changes nothing. Other kinds would
 * reach a person (a push, a notice), so only webhook gates can be tested.
 */
async function testGate(route, env, auth) {
  const gate = (await rpc(env.ACCOUNTS, auth.account, 'list-gates')).items.find(g => g.id === route.params.id);
  assert(gate, 'not_found', 'Gate not found', 404);
  assert(gate.kind === 'webhook', 'not_testable', 'Only approval-service (webhook) gates can be tested; test the others by using a grant that names them', 409);
  await rpc(env.ACCOUNTS, auth.account, 'charge', { kind: 'read', amount: price('read'), aggregate: true, detail: { gate: gate.id } });
  const result = await postGateEvent(env, gate.url, await signGateTest(env, { gate, account: auth.account }));
  return { gate: gate.id, url: gate.url, delivered: result.delivered, status: result.status, decision: result.decision ?? null, ...(result.error ? { error: result.error } : {}), cost_microdollars: price('read') };
}

/** A TOTP code or a security-key assertion offered as proof with an answer. */
function cleanProof(body) {
  const proof = {};
  if (body.number !== undefined) { assert(/^\d{2}$/.test(String(body.number)), 'invalid_answer', 'number must be the two-digit number shown where the sign-in waits'); proof.number = String(body.number); }
  if (body.totp !== undefined) { assert(typeof body.totp?.code === 'string' && body.totp.code.length <= 12, 'invalid_answer', 'totp.code must be the 6-digit code'); proof.totp = { code: body.totp.code }; }
  if (body.webauthn !== undefined) {
    const w = body.webauthn;
    assert(w && ['credential_id', 'clientDataJSON', 'authenticatorData', 'signature'].every(k => typeof w[k] === 'string' && w[k].length <= 8192), 'invalid_answer', 'webauthn must carry credential_id, clientDataJSON, authenticatorData and signature (base64url)');
    proof.webauthn = { credential_id: w.credential_id, clientDataJSON: w.clientDataJSON, authenticatorData: w.authenticatorData, signature: w.signature };
  }
  return proof;
}

function cleanAnswer(body) {
  assert(body.entry === undefined || (Number.isSafeInteger(body.entry) && body.entry >= 0 && body.entry < 3), 'invalid_answer', 'entry must be 0, 1 or 2');
  assert(typeof body.gate === 'string' && body.gate.length <= 80, 'invalid_answer', 'gate is required ("owner" or a gate id)');
  assert(body.decision === 'allow' || body.decision === 'deny', 'invalid_answer', 'decision must be "allow" or "deny"');
  return { entry: body.entry, gate: body.gate, decision: body.decision, proof: cleanProof(body) };
}

/**
 * The approval page (/gate.html#<link>): a signed link names the account and one request. It
 * shows the request and takes answers proven with a factor (a TOTP code, a security key), so the
 * holder of an authenticator app or key answers without a devicebasedauth.org session (plan §4.3).
 */
export async function gateLinks(route, request, env) {
  const link = await verifyToken(route.params.token, 'dbag_', env.TOKEN_SIGNING_KEY, 2048);
  assert(link && typeof link.a === 'string' && typeof link.r === 'string', 'invalid_link', 'This approval link is invalid or has expired', 404);
  if (request.method === 'GET') return rpc(env.ACCOUNTS, link.a, 'link-gate-request', { id: link.r });
  // A webhook gate's late answer, signed with the key it registered (spec/events.md §6).
  if (new URL(request.url).pathname.endsWith('/callback')) return rpc(env.ACCOUNTS, link.a, 'webhook-gate-answer', { id: link.r, jws: await readText(request, 8192), account: link.a });
  const answer = cleanAnswer(await readJson(request, 32768));
  return rpc(env.ACCOUNTS, link.a, 'answer-gate-request', { id: link.r, ...answer, answerer: { kind: 'link', device_id: null }, account: link.a });
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
  const answer = cleanAnswer(await readJson(request, 32768));
  return rpc(env.ACCOUNTS, auth.account, 'answer-gate-request', { id: route.params.id, ...answer, answerer: who, account: auth.account });
}
