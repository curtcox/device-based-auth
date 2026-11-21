/**
 * Gates, approvals and periodic confirmation (STATUS B7, done/additional_gates.md §10): asking for
 * and keeping a confirmation, listing and adding gates, answering gate requests, and waiting
 * while a site answers gate_pending.
 */
import { inspectCredential } from '@devicebasedauth/verify';
import { UsageError } from './errors.js';

const cleanText = text => String(text ?? '').replace(/[\p{Cc}\p{Cf}]/gu, '');

/** Does this credential need a current confirmation (it was issued with `confirm`)? */
export function needsConfirmation(payload) {
  return !!payload?.confirm;
}

/**
 * The saved confirmation if it still belongs to this credential and has at least `marginSeconds`
 * left (a verifier allows 60 s of skew; asking a little early avoids a refusal mid-request), else
 * null. Nothing is verified here: the verifier checks the signature.
 */
export function currentConfirmation(jwt, credentialPayload, { now = Math.floor(Date.now() / 1000), marginSeconds = 30 } = {}) {
  if (!jwt) return null;
  let payload;
  try { payload = inspectCredential(jwt).payload; } catch { return null; }
  if (payload.cid !== credentialPayload.cid || payload.cnf?.jkt !== credentialPayload.cnf?.jkt) return null;
  return Number.isSafeInteger(payload.exp) && payload.exp - marginSeconds > now ? jwt : null;
}

/**
 * Ask for a confirmation and wait while its gates decide (POST …/confirm again every
 * retry_after seconds; the server reuses the open request). `onPending(gateRequest)` is called
 * once, with the first pending answer, so the caller can say who must approve. Network errors are
 * retried until the deadline. Returns { status: 'confirmed', confirmation, expires_at, by_timeout },
 * { status: 'denied', code } or { status: 'timeout', gate_request }.
 */
export async function waitForConfirmation(client, device, { waitSeconds = 300, onPending = () => {}, sleep = ms => new Promise(r => setTimeout(r, ms)), clock = () => Date.now() } = {}) {
  const { cid } = inspectCredential(device.credential).payload;
  const path = `/api/v1/credentials/${encodeURIComponent(cid)}/confirm`;
  const deadline = clock() + waitSeconds * 1000;
  let told = false; let last = null;
  for (;;) {
    let result = null;
    try { result = await client.request('POST', path, { device, body: {} }); } catch (error) { if (error.code !== 'network_error') throw error; }
    if (result && result.status !== 'pending') return result;
    if (result) {
      last = result.gate_request;
      if (!told) { told = true; onPending(last); }
    }
    const wait = Math.max(1, Number(last?.retry_after) || 2) * 1000;
    if (clock() + wait > deadline) return { status: 'timeout', gate_request: last };
    await sleep(wait);
  }
}

/** Headers to add for a credential that needs confirmation (empty when none is needed or held). */
export function confirmationHeaders(confirmation) {
  return confirmation ? { 'DBA-Confirmation': confirmation } : {};
}

/** One line per gate for `dba gates`: id, kind, state and label (control characters dropped). */
export function formatGateList(items) {
  if (!items.length) return ['No gates.'];
  const rows = items.map(g => [cleanText(g.id), cleanText(g.kind), cleanText(g.state ?? 'active'), cleanText(g.label) + (g.device_id ? ` (${cleanText(g.device_id)})` : '')]);
  const header = ['GATE', 'KIND', 'STATE', 'LABEL'];
  const widths = header.map((h, i) => Math.min(40, Math.max(h.length, ...rows.map(r => r[i].length))));
  return [header, ...rows].map(row => row.map((cell, i) => (i === row.length - 1 ? cell : cell.padEnd(widths[i]))).join('  ').trimEnd());
}

export const CLI_GATE_KINDS = ['dba-device', 'webhook'];

/**
 * The body of POST /api/v1/gates from `dba gates add` options. The CLI adds the kinds that need
 * no browser: a device (--device dev_…) and a webhook (--url, --public-jwk JSON). TOTP, security
 * keys, Duo and Okta Verify are set up on the dashboard's Gates page, which shows the QR code or
 * talks to the authenticator.
 */
export function gateInputFromOptions({ kind, label, device, url, 'public-jwk': publicJwkText }) {
  if (!CLI_GATE_KINDS.includes(kind)) throw new UsageError(`--kind must be one of ${CLI_GATE_KINDS.join(', ')} (set up TOTP, security keys, Duo and Okta Verify on the dashboard's Gates page)`);
  if (!label) throw new UsageError('--label is required');
  if (kind === 'dba-device') {
    if (!device) throw new UsageError('--device dev_… is required: the device that will approve (it needs a credential with dba:approvals:answer)');
    return { kind, label, device_id: device };
  }
  if (!url || !publicJwkText) throw new UsageError('A webhook gate needs --url https://… and --public-jwk \'{"kty":"EC",…}\' (the key its late answers are signed with)');
  let jwk;
  try { jwk = JSON.parse(publicJwkText); } catch { throw new UsageError('--public-jwk must be a JSON Web Key'); }
  return { kind, label, url, public_jwk: jwk };
}

/**
 * A gate request in a few lines for `dba approvals`: what is asked, by which device, the number
 * to match, and how long is left. Every string came from someone else's credential or request, so
 * control characters are dropped.
 */
export function describeGateRequest(req) {
  const what = req.purpose === 'confirm' ? 'confirm it is still trusted'
    : req.purpose === 'sign_in' ? `sign in to ${cleanText(req.audience)}`
      : req.purpose === 'dashboard' ? 'open the devicebasedauth.org dashboard'
        : `${cleanText(req.action)} on ${cleanText(req.audience)}${req.resource ? ` (${cleanText(req.resource)})` : ''}`;
  const lines = [`${cleanText(req.id)}  ${cleanText(req.device_name || req.device_id || 'A device')} asks to ${what}`];
  if (req.number) lines.push(`  Number: ${cleanText(req.number)} (check it matches what the device shows)`);
  else if (req.purpose === 'sign_in' || req.purpose === 'dashboard') lines.push('  Type the two-digit number shown where the sign-in waits: --number NN');
  const waiting = (req.entries || []).filter(e => !e.outcome);
  const left = waiting.length ? Math.min(...waiting.map(e => e.expires_in)) : 0;
  lines.push(`  Status: ${cleanText(req.status)}${req.status === 'pending' ? `, ${left} s left${waiting.some(e => e.on_timeout === 'allow') ? ' (then allowed by timeout)' : ''}` : ''}`);
  return lines;
}

/**
 * Which answer to send for `dba approvals allow|deny ID`: the first of the request's answer_as
 * entries (the device's own gates for entries still waiting), or the one --entry names.
 */
export function answerFor(req, { decision, entry, number } = {}) {
  if (decision !== 'allow' && decision !== 'deny') throw new UsageError('Say allow or deny');
  const choices = (req.answer_as || []).filter(a => entry === undefined || a.entry === entry);
  if (!choices.length) throw new UsageError(`This device has no gate that can still answer ${req.id}${entry === undefined ? '' : ` entry ${entry}`}`);
  if (number !== undefined && !/^\d{2}$/.test(String(number))) throw new UsageError('--number is the two-digit number shown where the sign-in waits');
  return { entry: choices[0].entry, gate: choices[0].gate, decision, ...(number !== undefined && decision === 'allow' ? { number: String(number) } : {}) };
}

/**
 * The gate request a response says is still waiting (403 { code: "gate_pending", gate_request },
 * spec/credential.md §8), or null for any other response.
 */
export function pendingGate(status, bodyText) {
  if (status !== 403) return null;
  let body;
  try { body = JSON.parse(bodyText); } catch { return null; }
  return body?.code === 'gate_pending' ? (body.gate_request && typeof body.gate_request === 'object' ? body.gate_request : {}) : null;
}

/**
 * Send a request again, with a fresh proof each time (`attempt` makes one), every retry_after
 * seconds while the site answers gate_pending, as the browser SDK's fetchWithGates does. Returns
 * { response, gaveUp } where gaveUp is true when it stopped still pending after waitSeconds.
 */
export async function waitThroughGates(attempt, { waitSeconds = 300, onPending = () => {}, sleep = ms => new Promise(r => setTimeout(r, ms)), clock = () => Date.now() } = {}) {
  const deadline = clock() + waitSeconds * 1000;
  let told = false;
  for (;;) {
    const response = await attempt();
    const gate = pendingGate(response.status, response.body);
    if (!gate) return { response, gaveUp: false };
    if (!told) { told = true; onPending(gate); }
    const wait = Math.min(60, Math.max(1, Number(gate.retry_after) || 2)) * 1000;
    if (clock() + wait > deadline) return { response, gaveUp: true };
    await sleep(wait);
  }
}

/** What `dba curl --dba-wait` says while a site waits for gates (strings come from the site). */
export function describePendingGate(gate) {
  const where = typeof gate.approve_url === 'string' && /^(https:\/\/|http:\/\/(localhost|127\.0\.0\.1)[:/])/.test(gate.approve_url) ? ` Approve it at ${cleanText(gate.approve_url)}, or` : ' Approve it';
  return `dba: waiting for this request's gates${gate.id ? ` (request ${cleanText(gate.id)})` : ''}.${where} from the dashboard's Approvals page or \`dba approvals\` on a gate device.`;
}
