/** Gates and confirmation (STATUS B7): `dba confirm`, `dba gates` and `dba approvals`. */
import { inspectCredential } from '@devicebasedauth/verify';
import { UsageError, ApiError } from '../errors.js';
import { secondsOption } from '../args.js';
import { relativeTime, autoRenewEnabled } from '../credentials.js';
import { needsConfirmation, currentConfirmation, waitForConfirmation, formatGateList, gateInputFromOptions, describeGateRequest, answerFor } from '../gates.js';
import { out, note, readTextFile, writePrivate, usableDevice } from './profile.js';

/**
 * Ask this credential's gates to confirm it, wait, and save the confirmation. Says on stderr who
 * must approve while it waits. Throws when the gates deny or the wait ends.
 */
async function obtainConfirmation(profile, device, waitSeconds) {
  const result = await waitForConfirmation(profile.client, device, {
    waitSeconds,
    onPending: req => {
      note(`Waiting for this device's gates to confirm it (request ${req.id}${req.number ? `, number ${req.number}` : ''}; giving up ${relativeTime(Math.floor(Date.now() / 1000) + waitSeconds)})…`);
      if (req.approve_url) note(`Approve with a code or security key at ${req.approve_url}`);
    }
  });
  if (result.status === 'denied') throw new ApiError('The gates refused to confirm this device.', result.code || 'gate_denied');
  if (result.status !== 'confirmed') throw new ApiError('Gave up waiting for the gates to confirm this device.', 'confirmation_timeout');
  await writePrivate(profile.paths.confirmation, `${result.confirmation}\n`);
  return result;
}

/**
 * The confirmation to send with a request, for credentials that need one: the saved one while it
 * is current, else a new one (waiting for the gates) unless DBA_AUTO_CONFIRM=0. Credentials
 * without `confirm` need none.
 */
export async function usableConfirmation(profile, device) {
  const payload = inspectCredential(device.credential).payload;
  if (!needsConfirmation(payload)) return null;
  const saved = currentConfirmation(await readTextFile(profile.paths.confirmation), payload);
  if (saved) return saved;
  if (!autoRenewEnabled({ env: { DBA_AUTO_RENEW: process.env.DBA_AUTO_CONFIRM } })) {
    note('dba: this credential needs a current confirmation and has none; run `dba confirm` (sites will refuse it until then).');
    return null;
  }
  return (await obtainConfirmation(profile, device, 300)).confirmation;
}

/** `dba confirm`: ask this credential's gates to confirm it is still trusted, and save the confirmation. */
export async function confirm(profile, { options }) {
  const waitSeconds = secondsOption(options.wait, 'wait') ?? 300;
  const device = await usableDevice(profile);
  const payload = inspectCredential(device.credential).payload;
  if (!needsConfirmation(payload)) throw new UsageError(`${payload.cid} was not issued with "confirm": it needs no confirmation.`);
  const result = await obtainConfirmation(profile, device, waitSeconds);
  out(`Confirmed ${payload.cid} until ${new Date(result.expires_at * 1000).toISOString()} (${relativeTime(result.expires_at)})${result.by_timeout ? ', by timeout (no gate answered)' : ''}.`);
  out(`Saved ${profile.paths.confirmation}; \`dba headers\` and \`dba curl\` send it as DBA-Confirmation.`);
}

/** API key from DBA_API_KEY, else this device's credential. */
async function accountAuth(profile, scope) {
  const apiKey = process.env.DBA_API_KEY?.trim();
  if (apiKey) return { apiKey };
  try { return { device: await usableDevice(profile) }; } catch (error) {
    if (error instanceof UsageError) throw new UsageError(`${error.message} Or set DBA_API_KEY to an API key with ${scope}.`);
    throw error;
  }
}

/** `dba gates`: list, add, test and remove the account's gates. */
export async function gatesCommand(profile, { options, positionals }) {
  const [sub = 'list', id] = positionals;
  if (sub === 'list') {
    const { items } = await profile.client.request('GET', '/api/v1/gates', await accountAuth(profile, 'gates:read'));
    if (options.json) { out(JSON.stringify({ items }, null, 2)); return; }
    for (const line of formatGateList(items)) out(line);
    return;
  }
  if (sub === 'add') {
    const body = gateInputFromOptions(options);
    const created = await profile.client.request('POST', '/api/v1/gates', { ...await accountAuth(profile, 'gates:write'), body });
    if (options.json) { out(JSON.stringify(created, null, 2)); return; }
    out(`Added gate ${created.id} (${created.kind}, ${created.state ?? 'active'}). Name it in grants: "require": { "gates": [{ "any": ["${created.id}"] }] }`);
    return;
  }
  if (sub === 'test') {
    if (!id) throw new UsageError('Usage: dba gates test GATE');
    const result = await profile.client.request('POST', `/api/v1/gates/${encodeURIComponent(id)}/test`, { ...await accountAuth(profile, 'gates:write'), body: {} });
    if (options.json) { out(JSON.stringify(result, null, 2)); return; }
    if (!result.delivered) throw new ApiError(`${id} did not answer the test: ${result.status ? `HTTP ${result.status}` : result.error || 'no answer'}.`, 'gate_test_failed');
    out(`${id} answered HTTP ${result.status}${result.decision ? ` with "${result.decision}" (a test decides nothing)` : ''}.`);
    return;
  }
  if (sub === 'remove') {
    if (!id) throw new UsageError('Usage: dba gates remove GATE');
    await profile.client.request('DELETE', `/api/v1/gates/${encodeURIComponent(id)}`, await accountAuth(profile, 'gates:write'));
    out(`Removed gate ${id}. Requests that needed only it are now denied.`);
    return;
  }
  throw new UsageError(`Unknown gates command "${sub}" (list, add, test, remove)`);
}

/** `dba approvals`: gate requests this device can answer as a dba-device gate; allow or deny one. */
export async function approvals(profile, { options, positionals }) {
  const [sub = 'list', id] = positionals;
  const device = await usableDevice(profile);
  if (sub === 'allow' || sub === 'deny') {
    if (!id) throw new UsageError(`Usage: dba approvals ${sub} REQUEST`);
    const entry = options.entry === undefined ? undefined : Number(options.entry);
    if (entry !== undefined && !(Number.isSafeInteger(entry) && entry >= 0 && entry < 3)) throw new UsageError('--entry must be 0, 1 or 2');
    const path = `/api/v1/gate-requests/${encodeURIComponent(id)}`;
    const req = await profile.client.request('GET', path, { device });
    const body = answerFor(req, { decision: sub, entry, number: options.number });
    const result = await profile.client.request('POST', `${path}/answer`, { device, body });
    if (options.json) { out(JSON.stringify(result, null, 2)); return; }
    out(`${sub === 'allow' ? 'Allowed' : 'Denied'} ${id}${result.status === 'pending' ? ' (other gates must still answer)' : `: the request is now ${result.status}`}.`);
    return;
  }
  if (sub !== 'list') throw new UsageError(`Unknown approvals command "${sub}" (list, allow, deny)`);
  const seen = new Set();
  for (;;) {
    const { items } = await profile.client.request('GET', '/api/v1/gate-requests', { device });
    const waiting = items.filter(r => r.status === 'pending' && r.answer_as?.length);
    if (options.json) out(JSON.stringify(options.watch ? waiting.filter(r => !seen.has(r.id)) : { items }, null, options.watch ? 0 : 2));
    else {
      if (!options.watch && !waiting.length) out('Nothing is waiting for this device.');
      for (const req of waiting) {
        if (seen.has(req.id)) continue;
        for (const line of describeGateRequest(req)) out(line);
        out(`  Answer: dba approvals allow ${req.id}${req.number ? '' : ' --number NN'}   (or deny)`);
      }
    }
    for (const req of waiting) seen.add(req.id);
    if (!options.watch) return;
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
}
