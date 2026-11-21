/**
 * `dba signup` and `dba recover` (STATUS B9): an account made by paying, with this machine as its
 * first device; and getting back into an account after losing every device.
 */
import { rm } from 'node:fs/promises';
import { hostname } from 'node:os';
import { inspectCredential } from '@devicebasedauth/verify';
import { UsageError } from '../errors.js';
import { secondsOption } from '../args.js';
import { loadDeviceKey, keyStoreOption, forgetDeviceKey } from '../device-key.js';
import { describeCredential } from '../credentials.js';
import { depositCents, recoveryVia, startSignup, startRecovery, pollTicket, stillWaiting } from '../account.js';
import { newSavedKey } from './enroll.js';
import { out, note, readJsonFile, readTextFile, writePrivate, ensureDir } from './profile.js';

/** A new key for this profile, kept before anything is asked (so a wait can be resumed). */
async function freshKey(profile, options) {
  if (!options.force && await readTextFile(profile.paths.credential)) throw new UsageError(`This profile already has a credential (${profile.paths.credential}). Use --profile NAME for another device, or --force to replace it.`);
  const previous = await readJsonFile(profile.paths.key);
  const { key, saved } = await newSavedKey(profile, keyStoreOption({ flag: options['key-store'], env: process.env }));
  await ensureDir(profile.paths.dir);
  await writePrivate(profile.paths.key, `${JSON.stringify(saved.file, null, 2)}\n`);
  await forgetDeviceKey(previous, { secrets: profile.secrets });
  await rm(profile.paths.credential, { force: true });
  await writePrivate(profile.paths.config, `${JSON.stringify({ ...profile.config, origin: profile.origin }, null, 2)}\n`);
  return { key, device: { name: options.name || hostname(), kind: options.kind || 'cli', keyProtection: saved.keyProtection } };
}

/** Wait on a pending sign-up or recovery, then save its credential. */
async function finish(profile, key, pending, { waitSeconds }) {
  let told = '';
  const result = await pollTicket(profile.client, key, pending.path, pending.ticket, { waitSeconds, onPending: answer => {
    const line = answer.stage === 'waiting' ? `The emailed link was used; this device gets in after ${new Date(answer.ready_at).toISOString()}.` : null;
    if (line && line !== told) { note(line); told = line; }
  } });
  if (!result.credential) throw stillWaiting(pending.kind === 'signup' ? 'payment' : 'recovery', result.last);
  await writePrivate(profile.paths.credential, `${result.credential}\n`);
  await rm(profile.paths.pending, { force: true });
  return result.credential;
}

async function show(credential) {
  out('');
  for (const line of describeCredential(inspectCredential(credential).payload)) out(line);
}

/** Make recovery codes with the new credential (it counts as a recent sign-in for ten minutes). */
async function recoverySheet(profile, key, credential) {
  const sheet = await profile.client.request('POST', '/api/v1/settings/recovery-codes', { device: { key, credential } });
  out('');
  out(`Recovery sheet for account ${sheet.account} (shown once; keep it away from this machine):`);
  for (const code of sheet.codes) out(`  ${code}`);
}

const resumeKey = async profile => {
  const pending = await readJsonFile(profile.paths.pending);
  const file = await readJsonFile(profile.paths.key);
  if (!pending || !file) throw new UsageError(`Nothing to resume in ${profile.paths.dir}.`);
  return { pending, key: await loadDeviceKey(file, { secrets: profile.secrets, tpm: profile.tpm }) };
};

/** `dba signup`: a new account paid for by card, with this machine as its first device. */
export async function signup(profile, { options }) {
  const waitSeconds = secondsOption(options.wait, 'wait') ?? 1800;
  if (options.resume) {
    const { pending, key } = await resumeKey(profile);
    const credential = await finish(profile, key, pending, { waitSeconds });
    out('Payment received. Saved the credential.'); await show(credential);
    await afterSignup(profile, key, credential, options);
    return;
  }
  if (!options['accept-terms']) throw new UsageError(`Read the terms (${profile.origin}/terms.html) and the privacy policy (${profile.origin}/privacy.html), then run again with --accept-terms.`);
  const credit = depositCents(options.deposit);
  const { key, device } = await freshKey(profile, options);
  const started = await startSignup(profile.client, key, { credit, device });
  const pending = { kind: 'signup', path: '/api/v1/signup/complete', ticket: started.ticket, account: started.account };
  await writePrivate(profile.paths.pending, `${JSON.stringify(pending, null, 2)}\n`);
  if (started.local_payment) {
    note('This local server takes no cards; paying through its development route.');
    await profile.client.request('POST', '/api/v1/dev/signup-paid', { body: { ticket: started.ticket } });
  } else {
    out(`Pay the first deposit (${(started.total_cents / 100).toFixed(2)} USD, of which ${(started.credit_cents / 100).toFixed(2)} is credit) here:`);
    out('');
    out(started.url);
    out('');
    note(`Waiting for the payment (up to ${waitSeconds} s; Ctrl-C to stop and \`dba signup --resume\` later)…`);
  }
  const credential = await finish(profile, key, pending, { waitSeconds });
  out(`Account ${started.account} created; this machine is its first device. Saved the credential.`);
  await show(credential);
  await afterSignup(profile, key, credential, options);
}

/** A recovery sheet unless --no-recovery-codes: losing the only device would lose the account. */
async function afterSignup(profile, key, credential, options) {
  if (!options['no-recovery-codes']) return recoverySheet(profile, key, credential);
  note('No recovery codes: losing this machine loses the account and its balance, unless you add another way back in on the dashboard.');
}

/** `dba recover`: put this machine on an account after losing every device. */
export async function recover(profile, { options }) {
  const waitSeconds = secondsOption(options.wait, 'wait') ?? 600;
  if (options.resume) {
    const { pending, key } = await resumeKey(profile);
    await show(await finish(profile, key, pending, { waitSeconds }));
    return;
  }
  const via = recoveryVia(options);
  const { key, device } = await freshKey(profile, options);
  const started = await startRecovery(profile.client, key, { via, account: options.account, code: options.code, email: options.email, device });
  if (started.status === 'recovered') {
    await writePrivate(profile.paths.credential, `${started.credential}\n`);
    out(`Recovered account ${started.account} onto this machine (${started.recovery_codes_left} recovery codes left). Saved the credential.`);
    note('For ten minutes this counts as a recent sign-in: revoke the lost devices and make new recovery codes now.');
    await show(started.credential);
    return;
  }
  const pending = { kind: `recover-${via}`, path: '/api/v1/recover/complete', ticket: started.ticket };
  await writePrivate(profile.paths.pending, `${JSON.stringify(pending, null, 2)}\n`);
  if (via === 'gate') {
    out(`Approve this machine with a passkey or another of your devices, typing the number ${started.number}.`);
    if (started.approve_url) { out(''); out(started.approve_url); out(''); }
  } else {
    out(started.message || 'If that address belongs to an account, a recovery link was emailed to it.');
    out(`Once the link is used, this machine gets in after ${started.wait_hours} hours unless a signed-in device cancels it. Then run \`dba recover --resume\`.`);
  }
  await show(await finish(profile, key, pending, { waitSeconds: via === 'email' ? Math.min(waitSeconds, 60) : waitSeconds }));
}
