/** The device's lifecycle: enroll, import, renew (and rotate) and revoke. */
import { rm, rmdir } from 'node:fs/promises';
import { hostname } from 'node:os';
import { inspectCredential } from '@devicebasedauth/verify';
import { UsageError, ApiError } from '../errors.js';
import { secondsOption } from '../args.js';
import { audiencesFromOption, grantsFromOptions, enrollmentPayload, enrollmentTokenOption, signEnrollmentRequest, rotationProof, pollEnrollment } from '../enrollment.js';
import { newDeviceKey, tpmKeyFile, windowsTpmKeyFile, loadDeviceKey, keyStoreOption, saveDeviceKey, forgetDeviceKey, credentialMatchesKey } from '../device-key.js';
import { describeCredential, shouldRenew, relativeTime } from '../credentials.js';
import { TPM_BACKEND, TPM_PROTECTION, createTpmKey, tpmAttestation, tpmAvailable } from '../tpm.js';
import { WINDOWS_TPM_BACKEND } from '../windows-tpm.js';
import { out, note, readJsonFile, readTextFile, writePrivate, ensureDir, requireDevice, usableDevice, keyWithdrawn, credentialArgument } from './profile.js';

/**
 * A new device key, kept as `mode` says: made in the TPM for "tpm" (through tpm2-tools, or on
 * Windows the Platform Crypto Provider), else in software and saved by saveDeviceKey. Returns
 * { key, saved } like saveDeviceKey's result plus the loaded key.
 */
export async function newSavedKey(profile, mode) {
  if (mode !== 'tpm') {
    const key = await newDeviceKey();
    return { key, saved: await saveDeviceKey(key, { mode, secrets: profile.secrets }) };
  }
  if (profile.tpm.backend === WINDOWS_TPM_BACKEND) {
    let made;
    try { made = await profile.tpm.create(); } catch (error) { throw new UsageError(`Could not make a key in the TPM: ${error.message}. --key-store tpm on Windows needs a TPM 2.0 that Windows uses (tpm.msc shows it ready).`); }
    const file = windowsTpmKeyFile(made);
    return { key: await loadDeviceKey(file, { tpm: profile.tpm }), saved: { file, keyProtection: TPM_PROTECTION, store: null } };
  }
  if (!await tpmAvailable(profile.tpm.open)) throw new UsageError('No TPM is reachable: --key-store tpm needs tpm2-tools 5 and access to the TPM (/dev/tpmrm0, usually the "tss" group, or TPM2TOOLS_TCTI).');
  const made = await createTpmKey(profile.tpm.open);
  const file = tpmKeyFile(made);
  return { key: await loadDeviceKey(file, { tpm: profile.tpm }), saved: { file, keyProtection: TPM_PROTECTION, store: null } };
}

/**
 * The TPM's proof that the key is inside it. Enrollment goes ahead without one when the TPM
 * cannot give it (no EK certificate, a manufacturer the server does not know): the credential is
 * then still TPM-bound but grants that require attestation will deny.
 */
async function attestTpmKey(profile, key) {
  try {
    const attestation = await tpmAttestation(profile.tpm.open, key.tpm, { post: (path, body) => profile.client.request('POST', path, { body }) });
    note('The TPM proved the key is inside it (EK credential activation).');
    return attestation;
  } catch (error) {
    note(`dba: enrolling without attestation: ${error.message}${error.code ? ` (${error.code})` : ''}. Grants that require hardware attestation will deny this device.`);
    return undefined;
  }
}

/** `dba enroll`: a new key, then a credential by approval link or enrollment token. */
export async function enroll(profile, { options }) {
  const token = enrollmentTokenOption({ flag: options.token, env: process.env });
  if (token && options['print-request']) throw new UsageError('--print-request is for approval links; with an enrollment token the credential is issued at once');
  // With a token, audiences and grants are optional: the token's template applies.
  const aud = token && !options.aud?.length ? undefined : audiencesFromOption(options.aud);
  const grants = token && !options.grant?.length && !options.action?.length ? undefined : grantsFromOptions(options);
  const lifetime = secondsOption(options.lifetime, 'lifetime');
  const waitSeconds = secondsOption(options.wait, 'wait') ?? 900;
  const keyStore = keyStoreOption({ flag: options['key-store'], env: process.env });
  // Replacing the key orphans the current credential, so never do it by accident.
  if (!options.force && await readTextFile(profile.paths.credential)) throw new UsageError(`This profile already has a credential (${profile.paths.credential}). Use --profile NAME for another device, or --force to replace it.`);

  // Keep the key before asking, so an interrupted wait can still be finished with `dba import`,
  // and so the request can say where the key lives.
  const previous = await readJsonFile(profile.paths.key);
  const { key, saved } = await newSavedKey(profile, keyStore);
  await ensureDir(profile.paths.dir);
  await writePrivate(profile.paths.key, `${JSON.stringify(saved.file, null, 2)}\n`);
  await forgetDeviceKey(previous, { secrets: profile.secrets, tpm: profile.tpm });
  const attestation = key.tpm ? await attestTpmKey(profile, key) : undefined;
  if (key.keyName) note('dba: enrolling without attestation: dba cannot yet ask Windows to prove the key is in its TPM. Grants that require hardware attestation will deny this device.');
  const request = await signEnrollmentRequest(key, enrollmentPayload({ aud, grants, name: options.name || hostname(), kind: options.kind, lifetime, keyProtection: saved.keyProtection, attestation }));
  if (key.tpm || key.keyName) note(`The private key is in ${profile.tpm.name}; it cannot leave it.`);
  else if (saved.store) note(`Keeping the private key in ${profile.secrets.name}.`);
  else if (keyStore === 'auto' && profile.secrets) note(`${profile.secrets.name} is not available; keeping the private key in ${profile.paths.key} (0600).`);
  await rm(profile.paths.credential, { force: true });
  await writePrivate(profile.paths.config, `${JSON.stringify({ ...profile.config, origin: profile.origin }, null, 2)}\n`);
  if (options['print-request']) { out(request); return; }

  if (token) {
    const issued = await profile.client.request('POST', '/api/v1/enrollments/redeem', { body: { request, enrollment_token: token } });
    await writePrivate(profile.paths.credential, `${issued.credential}\n`);
    out('Enrolled with the enrollment token. Saved the credential.');
    out('');
    for (const line of describeCredential(inspectCredential(issued.credential).payload)) out(line);
    return;
  }

  const start = await profile.client.request('POST', '/api/v1/enrollments', { body: { request } });
  out('Ask the account owner to open this link while signed in to devicebasedauth.org, check the grants and approve:');
  out('');
  out(start.approval_url);
  out('');
  const wait = Math.min(waitSeconds, start.expires_in ?? waitSeconds);
  note(`Waiting for approval (giving up ${relativeTime(Math.floor(Date.now() / 1000) + wait)}; Ctrl-C to stop)…`);
  const result = await pollEnrollment(profile.client, start, { waitSeconds: wait });
  if (result.status !== 'approved') {
    throw new ApiError({ denied: 'The owner denied this device.', expired: 'The enrollment request expired before anyone approved it.', timeout: 'Gave up waiting for approval.' }[result.status] || `Enrollment ended: ${result.status}`, `enrollment_${result.status}`);
  }
  await writePrivate(profile.paths.credential, `${result.credential}\n`);
  out('Approved. Saved the credential.');
  out('');
  for (const line of describeCredential(inspectCredential(result.credential).payload)) out(line);
}

/** `dba import`: save a credential issued for this profile's key (after `enroll --print-request`). */
export async function importCredential(profile, { positionals }) {
  const credential = await credentialArgument(positionals[0]);
  const file = await readJsonFile(profile.paths.key);
  if (!file) throw new UsageError(`No key in ${profile.paths.dir}. Run \`dba enroll --print-request\` first.`);
  if (!await credentialMatchesKey(credential, await loadDeviceKey(file, { secrets: profile.secrets, tpm: profile.tpm }))) throw new UsageError('That credential was issued for a different key (cnf.jkt does not match key.json).');
  await writePrivate(profile.paths.credential, `${credential}\n`);
  for (const line of describeCredential(inspectCredential(credential).payload)) out(line);
}

/** `dba renew`: renew now, optionally moving to a new key (--rotate), or only when due (--if-due). */
export async function renew(profile, { options }) {
  if (options['if-due']) {
    if (options.rotate) throw new UsageError('--if-due and --rotate cannot be combined');
    const before = await requireDevice(profile);
    const { payload } = inspectCredential(before.credential);
    if (payload.exp * 1000 <= Date.now()) throw new ApiError('The credential has expired; enroll again with `dba enroll --force`.', 'expired');
    if (!shouldRenew(payload) && !await keyWithdrawn(profile, before.credential)) { out(`Not due: ${payload.cid} expires ${relativeTime(payload.exp)}; renewal is due ${relativeTime(Math.ceil(payload.iat + ((payload.exp - payload.iat) * 2) / 3))}.`); return; }
    const after = await usableDevice(profile, { force: true });
    if (after.credential === before.credential) throw new ApiError('The credential was not renewed (see the message above, or another dba process is renewing it now).', 'renew_failed');
    return;
  }
  const device = await requireDevice(profile);
  const { cid } = inspectCredential(device.credential).payload;
  const previous = options.rotate ? await readJsonFile(profile.paths.key) : null;
  // The new key goes where the old one was. In the OS store it gets its own entry now (named by
  // its thumbprint, so the old one is untouched); key.json changes only after the server agreed:
  // until then the old key and credential are the good pair. A rotated credential carries no
  // attestation (the server drops it), so a TPM key is not attested again here.
  const fresh = options.rotate ? await newSavedKey(profile, [TPM_BACKEND, WINDOWS_TPM_BACKEND].includes(previous?.key_store) ? 'tpm' : previous?.key_store ? 'os' : 'file') : null;
  const next = fresh?.key ?? null;
  const saved = fresh?.saved ?? null;
  const body = next ? { new_key_proof: await rotationProof(next, cid) } : {};
  let result;
  try {
    result = await profile.client.request('POST', `/api/v1/credentials/${encodeURIComponent(cid)}/renew`, { device, body });
  } catch (error) {
    if (saved) await forgetDeviceKey(saved.file, { secrets: profile.secrets, tpm: profile.tpm });
    throw error;
  }
  if (saved) {
    await writePrivate(profile.paths.key, `${JSON.stringify(saved.file, null, 2)}\n`);
    await forgetDeviceKey(previous, { secrets: profile.secrets, tpm: profile.tpm });
  }
  await writePrivate(profile.paths.credential, `${result.credential}\n`);
  out(`${result.rotated ? 'Rotated to a new key and renewed' : 'Renewed'} ${result.cid}${result.recovered ? ' (the issuer withdrew the key that signed it; no charge)' : ''} (now ${result.jti}); expires ${new Date(result.exp * 1000).toISOString()} (${relativeTime(result.exp)}).`);
}

/** `dba revoke`: revoke this device's credential and delete its files. */
export async function revoke(profile) {
  const device = await requireDevice(profile);
  const { cid } = inspectCredential(device.credential).payload;
  try {
    await profile.client.request('POST', '/api/v1/self/revoke', { device, body: {} });
    out(`Revoked ${cid}.`);
  } catch (error) {
    // Already dead credentials cannot authenticate to revoke themselves; deleting them is still right.
    if (!['revoked', 'expired'].includes(error.code)) throw error;
    out(`${cid} was already ${error.code}.`);
  }
  await forgetDeviceKey(await readJsonFile(profile.paths.key), { secrets: profile.secrets, tpm: profile.tpm });
  for (const path of [profile.paths.credential, profile.paths.confirmation, profile.paths.key, profile.paths.config, profile.paths.certificate, profile.paths.certificateKey, profile.paths.ca]) await rm(path, { force: true });
  await rmdir(profile.paths.dir).catch(() => {});
  out(`Deleted the key and credential in ${profile.paths.dir}.`);
}
