#!/usr/bin/env node
/**
 * dba: enroll this machine as a device on devicebasedauth.org, then use its credential.
 * Node 22+, no dependencies beyond @devicebasedauth/verify. The logic lives in lib.js; this file
 * only touches files, stdin/stdout and child processes.
 */
import { mkdir, mkdtemp, readFile, writeFile, rename, chmod, rm, rmdir, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createPrivateKey } from 'node:crypto';
import { homedir, hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  UsageError, ApiError, parseArgs, splitCommand, configPaths, resolveOrigin, audiencesFromOption, grantsFromOptions, secondsOption,
  enrollmentPayload, enrollmentTokenOption, newDeviceKey, tpmKeyFile, loadDeviceKey, keyStoreOption, osSecretStore, saveDeviceKey, forgetDeviceKey, signEnrollmentRequest, rotationProof, deviceHeaders, credentialMatchesKey,
  curlRequest, curlArgs, curlHeaderFile, curlWaitOption, waitThroughGates, describePendingGate, createClient, pollEnrollment, describeCredential, shouldRenew, relativeTime, autoRenewEnabled, renewIfDue, issuerKeyWithdrawn, listQuery, formatCredentialList,
  needsConfirmation, currentConfirmation, waitForConfirmation, confirmationHeaders, formatGateList, gateInputFromOptions, describeGateRequest, answerFor
} from './lib.js';
import { inspectCredential, createProof } from '@devicebasedauth/verify';
import { TPM_BACKEND, TPM_PROTECTION, TPM_NAME, createTpmKey, tpmAttestation, tpmAvailable } from './tpm.js';
import { nodeTpmSessions } from './tpm-node.js';

const HELP = `dba — device credentials from devicebasedauth.org

Usage: dba [--profile NAME] [--origin URL] <command> [options]

Enroll this machine:
  dba enroll --aud SITE[,SITE] (--action ACTION ... | --grant 'JSON' ...)
             [--name "My laptop"] [--kind cli] [--lifetime SECONDS] [--wait SECONDS]
             [--print-request] [--force] [--key-store auto|os|file|tpm]
      Makes a new P-256 key, asks for a credential and prints a link for the account owner to
      approve. Waits (default 900 s) and saves the credential. All --action values form one
      grant; each --grant adds one (or a JSON list). --print-request only prints the signed
      request (for agents and the MCP server); finish with \`dba import\`.
      The private key never leaves this machine. It is kept in the OS secret store when there
      is one (macOS Keychain; Secret Service via secret-tool on Linux; DPAPI on Windows) and the credential says
      key_protection "os-keychain"; else in a 0600 file, "software". --key-store os refuses to
      fall back to the file, file never tries the OS store (also DBA_KEY_STORE).
      --key-store tpm makes the key inside the TPM 2.0 (needs tpm2-tools and access to
      /dev/tpmrm0, or TPM2TOOLS_TCTI): it can never leave the TPM, which signs every request.
      dba also proves to the server that the key is in a genuine TPM (EK credential
      activation), so the credential says attestation "tpm" and satisfies grants that require
      hardware; key_protection "tpm". \`dba certificate\` cannot export a TPM key.
  dba enroll --token dbae_… [--aud …] [--action …] [--name …]
      Enroll with an enrollment token the owner created for a fleet: no approval link, the
      credential is issued at once. The token's audiences and grants apply unless you narrow
      them. Prefer DBA_ENROLLMENT_TOKEN=dbae_… over --token to keep it out of shell history.

Use the credential:
  dba status | whoami [--online] [--json]   What this device may do, in plain English.
  dba headers METHOD URL                    Print Authorization and DPoP headers for one request.
  dba sign METHOD URL                       Print only the DPoP proof.
  dba curl CURL-ARGS...                     Run curl (7.55+) with the headers added (from a private file, not argv).
                                            --dba-wait[=SECONDS] (anywhere among them): while the site
                                            answers 403 gate_pending, send the request again with a
                                            fresh proof until its gates decide (default 300 s; exits 1
                                            if they have not). Prints the final body; no -o, -i, -f.
  dba token --aud SITE                      Print a 10-minute bearer token for SITE:
                                              curl -H "Authorization: Bearer $(dba token --aud hashbin.org)" ...
  dba certificate [--lifetime SECONDS]      Write an X.509 client certificate for this device's key
                                            (client.crt, client.key, ca.crt in the profile
                                            directory) for mTLS: curl --cert … --key …. Valid 1 hour
                                            by default, at most 24; 5 µ$.
  dba renew [--rotate] [--if-due]           Renew the credential (--rotate: move to a new key;
                                            --if-due: only once 2/3 of its lifetime has passed,
                                            for a daily cron job on rarely used devices).
  dba revoke                                Revoke this device's credential and delete its files.

Gates and confirmation:
  dba confirm [--wait SECONDS]              Ask this credential's gates to confirm it is still trusted
                                            (credentials issued with "confirm"). Waits (default 300 s),
                                            saves confirmation.jwt; 12 µ$. headers and curl send it as
                                            DBA-Confirmation and ask for a new one when it is due
                                            (DBA_AUTO_CONFIRM=0: never ask on their own).
  dba approvals [--watch] [--json]          Gate requests this device can answer as a dba-device gate
                                            (its credential needs dba:approvals:answer). --watch keeps
                                            listing new ones every 5 s until Ctrl-C.
  dba approvals allow|deny REQUEST [--entry N] [--number NN]
                                            Answer one. Sign-ins hide their number: type the one shown
                                            where the sign-in waits with --number.
  dba gates [--json]                        The account's gates (DBA_API_KEY with gates:read, or this
                                            device with dba:gates:read).
  dba gates add --kind dba-device --label TEXT --device dev_…
  dba gates add --kind webhook --label TEXT --url https://… --public-jwk JSON
  dba gates test GATE                       Send a webhook gate a signed test message (5 µ$).
  dba gates remove GATE                     Changing gates needs DBA_API_KEY with gates:write (a device
                                            cannot: that needs a recent sign-in). TOTP, security keys,
                                            Duo and Okta Verify are set up on the dashboard's Gates page.

The account:
  dba list [--status active|expired|revoked] [--audience SITE] [--device ID] [--all] [--json]
      Every credential on the account, 50 at a time (--all: every page). Uses DBA_API_KEY (an
      API key with credentials:read) when set, else this device's credential, which then needs
      dba:credentials:read. Each page is a metered read (5 µ$).

Any credential:
  dba inspect CREDENTIAL|- [--json]         Decode it and ask the server about its signature and revocation.
  dba import CREDENTIAL|-                   Save a credential issued for this profile's key.

Renewal:
  headers, sign, curl, token, certificate and status --online renew the credential first once two thirds of
  its lifetime has passed (25 µ$ from the account's balance). If renewal fails they warn and use
  the current credential, which is still valid. Turn this off with --no-renew or DBA_AUTO_RENEW=0.

Options:
  --profile NAME   Keep several devices apart (default "default").
  --no-renew       Never renew automatically.
  --origin URL     Server (default $DBA_ORIGIN, then the origin used at enrollment,
                   then https://devicebasedauth.org).

Files: $DBA_HOME/<profile>/ (default ~/.config/dba/<profile>/): key.json, credential.jwt, config.json.
A key in the OS secret store is listed there under service org.devicebasedauth.dba.
`;

const COMMANDS = {
  enroll: { values: ['name', 'kind', 'lifetime', 'wait', 'token', 'key-store'], repeatable: ['aud', 'grant', 'action'], booleans: ['print-request', 'force'] },
  status: { booleans: ['online', 'json'] },
  whoami: { booleans: ['online', 'json'] },
  inspect: { booleans: ['json'] },
  import: {},
  headers: {},
  sign: {},
  token: { values: ['aud'] },
  certificate: { values: ['lifetime'] },
  renew: { booleans: ['rotate', 'if-due'] },
  revoke: {},
  list: { values: ['status', 'audience', 'device'], booleans: ['all', 'json'] },
  confirm: { values: ['wait'] },
  approvals: { values: ['entry', 'number'], booleans: ['watch', 'json'] },
  gates: { values: ['kind', 'label', 'device', 'url', 'public-jwk'], booleans: ['json'] },
  help: {}
};
const GLOBAL = { values: ['profile', 'origin'], booleans: ['help', 'no-renew'] };

const out = line => process.stdout.write(`${line}\n`);
// `dba status | head -2` closes the pipe early; that is the reader's choice, not an error.
process.stdout.on('error', error => { if (error.code === 'EPIPE') process.exit(process.exitCode ?? 0); else throw error; });
const note = line => process.stderr.write(`${line}\n`);

// ---- files -------------------------------------------------------------------------------

async function readJsonFile(path) {
  try { return JSON.parse(await readFile(path, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
async function readTextFile(path) {
  try { return (await readFile(path, 'utf8')).trim(); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

/**
 * Write a file only its owner can read, atomically, so a crash never leaves half a key. chmod
 * after writing because `mode` only applies when a file is created.
 */
async function writePrivate(path, text) {
  const temp = `${path}.${process.pid}.tmp`;
  await writeFile(temp, text, { mode: 0o600 });
  await chmod(temp, 0o600);
  await rename(temp, path);
}

/**
 * Run a program without a shell, feeding `input` on stdin. Resolves to { code, stdout }; code is
 * null when it could not start or took longer than `timeoutMs` (a keyring waiting for an unlock
 * prompt nobody will answer).
 */
function runProgram(command, args, input, { timeoutMs = 20_000 } = {}) {
  return new Promise(resolve => {
    let child;
    try { child = spawn(command, args, { stdio: ['pipe', 'pipe', 'ignore'] }); } catch { resolve({ code: null, stdout: '' }); return; }
    let stdout = '';
    let done = false;
    const finish = code => { if (!done) { done = true; clearTimeout(timer); resolve({ code, stdout }); } };
    const timer = setTimeout(() => { child.kill(); finish(null); }, timeoutMs);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.on('error', () => finish(null));
    child.on('close', code => finish(code));
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}

async function ensureDir(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await chmod(dir, 0o700);
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8').trim();
}

/** The profile's files and everything needed to act as the device. */
async function loadProfile(globals) {
  const paths = configPaths({ env: process.env, home: homedir(), profile: globals.profile });
  const config = await readJsonFile(paths.config) || {};
  const origin = resolveOrigin({ flag: globals.origin, env: process.env, saved: config.origin });
  // DPAPI blobs live in the profile directory, which a first enrollment has not made yet.
  const files = { read: readTextFile, write: async (path, text) => { await ensureDir(paths.dir); await writePrivate(path, text); }, remove: path => rm(path, { force: true }) };
  const secrets = osSecretStore({ platform: process.platform, run: runProgram, files, dir: paths.dir });
  const tpm = { backend: TPM_BACKEND, name: TPM_NAME, open: nodeTpmSessions() };
  return { paths, config, origin, secrets, tpm, client: createClient({ origin }), autoRenew: autoRenewEnabled({ flag: globals['no-renew'], env: process.env }) };
}

/** The saved key and credential; a clear message when this profile has not enrolled yet. */
async function requireDevice(profile) {
  const file = await readJsonFile(profile.paths.key);
  const credential = await readTextFile(profile.paths.credential);
  if (!file || !credential) throw new UsageError(`No credential in ${profile.paths.dir}. Run \`dba enroll\` first.`);
  return { key: await loadDeviceKey(file, { secrets: profile.secrets, tpm: profile.tpm }), credential };
}

/**
 * A lock directory, so two dba processes started together (say, in parallel jobs) do not both
 * renew: the second would be refused as superseded. A lock older than a minute is left over from
 * a crash and is taken over. Returns a release function, or null when another process holds it.
 */
async function lockProfile(profile) {
  const path = `${profile.paths.dir}/renew.lock`;
  for (let attempt = 0; attempt < 2; attempt++) {
    try { await mkdir(path, { mode: 0o700 }); return () => rmdir(path).catch(() => {}); } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const age = Date.now() - (await stat(path).catch(() => ({ mtimeMs: Date.now() }))).mtimeMs;
      if (age < 60_000) return null;
      await rmdir(path).catch(() => {});
    }
  }
  return null;
}

/**
 * The device, renewed first when it is due and auto-renewal is on. Never fails because of the
 * renewal: the current credential is still valid, so the command goes ahead with a warning.
 */
/** Has the issuer withdrawn the key that signed this credential? (cached JWKS, see lib.js) */
function keyWithdrawn(profile, credential) {
  const path = `${profile.paths.dir}/jwks-cache.json`;
  return issuerKeyWithdrawn({ client: profile.client, credential, cache: { read: () => readJsonFile(path), write: entry => writePrivate(path, JSON.stringify(entry)) } });
}

async function usableDevice(profile, { force = false } = {}) {
  const device = await requireDevice(profile);
  if (!force && !profile.autoRenew) return device;
  const due = shouldRenew(inspectCredential(device.credential).payload);
  const withdrawn = !due && await keyWithdrawn(profile, device.credential);
  if (!due && !withdrawn) return device;
  const release = await lockProfile(profile);
  if (!release) return device;
  try {
    // Another process may have renewed while this one waited for the lock.
    const current = await requireDevice(profile);
    const outcome = await renewIfDue({ client: profile.client, device: current, withdrawn: withdrawn && current.credential === device.credential, save: result => writePrivate(profile.paths.credential, `${result.credential}\n`) });
    if (outcome.renewed && outcome.result.recovered) { note(`Renewed ${outcome.result.cid} because the issuer withdrew the key that signed it (free); expires ${relativeTime(outcome.result.exp)}.`); return { ...current, credential: outcome.result.credential }; }
    if (outcome.renewed) { note(`Renewed ${outcome.result.cid} (now ${outcome.result.jti}); expires ${relativeTime(outcome.result.exp)}.`); return { ...current, credential: outcome.result.credential }; }
    if (outcome.reason === 'superseded') return requireDevice(profile);
    if (outcome.reason === 'failed') note(`dba: could not renew the credential (${outcome.error.code || outcome.error.message}); using the current one, which expires ${relativeTime(inspectCredential(current.credential).payload.exp)}.`);
    return current;
  } finally {
    await release();
  }
}

async function credentialArgument(value) {
  if (value === undefined) throw new UsageError('Give a credential, or - to read one from stdin');
  const credential = value === '-' ? await readStdin() : value.trim();
  try { inspectCredential(credential); } catch { throw new UsageError('That is not a credential (expected a compact JWS: three base64url parts separated by dots)'); }
  return credential;
}

function requestTarget(positionals, command) {
  const [method, url] = positionals;
  if (!method || !url || positionals.length > 2) throw new UsageError(`Usage: dba ${command} METHOD URL`);
  try { new URL(url); } catch { throw new UsageError(`Not a URL: ${url}`); }
  return { method: method.toUpperCase(), url };
}

/**
 * A new device key, kept as `mode` says: made in the TPM for "tpm", else in software and saved by
 * saveDeviceKey. Returns { key, saved } like saveDeviceKey's result plus the loaded key.
 */
async function newSavedKey(profile, mode) {
  if (mode !== 'tpm') {
    const key = await newDeviceKey();
    return { key, saved: await saveDeviceKey(key, { mode, secrets: profile.secrets }) };
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

// ---- commands ----------------------------------------------------------------------------

async function enroll(profile, { options }) {
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
  await forgetDeviceKey(previous, { secrets: profile.secrets });
  const attestation = key.tpm ? await attestTpmKey(profile, key) : undefined;
  const request = await signEnrollmentRequest(key, enrollmentPayload({ aud, grants, name: options.name || hostname(), kind: options.kind, lifetime, keyProtection: saved.keyProtection, attestation }));
  if (key.tpm) note(`The private key is in ${profile.tpm.name}; it cannot leave it.`);
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

async function status(profile, { options }) {
  const { key, credential } = options.online ? await usableDevice(profile) : await requireDevice(profile);
  const { payload } = inspectCredential(credential);
  const server = options.online ? await profile.client.request('GET', '/api/v1/whoami', { device: { key, credential } }) : undefined;
  if (options.json) { out(JSON.stringify({ profile: profile.paths.dir, origin: profile.origin, credential: payload, ...(server ? { server } : {}) }, null, 2)); return; }
  for (const line of describeCredential(payload)) out(line);
  if (server) out(`\nThe server accepts this credential (account ${server.account}, version ${String(server.jti).split('.').at(-1)}).`);
  else out(`\n(Read from ${profile.paths.credential}; add --online to check it with ${profile.origin}.)`);
  if (payload.exp * 1000 > Date.now() && shouldRenew(payload)) note(`It expires ${relativeTime(payload.exp)}: run \`dba renew\`.`);
}

async function inspect(profile, { options, positionals }) {
  const credential = await credentialArgument(positionals[0]);
  const result = await profile.client.request('POST', '/api/v1/inspect', { body: { credential } });
  if (options.json) { out(JSON.stringify(result, null, 2)); return; }
  for (const line of describeCredential(result.payload)) out(line);
  out('');
  out(`Type:      ${result.header.typ}`);
  out(`Signature: ${result.signature_valid ? `valid (issuer key ${result.header.kid})` : 'NOT valid'}`);
  if (result.revoked !== undefined) out(`Revoked:   ${result.revoked ? 'YES' : 'no'}`);
  out(`Verdict:   ${result.valid ? 'valid' : 'NOT valid'}`);
  for (const problem of result.problems || []) out(`  - ${problem.code}: ${problem.message}`);
}

async function importCredential(profile, { positionals }) {
  const credential = await credentialArgument(positionals[0]);
  const file = await readJsonFile(profile.paths.key);
  if (!file) throw new UsageError(`No key in ${profile.paths.dir}. Run \`dba enroll --print-request\` first.`);
  if (!await credentialMatchesKey(credential, await loadDeviceKey(file, { secrets: profile.secrets, tpm: profile.tpm }))) throw new UsageError('That credential was issued for a different key (cnf.jkt does not match key.json).');
  await writePrivate(profile.paths.credential, `${credential}\n`);
  for (const line of describeCredential(inspectCredential(credential).payload)) out(line);
}

async function headers(profile, { positionals }) {
  const { method, url } = requestTarget(positionals, 'headers');
  const device = await usableDevice(profile);
  const all = { ...await deviceHeaders({ ...device, method, url }), ...confirmationHeaders(await usableConfirmation(profile, device)) };
  for (const [name, value] of Object.entries(all)) out(`${name}: ${value}`);
}

async function sign(profile, { positionals }) {
  const { method, url } = requestTarget(positionals, 'sign');
  const { key, credential } = await usableDevice(profile);
  out(await createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method, url, credential }));
}

/** Run curl to completion; with `capture`, its stdout is returned instead of shown. */
function runCurl(args, { capture = false } = {}) {
  const child = spawn('curl', args, { stdio: ['inherit', capture ? 'pipe' : 'inherit', 'inherit'] });
  const chunks = [];
  child.stdout?.on('data', chunk => chunks.push(chunk));
  return new Promise((resolve, reject) => {
    child.on('error', error => reject(error.code === 'ENOENT' ? new UsageError('curl is not installed') : error));
    child.on('close', (code, signal) => resolve({ code: code ?? (signal ? 1 : 0), stdout: Buffer.concat(chunks).toString('utf8') }));
  });
}

async function curl(profile, allArgs) {
  const { args, waitSeconds } = curlWaitOption(allArgs);
  const { method, url } = curlRequest(args);
  const device = await usableDevice(profile);
  // The headers go to curl in a file only this user can read (see curlArgs), removed afterwards.
  const dir = await mkdtemp(join(tmpdir(), 'dba-curl-'));
  try {
    const file = join(dir, 'headers');
    const confirmation = await usableConfirmation(profile, device);
    const writeHeaders = async () => writeFile(file, curlHeaderFile({ ...await deviceHeaders({ ...device, method, url }), ...confirmationHeaders(confirmation) }), { mode: 0o600 });
    if (waitSeconds === null) {
      await writeHeaders();
      return (await runCurl(curlArgs(args, file))).code;
    }
    // --dba-wait: read each response; while the site answers gate_pending, send the request again
    // with a fresh proof (a proof is used once) until it answers otherwise or the wait runs out.
    const body = join(dir, 'body');
    let code = 0;
    const { response, gaveUp } = await waitThroughGates(async () => {
      await writeHeaders();
      await rm(body, { force: true });
      const result = await runCurl([...curlArgs(args, file), '--no-progress-meter', '-o', body, '-w', '%{http_code}'], { capture: true });
      code = result.code;
      const raw = await readFile(body).catch(() => Buffer.alloc(0)); // no file: curl failed, or HEAD
      return { status: Number(result.stdout.trim().slice(-3)) || 0, body: raw.toString('utf8'), raw };
    }, { waitSeconds, onPending: gate => note(describePendingGate(gate)) });
    process.stdout.write(response.raw);
    if (gaveUp) { note(`dba: still waiting for gates after ${waitSeconds} s; giving up.`); return 1; }
    return code;
  } finally { await rm(dir, { recursive: true, force: true }); }
}

async function token(profile, { options }) {
  if (!options.aud) throw new UsageError('Usage: dba token --aud SITE');
  const device = await usableDevice(profile);
  const result = await profile.client.request('POST', '/api/v1/token', { device, body: { audience: options.aud } });
  // Only the token on stdout, so $(dba token --aud x) works.
  out(result.access_token);
}

async function certificate(profile, { options }) {
  const lifetime = secondsOption(options.lifetime, 'lifetime');
  const device = await usableDevice(profile);
  if (!device.key.privateJwk) throw new UsageError('This device\'s key is in the TPM and cannot be written to a file for curl. Use `dba curl`, or a TLS stack with a TPM provider (tpm2-openssl).');
  const result = await profile.client.request('POST', '/api/v1/certificate', { device, body: lifetime ? { lifetime_seconds: lifetime } : {} });
  // curl and most TLS stacks want the key as PKCS#8 PEM; it is the same key as key.json.
  const keyPem = createPrivateKey({ key: device.key.privateJwk, format: 'jwk' }).export({ type: 'pkcs8', format: 'pem' });
  await writePrivate(profile.paths.certificateKey, keyPem);
  await writePrivate(profile.paths.certificate, result.certificate);
  await writePrivate(profile.paths.ca, result.ca);
  out(`Client certificate for ${result.subject}, valid until ${result.not_after}:`);
  out(`  certificate  ${profile.paths.certificate}`);
  out(`  private key  ${profile.paths.certificateKey}`);
  out(`  issuing CA   ${profile.paths.ca}`);
  out('');
  out(`curl --cert ${profile.paths.certificate} --key ${profile.paths.certificateKey} https://…`);
}

async function renew(profile, { options }) {
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
  const fresh = options.rotate ? await newSavedKey(profile, previous?.key_store === TPM_BACKEND ? 'tpm' : previous?.key_store ? 'os' : 'file') : null;
  const next = fresh?.key ?? null;
  const saved = fresh?.saved ?? null;
  const body = next ? { new_key_proof: await rotationProof(next, cid) } : {};
  let result;
  try {
    result = await profile.client.request('POST', `/api/v1/credentials/${encodeURIComponent(cid)}/renew`, { device, body });
  } catch (error) {
    if (saved) await forgetDeviceKey(saved.file, { secrets: profile.secrets });
    throw error;
  }
  if (saved) {
    await writePrivate(profile.paths.key, `${JSON.stringify(saved.file, null, 2)}\n`);
    await forgetDeviceKey(previous, { secrets: profile.secrets });
  }
  await writePrivate(profile.paths.credential, `${result.credential}\n`);
  out(`${result.rotated ? 'Rotated to a new key and renewed' : 'Renewed'} ${result.cid}${result.recovered ? ' (the issuer withdrew the key that signed it; no charge)' : ''} (now ${result.jti}); expires ${new Date(result.exp * 1000).toISOString()} (${relativeTime(result.exp)}).`);
}

async function revoke(profile) {
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
  await forgetDeviceKey(await readJsonFile(profile.paths.key), { secrets: profile.secrets });
  for (const path of [profile.paths.credential, profile.paths.confirmation, profile.paths.key, profile.paths.config, profile.paths.certificate, profile.paths.certificateKey, profile.paths.ca]) await rm(path, { force: true });
  await rmdir(profile.paths.dir).catch(() => {});
  out(`Deleted the key and credential in ${profile.paths.dir}.`);
}

async function list(profile, { options }) {
  listQuery(options); // check the options before touching keys or the network
  const apiKey = process.env.DBA_API_KEY?.trim();
  let auth;
  try { auth = apiKey ? { apiKey } : { device: await usableDevice(profile) }; } catch (error) {
    if (error instanceof UsageError) throw new UsageError(`${error.message} Or set DBA_API_KEY to an API key with credentials:read.`);
    throw error;
  }
  const items = []; let cursor; let more = false;
  do {
    const page = await profile.client.request('GET', listQuery({ status: options.status, audience: options.audience, device: options.device, cursor }), auth);
    items.push(...page.items);
    cursor = page.next_cursor || undefined;
    more = !!cursor;
  } while (options.all && cursor);
  if (options.json) { out(JSON.stringify({ items, next_cursor: cursor ?? null }, null, 2)); return; }
  for (const line of formatCredentialList(items)) out(line);
  if (more) note('More credentials exist: add --all to list every page.');
}

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
async function usableConfirmation(profile, device) {
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

async function confirm(profile, { options }) {
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

async function gatesCommand(profile, { options, positionals }) {
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

async function approvals(profile, { options, positionals }) {
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

const HANDLERS = { list, confirm, approvals, gates: gatesCommand, enroll, status, whoami: status, inspect, import: importCredential, headers, sign, token, certificate, renew, revoke };

async function main(argv) {
  const { globals, command, rest } = splitCommand(argv);
  if (!command || command === 'help' || (globals.help && command !== 'curl')) { out(HELP); return 0; }
  if (command === 'curl') return curl(await loadProfile(globals), rest);
  const spec = COMMANDS[command];
  if (!spec) throw new UsageError(`Unknown command "${command}"`);
  const parsed = parseArgs(rest, { values: [...(spec.values || []), ...GLOBAL.values], booleans: [...(spec.booleans || []), ...GLOBAL.booleans], repeatable: spec.repeatable || [] });
  if (parsed.options.help) { out(HELP); return 0; }
  for (const name of [...GLOBAL.values, 'no-renew']) if (parsed.options[name] !== undefined) globals[name] = parsed.options[name];
  await HANDLERS[command](await loadProfile(globals), parsed);
  return 0;
}

main(process.argv.slice(2)).then(code => { process.exitCode = code; }, error => {
  if (error instanceof UsageError) note(`dba: ${error.message}\nRun \`dba help\` for usage.`);
  else if (error instanceof ApiError) note(`dba: ${error.message}${error.code ? ` (${error.code})` : ''}`);
  else note(`dba: ${error.stack || error.message}`);
  process.exitCode = 1;
});
