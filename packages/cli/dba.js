#!/usr/bin/env node
/**
 * dba: enroll this machine as a device on devicebasedauth.org, then use its credential.
 * Node 22+, no dependencies beyond @devicebasedauth/verify. The logic lives in lib.js; this file
 * only touches files, stdin/stdout and child processes.
 */
import { mkdir, readFile, writeFile, rename, chmod, rm, rmdir, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createPrivateKey } from 'node:crypto';
import { homedir, hostname } from 'node:os';
import {
  UsageError, ApiError, parseArgs, splitCommand, configPaths, resolveOrigin, audiencesFromOption, grantsFromOptions, secondsOption,
  enrollmentPayload, enrollmentTokenOption, newDeviceKey, keyFile, loadDeviceKey, signEnrollmentRequest, rotationProof, deviceHeaders, credentialMatchesKey,
  curlRequest, curlArgs, createClient, pollEnrollment, describeCredential, shouldRenew, relativeTime, autoRenewEnabled, renewIfDue, issuerKeyWithdrawn, listQuery, formatCredentialList
} from './lib.js';
import { inspectCredential, createProof } from '@devicebasedauth/verify';

const HELP = `dba — device credentials from devicebasedauth.org

Usage: dba [--profile NAME] [--origin URL] <command> [options]

Enroll this machine:
  dba enroll --aud SITE[,SITE] (--action ACTION ... | --grant 'JSON' ...)
             [--name "My laptop"] [--kind cli] [--lifetime SECONDS] [--wait SECONDS]
             [--print-request] [--force]
      Makes a new P-256 key, asks for a credential and prints a link for the account owner to
      approve. Waits (default 900 s) and saves the credential. All --action values form one
      grant; each --grant adds one (or a JSON list). --print-request only prints the signed
      request (for agents and the MCP server); finish with \`dba import\`.
      The private key is kept in a 0600 file, so credentials made by this CLI say
      key_protection "software". It never leaves this machine.
  dba enroll --token dbae_… [--aud …] [--action …] [--name …]
      Enroll with an enrollment token the owner created for a fleet: no approval link, the
      credential is issued at once. The token's audiences and grants apply unless you narrow
      them. Prefer DBA_ENROLLMENT_TOKEN=dbae_… over --token to keep it out of shell history.

Use the credential:
  dba status | whoami [--online] [--json]   What this device may do, in plain English.
  dba headers METHOD URL                    Print Authorization and DPoP headers for one request.
  dba sign METHOD URL                       Print only the DPoP proof.
  dba curl CURL-ARGS...                     Run curl with the headers added.
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
`;

const COMMANDS = {
  enroll: { values: ['name', 'kind', 'lifetime', 'wait', 'token'], repeatable: ['aud', 'grant', 'action'], booleans: ['print-request', 'force'] },
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
  return { paths, config, origin, client: createClient({ origin }), autoRenew: autoRenewEnabled({ flag: globals['no-renew'], env: process.env }) };
}

/** The saved key and credential; a clear message when this profile has not enrolled yet. */
async function requireDevice(profile) {
  const file = await readJsonFile(profile.paths.key);
  const credential = await readTextFile(profile.paths.credential);
  if (!file || !credential) throw new UsageError(`No credential in ${profile.paths.dir}. Run \`dba enroll\` first.`);
  return { key: await loadDeviceKey(file), credential };
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

// ---- commands ----------------------------------------------------------------------------

async function enroll(profile, { options }) {
  const token = enrollmentTokenOption({ flag: options.token, env: process.env });
  if (token && options['print-request']) throw new UsageError('--print-request is for approval links; with an enrollment token the credential is issued at once');
  // With a token, audiences and grants are optional: the token's template applies.
  const aud = token && !options.aud?.length ? undefined : audiencesFromOption(options.aud);
  const grants = token && !options.grant?.length && !options.action?.length ? undefined : grantsFromOptions(options);
  const lifetime = secondsOption(options.lifetime, 'lifetime');
  const waitSeconds = secondsOption(options.wait, 'wait') ?? 900;
  // Replacing the key orphans the current credential, so never do it by accident.
  if (!options.force && await readTextFile(profile.paths.credential)) throw new UsageError(`This profile already has a credential (${profile.paths.credential}). Use --profile NAME for another device, or --force to replace it.`);

  const key = await newDeviceKey();
  const request = await signEnrollmentRequest(key, enrollmentPayload({ aud, grants, name: options.name || hostname(), kind: options.kind, lifetime }));
  await ensureDir(profile.paths.dir);
  // Save the key before asking, so an interrupted wait can still be finished with `dba import`.
  await writePrivate(profile.paths.key, `${JSON.stringify(keyFile(key), null, 2)}\n`);
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
  if (!await credentialMatchesKey(credential, await loadDeviceKey(file))) throw new UsageError('That credential was issued for a different key (cnf.jkt does not match key.json).');
  await writePrivate(profile.paths.credential, `${credential}\n`);
  for (const line of describeCredential(inspectCredential(credential).payload)) out(line);
}

async function headers(profile, { positionals }) {
  const { method, url } = requestTarget(positionals, 'headers');
  const device = await usableDevice(profile);
  for (const [name, value] of Object.entries(await deviceHeaders({ ...device, method, url }))) out(`${name}: ${value}`);
}

async function sign(profile, { positionals }) {
  const { method, url } = requestTarget(positionals, 'sign');
  const { key, credential } = await usableDevice(profile);
  out(await createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method, url, credential }));
}

async function curl(profile, args) {
  const { method, url } = curlRequest(args);
  const device = await usableDevice(profile);
  const child = spawn('curl', curlArgs(args, await deviceHeaders({ ...device, method, url })), { stdio: 'inherit' });
  return new Promise((resolve, reject) => {
    child.on('error', error => reject(error.code === 'ENOENT' ? new UsageError('curl is not installed') : error));
    child.on('exit', (code, signal) => resolve(code ?? (signal ? 1 : 0)));
  });
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
  const next = options.rotate ? await newDeviceKey() : null;
  const body = next ? { new_key_proof: await rotationProof(next, cid) } : {};
  const result = await profile.client.request('POST', `/api/v1/credentials/${encodeURIComponent(cid)}/renew`, { device, body });
  // Save only after the server agreed: until then the old key and credential are the good pair.
  if (next) await writePrivate(profile.paths.key, `${JSON.stringify(keyFile(next), null, 2)}\n`);
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
  for (const path of [profile.paths.credential, profile.paths.key, profile.paths.config, profile.paths.certificate, profile.paths.certificateKey, profile.paths.ca]) await rm(path, { force: true });
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

const HANDLERS = { list, enroll, status, whoami: status, inspect, import: importCredential, headers, sign, token, certificate, renew, revoke };

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
