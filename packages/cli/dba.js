#!/usr/bin/env node
/**
 * dba: enroll this machine as a device on devicebasedauth.org, then use its credential.
 * Node 22+, no dependencies beyond @devicebasedauth/verify. The logic lives in lib.js; this file
 * only touches files, stdin/stdout and child processes.
 */
import { mkdir, readFile, writeFile, rename, chmod, rm, rmdir } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { homedir, hostname } from 'node:os';
import {
  UsageError, ApiError, parseArgs, splitCommand, configPaths, resolveOrigin, audiencesFromOption, grantsFromOptions, secondsOption,
  enrollmentPayload, newDeviceKey, keyFile, loadDeviceKey, signEnrollmentRequest, rotationProof, deviceHeaders, credentialMatchesKey,
  curlRequest, curlArgs, createClient, pollEnrollment, describeCredential, shouldRenew, relativeTime
} from './lib.js';
import { inspectCredential, createProof } from '../verify/src/index.js';

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

Use the credential:
  dba status | whoami [--online] [--json]   What this device may do, in plain English.
  dba headers METHOD URL                    Print Authorization and DPoP headers for one request.
  dba sign METHOD URL                       Print only the DPoP proof.
  dba curl CURL-ARGS...                     Run curl with the headers added.
  dba token --aud SITE                      Print a 10-minute bearer token for SITE:
                                              curl -H "Authorization: Bearer $(dba token --aud hashbin.org)" ...
  dba renew [--rotate]                      Renew the credential (--rotate: move to a new key).
  dba revoke                                Revoke this device's credential and delete its files.

Any credential:
  dba inspect CREDENTIAL|- [--json]         Decode it and ask the server about its signature and revocation.
  dba import CREDENTIAL|-                   Save a credential issued for this profile's key.

Options:
  --profile NAME   Keep several devices apart (default "default").
  --origin URL     Server (default $DBA_ORIGIN, then the origin used at enrollment,
                   then https://devicebasedauth.org).

Files: $DBA_HOME/<profile>/ (default ~/.config/dba/<profile>/): key.json, credential.jwt, config.json.
`;

const COMMANDS = {
  enroll: { values: ['name', 'kind', 'lifetime', 'wait'], repeatable: ['aud', 'grant', 'action'], booleans: ['print-request', 'force'] },
  status: { booleans: ['online', 'json'] },
  whoami: { booleans: ['online', 'json'] },
  inspect: { booleans: ['json'] },
  import: {},
  headers: {},
  sign: {},
  token: { values: ['aud'] },
  renew: { booleans: ['rotate'] },
  revoke: {},
  help: {}
};
const GLOBAL = { values: ['profile', 'origin'], booleans: ['help'] };

const out = line => process.stdout.write(`${line}\n`);
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
  return { paths, config, origin, client: createClient({ origin }) };
}

/** The saved key and credential; a clear message when this profile has not enrolled yet. */
async function requireDevice(profile) {
  const file = await readJsonFile(profile.paths.key);
  const credential = await readTextFile(profile.paths.credential);
  if (!file || !credential) throw new UsageError(`No credential in ${profile.paths.dir}. Run \`dba enroll\` first.`);
  return { key: await loadDeviceKey(file), credential };
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
  const aud = audiencesFromOption(options.aud);
  const grants = grantsFromOptions(options);
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
  const { key, credential } = await requireDevice(profile);
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
  const device = await requireDevice(profile);
  for (const [name, value] of Object.entries(await deviceHeaders({ ...device, method, url }))) out(`${name}: ${value}`);
}

async function sign(profile, { positionals }) {
  const { method, url } = requestTarget(positionals, 'sign');
  const { key, credential } = await requireDevice(profile);
  out(await createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method, url, credential }));
}

async function curl(profile, args) {
  const { method, url } = curlRequest(args);
  const device = await requireDevice(profile);
  const child = spawn('curl', curlArgs(args, await deviceHeaders({ ...device, method, url })), { stdio: 'inherit' });
  return new Promise((resolve, reject) => {
    child.on('error', error => reject(error.code === 'ENOENT' ? new UsageError('curl is not installed') : error));
    child.on('exit', (code, signal) => resolve(code ?? (signal ? 1 : 0)));
  });
}

async function token(profile, { options }) {
  if (!options.aud) throw new UsageError('Usage: dba token --aud SITE');
  const device = await requireDevice(profile);
  const result = await profile.client.request('POST', '/api/v1/token', { device, body: { audience: options.aud } });
  // Only the token on stdout, so $(dba token --aud x) works.
  out(result.access_token);
}

async function renew(profile, { options }) {
  const device = await requireDevice(profile);
  const { cid } = inspectCredential(device.credential).payload;
  const next = options.rotate ? await newDeviceKey() : null;
  const body = next ? { new_key_proof: await rotationProof(next, cid) } : {};
  const result = await profile.client.request('POST', `/api/v1/credentials/${encodeURIComponent(cid)}/renew`, { device, body });
  // Save only after the server agreed: until then the old key and credential are the good pair.
  if (next) await writePrivate(profile.paths.key, `${JSON.stringify(keyFile(next), null, 2)}\n`);
  await writePrivate(profile.paths.credential, `${result.credential}\n`);
  out(`${result.rotated ? 'Rotated to a new key and renewed' : 'Renewed'} ${result.cid} (now ${result.jti}); expires ${new Date(result.exp * 1000).toISOString()} (${relativeTime(result.exp)}).`);
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
  for (const path of [profile.paths.credential, profile.paths.key, profile.paths.config]) await rm(path, { force: true });
  await rmdir(profile.paths.dir).catch(() => {});
  out(`Deleted the key and credential in ${profile.paths.dir}.`);
}

const HANDLERS = { enroll, status, whoami: status, inspect, import: importCredential, headers, sign, token, renew, revoke };

async function main(argv) {
  const { globals, command, rest } = splitCommand(argv);
  if (!command || command === 'help' || (globals.help && command !== 'curl')) { out(HELP); return 0; }
  if (command === 'curl') return curl(await loadProfile(globals), rest);
  const spec = COMMANDS[command];
  if (!spec) throw new UsageError(`Unknown command "${command}"`);
  const parsed = parseArgs(rest, { values: [...(spec.values || []), ...GLOBAL.values], booleans: [...(spec.booleans || []), ...GLOBAL.booleans], repeatable: spec.repeatable || [] });
  if (parsed.options.help) { out(HELP); return 0; }
  for (const name of GLOBAL.values) if (parsed.options[name] !== undefined) globals[name] = parsed.options[name];
  await HANDLERS[command](await loadProfile(globals), parsed);
  return 0;
}

main(process.argv.slice(2)).then(code => { process.exitCode = code; }, error => {
  if (error instanceof UsageError) note(`dba: ${error.message}\nRun \`dba help\` for usage.`);
  else if (error instanceof ApiError) note(`dba: ${error.message}${error.code ? ` (${error.code})` : ''}`);
  else note(`dba: ${error.stack || error.message}`);
  process.exitCode = 1;
});
