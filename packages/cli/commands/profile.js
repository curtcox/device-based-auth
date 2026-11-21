/**
 * What every dba command shares: printing, the profile's private files, child processes, and
 * the device (key and credential) loaded from the profile and renewed when it is due.
 */
import { mkdir, readFile, writeFile, rename, chmod, rmdir, rm, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';
import { inspectCredential } from '@devicebasedauth/verify';
import { UsageError } from '../errors.js';
import { configPaths, resolveOrigin } from '../args.js';
import { loadDeviceKey, osSecretStore } from '../device-key.js';
import { createClient } from '../client.js';
import { shouldRenew, relativeTime, autoRenewEnabled, renewIfDue, issuerKeyWithdrawn } from '../credentials.js';
import { TPM_BACKEND, TPM_NAME } from '../tpm.js';
import { nodeTpmSessions } from '../tpm-node.js';

/** Print a line of the command's output (stdout). */
export const out = line => process.stdout.write(`${line}\n`);
/** Print a line of commentary (stderr), so stdout stays parseable. */
export const note = line => process.stderr.write(`${line}\n`);

/** A JSON file, or null when it does not exist. */
export async function readJsonFile(path) {
  try { return JSON.parse(await readFile(path, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
/** A text file without surrounding whitespace, or null when it does not exist. */
export async function readTextFile(path) {
  try { return (await readFile(path, 'utf8')).trim(); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

/**
 * Write a file only its owner can read, atomically, so a crash never leaves half a key. chmod
 * after writing because `mode` only applies when a file is created.
 */
export async function writePrivate(path, text) {
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

/** Make the profile directory, private to its owner even if it already existed. */
export async function ensureDir(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await chmod(dir, 0o700);
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8').trim();
}

/** The profile's files and everything needed to act as the device. */
export async function loadProfile(globals) {
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
export async function requireDevice(profile) {
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

/** Has the issuer withdrawn the key that signed this credential? (cached JWKS, see credentials.js) */
export function keyWithdrawn(profile, credential) {
  const path = `${profile.paths.dir}/jwks-cache.json`;
  return issuerKeyWithdrawn({ client: profile.client, credential, cache: { read: () => readJsonFile(path), write: entry => writePrivate(path, JSON.stringify(entry)) } });
}

/**
 * The device, renewed first when it is due and auto-renewal is on. Never fails because of the
 * renewal: the current credential is still valid, so the command goes ahead with a warning.
 */
export async function usableDevice(profile, { force = false } = {}) {
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

/** A credential given on the command line, or read from stdin for "-"; refuses anything that is not a compact JWS. */
export async function credentialArgument(value) {
  if (value === undefined) throw new UsageError('Give a credential, or - to read one from stdin');
  const credential = value === '-' ? await readStdin() : value.trim();
  try { inspectCredential(credential); } catch { throw new UsageError('That is not a credential (expected a compact JWS: three base64url parts separated by dots)'); }
  return credential;
}
