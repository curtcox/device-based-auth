/** Using the credential (status, headers, sign, curl, token, certificate) and looking at others (inspect, list). */
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createPrivateKey } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspectCredential, createProof } from '@devicebasedauth/verify';
import { UsageError } from '../errors.js';
import { secondsOption } from '../args.js';
import { deviceHeaders } from '../device-key.js';
import { describeCredential, timedGrantProblem, shouldRenew, relativeTime, listQuery, formatCredentialList } from '../credentials.js';
import { curlRequest, curlArgs, curlHeaderFile, curlWaitOption } from '../curl.js';
import { confirmationHeaders, waitThroughGates, describePendingGate } from '../gates.js';
import { out, note, writePrivate, requireDevice, usableDevice, credentialArgument } from './profile.js';
import { usableConfirmation } from './gates.js';

/** `dba status` / `dba whoami`: what this device may do, read locally or checked --online. */
export async function status(profile, { options }) {
  const { key, credential } = options.online ? await usableDevice(profile) : await requireDevice(profile);
  const { payload } = inspectCredential(credential);
  const server = options.online ? await profile.client.request('GET', '/api/v1/whoami', { device: { key, credential } }) : undefined;
  if (options.json) { out(JSON.stringify({ profile: profile.paths.dir, origin: profile.origin, credential: payload, ...(server ? { server } : {}) }, null, 2)); return; }
  for (const line of describeCredential(payload)) out(line);
  if (server) out(`\nThe server accepts this credential (account ${server.account}, version ${String(server.jti).split('.').at(-1)}).`);
  else out(`\n(Read from ${profile.paths.credential}; add --online to check it with ${profile.origin}.)`);
  if (payload.exp * 1000 > Date.now() && shouldRenew(payload)) note(`It expires ${relativeTime(payload.exp)}: run \`dba renew\`.`);
}

/** `dba inspect`: decode any credential and ask the server about its signature and revocation. */
export async function inspect(profile, { options, positionals }) {
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

/** The METHOD URL that `dba headers` and `dba sign` take. */
function requestTarget(positionals, command) {
  const [method, url] = positionals;
  if (!method || !url || positionals.length > 2) throw new UsageError(`Usage: dba ${command} METHOD URL`);
  try { new URL(url); } catch { throw new UsageError(`Not a URL: ${url}`); }
  return { method: method.toUpperCase(), url };
}

/** Refuse (or warn about) a credential whose grants need a timed challenge (see timedGrantProblem). */
function checkUntimed(credential, command) {
  const problem = timedGrantProblem(inspectCredential(credential).payload, command);
  if (problem?.refuse) throw new UsageError(problem.refuse);
  if (problem?.warn) note(problem.warn);
}

/** `dba headers`: Authorization and DPoP (and DBA-Confirmation) headers for one request. */
export async function headers(profile, { positionals }) {
  const { method, url } = requestTarget(positionals, 'headers');
  const device = await usableDevice(profile);
  checkUntimed(device.credential, 'headers');
  const nonce = await profile.client.nonceFor(device, url);
  const all = { ...await deviceHeaders({ ...device, method, url, nonce }), ...confirmationHeaders(await usableConfirmation(profile, device)) };
  for (const [name, value] of Object.entries(all)) out(`${name}: ${value}`);
}

/** `dba sign`: only the DPoP proof for one request. */
export async function sign(profile, { positionals }) {
  const { method, url } = requestTarget(positionals, 'sign');
  const device = await usableDevice(profile);
  checkUntimed(device.credential, 'sign');
  const { key, credential } = device;
  out(await createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method, url, credential, nonce: await profile.client.nonceFor(device, url) }));
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

/** `dba curl`: run curl with the headers added, waiting through gates with --dba-wait. Returns the exit code. */
export async function curl(profile, allArgs) {
  const { args, waitSeconds } = curlWaitOption(allArgs);
  const { method, url } = curlRequest(args);
  const device = await usableDevice(profile);
  checkUntimed(device.credential, 'curl');
  // The headers go to curl in a file only this user can read (see curlArgs), removed afterwards.
  const dir = await mkdtemp(join(tmpdir(), 'dba-curl-'));
  try {
    const file = join(dir, 'headers');
    const confirmation = await usableConfirmation(profile, device);
    // curl sends once, so a request to devicebasedauth.org carries its account's DPoP nonce from
    // the start (a just-started account object would refuse a proof without it).
    const nonce = await profile.client.nonceFor(device, url);
    const writeHeaders = async () => writeFile(file, curlHeaderFile({ ...await deviceHeaders({ ...device, method, url, nonce }), ...confirmationHeaders(confirmation) }), { mode: 0o600 });
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

/** `dba token`: a 10-minute bearer token for one site. */
export async function token(profile, { options }) {
  if (!options.aud) throw new UsageError('Usage: dba token --aud SITE');
  const device = await usableDevice(profile);
  const result = await profile.client.request('POST', '/api/v1/token', { device, body: { audience: options.aud } });
  // Only the token on stdout, so $(dba token --aud x) works.
  out(result.access_token);
}

/** `dba certificate`: an X.509 client certificate for this device's key, for mTLS. */
export async function certificate(profile, { options }) {
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

/** `dba list`: every credential on the account, by API key or this device. */
export async function list(profile, { options }) {
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
