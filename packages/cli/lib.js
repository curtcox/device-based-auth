/**
 * The pure parts of the `dba` CLI: argument parsing, request building, curl argument handling,
 * the API client and the text it prints. dba.js adds only files, stdin/stdout and processes, so
 * everything here can be tested in-process against the Worker.
 */
import {
  signJws, generateKeyPair, exportPublicJwk, importJwk, publicJwk, jwkThumbprint, createProof, inspectCredential, describeGrant, validateGrants
} from '@devicebasedauth/verify';

export const DEFAULT_ORIGIN = 'https://devicebasedauth.org';
export const ENROLL_TYP = 'dba-enroll+jwt';
export const ROTATE_TYP = 'dba-rotate+jwt';
export const DEVICE_KINDS = ['browser', 'phone', 'desktop', 'server', 'cli', 'agent', 'iot', 'other'];
/** Keys in a 0600 file say so in the credential; approvers see it. */
export const KEY_PROTECTION = 'software';
/** Keys whose private part is in the OS secret store (macOS Keychain, Secret Service). */
export const KEYCHAIN_PROTECTION = 'os-keychain';

/** A mistake in how the command was called. dba.js prints it with a pointer to `dba help`. */
export class UsageError extends Error {
  constructor(message) { super(message); this.code = 'usage'; }
}

/** An error response from the server (or no response at all), carrying its { error, code }. */
export class ApiError extends Error {
  constructor(message, code, status = 0, body = null) { super(message); this.code = code; this.status = status; this.body = body; }
}

/**
 * Parse options after a command. `spec` lists the options the command takes:
 * { values: [...], booleans: [...], repeatable: [...] } (repeatable options are also values).
 * Accepts `--name value`, `--name=value`, `-h`, and `--` to end options. Unknown options throw,
 * because a mistyped `--grant` silently ignored would enroll a device with the wrong grants.
 * Returns { options, positionals }.
 */
export function parseArgs(argv, { values = [], booleans = [], repeatable = [] } = {}) {
  const options = {}; const positionals = [];
  for (const name of repeatable) options[name] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') { positionals.push(...argv.slice(i + 1)); break; }
    if (arg === '-h') { options.help = true; continue; }
    if (!arg.startsWith('--') || arg === '-') { positionals.push(arg); continue; }
    const eq = arg.indexOf('=');
    const name = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
    if (booleans.includes(name)) {
      if (eq !== -1) throw new UsageError(`--${name} does not take a value`);
      options[name] = true; continue;
    }
    if (!values.includes(name) && !repeatable.includes(name)) throw new UsageError(`Unknown option --${name}`);
    let value;
    if (eq !== -1) value = arg.slice(eq + 1);
    else { if (i + 1 >= argv.length) throw new UsageError(`--${name} needs a value`); value = argv[++i]; }
    if (repeatable.includes(name)) options[name].push(value); else options[name] = value;
  }
  return { options, positionals };
}

/**
 * Split the global options (--profile, --origin, --no-renew, --help) that come before the command from the
 * command and its arguments. `dba curl` passes everything after the command straight to curl,
 * so global options for it must come first; other commands also accept them later.
 */
export function splitCommand(argv) {
  const globals = {}; let i = 0;
  for (; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') { globals.help = true; continue; }
    if (arg === '--no-renew') { globals['no-renew'] = true; continue; }
    const match = arg.match(/^--(profile|origin)(?:=(.*))?$/);
    if (!match) break;
    if (match[2] !== undefined) globals[match[1]] = match[2];
    else { if (i + 1 >= argv.length) throw new UsageError(`--${match[1]} needs a value`); globals[match[1]] = argv[++i]; }
  }
  return { globals, command: argv[i], rest: argv.slice(i + 1) };
}

/**
 * Where a profile's files live: $DBA_HOME/<profile>, else $XDG_CONFIG_HOME/dba/<profile>, else
 * ~/.config/dba/<profile>. Profiles let one machine hold several devices (say, work and home).
 */
export function configPaths({ env = {}, home, profile = 'default' }) {
  if (!/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$/.test(profile)) throw new UsageError('--profile must be 1–64 letters, digits, ".", "_" or "-"');
  const base = env.DBA_HOME || `${env.XDG_CONFIG_HOME || `${home}/.config`}/dba`;
  const dir = `${base.replace(/\/+$/, '')}/${profile}`;
  return { dir, key: `${dir}/key.json`, credential: `${dir}/credential.jwt`, config: `${dir}/config.json`, certificate: `${dir}/client.crt`, certificateKey: `${dir}/client.key`, ca: `${dir}/ca.crt` };
}

/**
 * The server to talk to: --origin, then $DBA_ORIGIN, then the origin the profile enrolled with
 * (so a device enrolled against a local server keeps using it), then devicebasedauth.org.
 */
export function resolveOrigin({ flag, env = {}, saved } = {}) {
  const value = flag || env.DBA_ORIGIN || saved || DEFAULT_ORIGIN;
  let url;
  try { url = new URL(value); } catch { throw new UsageError(`Not a URL: ${value}`); }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new UsageError(`The origin must be http(s): ${value}`);
  return url.origin;
}

/** Audiences from repeated and/or comma-separated --aud values. */
export function audiencesFromOption(values = []) {
  const audiences = [...new Set(values.flatMap(v => v.split(',')).map(v => v.trim()).filter(Boolean))];
  if (!audiences.length) throw new UsageError('Give the site(s) this device is for with --aud, e.g. --aud hashbin.org');
  return audiences;
}

/**
 * Grants from --grant (one JSON grant, or a JSON list of grants, per use) and --action (all
 * --action values together form one plain grant). Checked locally so a typo fails here, with
 * the evaluator's own message, rather than after the owner has opened the approval page.
 */
export function grantsFromOptions({ grant = [], action = [] }) {
  const grants = [];
  for (const text of grant) {
    let value;
    try { value = JSON.parse(text); } catch { throw new UsageError(`--grant is not valid JSON: ${text}`); }
    grants.push(...(Array.isArray(value) ? value : [value]));
  }
  if (action.length) grants.push({ actions: action });
  if (!grants.length) throw new UsageError('Say what the device may do with --action (e.g. --action hashbin:content:write) or --grant \'<grant JSON>\'');
  const problems = validateGrants(grants);
  if (problems.length) throw new UsageError(`Invalid grants: ${problems.join('; ')}`);
  return grants;
}

/** Parse a whole number of seconds from an option. */
export function secondsOption(value, name) {
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) <= 0) throw new UsageError(`--${name} must be a whole number of seconds`);
  return Number(value);
}

/** An enrollment token from --token or $DBA_ENROLLMENT_TOKEN (the variable keeps it out of shell history). */
export function enrollmentTokenOption({ flag, env = {} } = {}) {
  const token = (flag ?? env.DBA_ENROLLMENT_TOKEN ?? '').trim();
  if (!token) return null;
  if (!token.startsWith('dbae_')) throw new UsageError('An enrollment token starts with dbae_');
  return token;
}

/** The payload of an enrollment request (spec: POST /api/v1/enrollments). */
export function enrollmentPayload({ aud, grants, name, kind = 'cli', lifetime, keyProtection = KEY_PROTECTION, now = Math.floor(Date.now() / 1000) }) {
  if (!DEVICE_KINDS.includes(kind)) throw new UsageError(`--kind must be one of ${DEVICE_KINDS.join(', ')}`);
  // aud and grants may be left out when enrolling with an enrollment token (the token's template applies).
  const payload = { iat: now, ...(aud ? { aud } : {}), ...(grants ? { grants } : {}), device: { name: name || 'dba CLI', kind, key_protection: keyProtection } };
  if (lifetime !== undefined) payload.lifetime_seconds = lifetime;
  return payload;
}

/**
 * A new device key. It is extractable because the CLI has to keep it between runs, in the OS
 * secret store or a 0600 file (see saveDeviceKey); either way it is a software key, never a
 * hardware-bound one. Returns { privateKey, publicJwk, privateJwk }.
 */
export async function newDeviceKey() {
  const pair = await generateKeyPair(true);
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  return { privateKey: pair.privateKey, publicJwk: await exportPublicJwk(pair.publicKey), privateJwk: { kty: 'EC', crv: 'P-256', x: privateJwk.x, y: privateJwk.y, d: privateJwk.d } };
}

/**
 * The contents of key.json for a key from newDeviceKey. With `store` (an entry saved by
 * saveDeviceKey in the OS secret store) the file holds only the public key and where the private
 * part is, so copying the profile directory does not copy the key.
 */
export function keyFile(key, now = new Date(), store = null) {
  if (store) return { public_jwk: key.publicJwk, key_protection: KEYCHAIN_PROTECTION, key_store: store.backend, key_store_account: store.account, created_at: now.toISOString() };
  return { private_jwk: key.privateJwk, public_jwk: key.publicJwk, key_protection: KEY_PROTECTION, created_at: now.toISOString() };
}

/**
 * Load key.json contents back into a signing key. A key kept in the OS secret store needs
 * `secrets` (from osSecretStore); its private part is checked against the public key in the
 * file, so a swapped or stale store entry is caught here and not as a server-side refusal.
 */
export async function loadDeviceKey(file, { secrets } = {}) {
  if (file?.key_store) {
    if (!secrets || secrets.backend !== file.key_store) throw new UsageError(`key.json says the private key is in ${STORE_NAMES[file.key_store] || file.key_store}, which this system cannot reach.`);
    const d = await secrets.load(file.key_store_account);
    if (!d) throw new UsageError(`The private key for this profile is missing from ${STORE_NAMES[file.key_store]} (entry ${file.key_store_account}). Enroll again with \`dba enroll --force\`.`);
    const privateJwk = { kty: 'EC', crv: 'P-256', x: file.public_jwk?.x, y: file.public_jwk?.y, d };
    const mismatch = new UsageError(`The private key in ${STORE_NAMES[file.key_store]} (entry ${file.key_store_account}) does not belong to key.json's public key.`);
    // Node refuses to import a d that does not match x, y; other runtimes may not, hence the signature check.
    const privateKey = await importJwk(privateJwk, 'sign').catch(() => { throw mismatch; });
    const key = { privateKey, publicJwk: publicJwk(privateJwk), privateJwk };
    if (!await keyPairMatches(key)) throw mismatch;
    return key;
  }
  if (!file?.private_jwk?.d) throw new Error('key.json has no private key');
  return { privateKey: await importJwk(file.private_jwk, 'sign'), publicJwk: publicJwk(file.private_jwk), privateJwk: file.private_jwk };
}

/** Does the private key sign for the public key? (not every runtime checks that x, y match d on import) */
async function keyPairMatches(key) {
  const data = crypto.getRandomValues(new Uint8Array(32));
  const algorithm = { name: 'ECDSA', hash: 'SHA-256' };
  const signature = await crypto.subtle.sign(algorithm, key.privateKey, data);
  return crypto.subtle.verify(algorithm, await importJwk(key.publicJwk, 'verify'), signature, data);
}

// ---- OS secret store ----------------------------------------------------------------------

/** Where `dba enroll` keeps the private key: `auto` (the OS secret store when it works, else a file), `os` (fail without one) or `file`. */
export const KEY_STORES = ['auto', 'os', 'file'];
export const SECRET_SERVICE = 'org.devicebasedauth.dba';
const STORE_NAMES = { 'macos-keychain': 'the macOS Keychain', 'secret-service': 'the Secret Service keyring (secret-tool)', 'windows-dpapi': 'Windows DPAPI (your Windows account)' };

/** --key-store, else DBA_KEY_STORE, else auto. */
export function keyStoreOption({ flag, env = {} } = {}) {
  const value = (flag ?? env.DBA_KEY_STORE ?? 'auto').trim().toLowerCase() || 'auto';
  if (!KEY_STORES.includes(value)) throw new UsageError(`--key-store must be one of ${KEY_STORES.join(', ')}`);
  return value;
}

/**
 * The OS secret store for this platform, or null when there is none the CLI knows: the macOS
 * Keychain through `security`, the freedesktop Secret Service (GNOME Keyring, KWallet) through
 * `secret-tool`, or on Windows DPAPI through Windows PowerShell (see windowsDpapiStore). Headless
 * Linux without secret-tool uses the file.
 *
 * `run(command, args, input)` runs a program without a shell and resolves to { code, stdout }
 * (code null when it could not start). The secret never goes on a command line, where other
 * users could read it from the process list: secret-tool reads it from stdin, and `security`
 * gets it inside a command typed into its interactive mode (`security -i`), also on stdin.
 * Entries are named by the key's JWK thumbprint, which is base64url and needs no quoting.
 * Windows also needs `files` ({ read, write, remove } of text files, read resolving to null when
 * absent) and `dir`, where the DPAPI-sealed blobs live.
 */
export function osSecretStore({ platform, run, files, dir }) {
  const check = account => { if (!/^[A-Za-z0-9_-]{43}$/.test(account)) throw new Error('secret store account must be a JWK thumbprint'); };
  const checkSecret = secret => { if (!/^[A-Za-z0-9_-]+$/.test(secret)) throw new Error('secret must be base64url'); };
  if (platform === 'darwin') {
    return {
      backend: 'macos-keychain',
      name: STORE_NAMES['macos-keychain'],
      async save(account, secret) {
        check(account); checkSecret(secret);
        const result = await run('security', ['-i'], `add-generic-password -U -s ${SECRET_SERVICE} -a ${account} -l dba-cli-device-key -w ${secret}\n`);
        return result.code === 0;
      },
      async load(account) {
        check(account);
        const result = await run('security', ['find-generic-password', '-s', SECRET_SERVICE, '-a', account, '-w'], '');
        return result.code === 0 ? result.stdout.trim() || null : null;
      },
      async remove(account) { check(account); await run('security', ['delete-generic-password', '-s', SECRET_SERVICE, '-a', account], ''); }
    };
  }
  if (platform === 'linux' || platform === 'freebsd' || platform === 'openbsd') {
    return {
      backend: 'secret-service',
      name: STORE_NAMES['secret-service'],
      async save(account, secret) {
        check(account); checkSecret(secret);
        const result = await run('secret-tool', ['store', '--label=dba CLI device key', 'service', SECRET_SERVICE, 'account', account], secret);
        return result.code === 0;
      },
      async load(account) {
        check(account);
        const result = await run('secret-tool', ['lookup', 'service', SECRET_SERVICE, 'account', account], '');
        return result.code === 0 ? result.stdout.trim() || null : null;
      },
      async remove(account) { check(account); await run('secret-tool', ['clear', 'service', SECRET_SERVICE, 'account', account], ''); }
    };
  }
  if (platform === 'win32' && files && dir) return windowsDpapiStore({ run, files, dir, check, checkSecret });
  return null;
}

/** PowerShell's -EncodedCommand: the script as base64 of UTF-16LE. */
export function powershellEncoded(script) {
  const bytes = new Uint8Array(script.length * 2);
  for (let i = 0; i < script.length; i++) { const code = script.charCodeAt(i); bytes[2 * i] = code & 0xff; bytes[2 * i + 1] = code >> 8; }
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * The DPAPI script for one entry: reads stdin, and writes base64 of the sealed blob ("protect")
 * or the secret it unseals ("unprotect"). The data is on stdin, never in the script, so neither
 * the secret nor the blob is on a command line. The entropy names the entry, so a blob copied
 * over another entry's file does not unseal there.
 */
export function dpapiScript(mode, account) {
  const call = mode === 'protect'
    ? '[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($in),$entropy,$scope))'
    : '[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($in),$entropy,$scope))';
  return [
    "$ErrorActionPreference='Stop'",
    'Add-Type -AssemblyName System.Security',
    '$in=[Console]::In.ReadToEnd().Trim()',
    `$entropy=[Text.Encoding]::UTF8.GetBytes('${SECRET_SERVICE}/${account}')`,
    '$scope=[Security.Cryptography.DataProtectionScope]::CurrentUser',
    `[Console]::Out.Write(${call})`
  ].join(';');
}

/**
 * Windows: the private key sealed with DPAPI for the signed-in Windows user (CurrentUser scope),
 * the blob in `<dir>/<thumbprint>.dpapi` (the profile directory). Only that user on that machine (or their roaming profile
 * with its password) can unseal it, so copying the profile or the blob elsewhere copies nothing
 * usable. Uses Windows PowerShell 5.1, present on every supported Windows, and the built-in
 * ProtectedData class: nothing to install, nothing compiled.
 */
function windowsDpapiStore({ run, files, dir, check, checkSecret }) {
  const path = account => `${dir}/${account}.dpapi`;
  const powershell = (mode, account, input) => run('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', powershellEncoded(dpapiScript(mode, account))], input);
  return {
    backend: 'windows-dpapi',
    name: STORE_NAMES['windows-dpapi'],
    async save(account, secret) {
      check(account); checkSecret(secret);
      const result = await powershell('protect', account, secret);
      const blob = result.stdout.trim();
      if (result.code !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(blob)) return false;
      await files.write(path(account), blob);
      return true;
    },
    async load(account) {
      check(account);
      const blob = (await files.read(path(account)))?.trim();
      if (!blob || !/^[A-Za-z0-9+/]+={0,2}$/.test(blob)) return null;
      const result = await powershell('unprotect', account, blob);
      return result.code === 0 ? result.stdout.trim() || null : null;
    },
    async remove(account) { check(account); await files.remove(path(account)); }
  };
}

/**
 * Keep a new key: its private part in the OS secret store when `mode` allows and the store works
 * (read back to be sure: a locked or absent keyring can report success), else in key.json.
 * Returns { file, keyProtection, store } where `file` is the key.json contents and `store` the
 * secret-store entry ({ backend, account }) or null. Throws for mode "os" without a working store.
 */
export async function saveDeviceKey(key, { mode = 'auto', secrets, now = new Date() } = {}) {
  if (mode !== 'file' && secrets) {
    const account = await jwkThumbprint(key.publicJwk);
    let saved = false;
    try { saved = await secrets.save(account, key.privateJwk.d) && await secrets.load(account) === key.privateJwk.d; } catch { saved = false; }
    if (saved) {
      const store = { backend: secrets.backend, account };
      return { file: keyFile(key, now, store), keyProtection: KEYCHAIN_PROTECTION, store };
    }
    await secrets.remove(account).catch(() => {});
    if (mode === 'os') throw new UsageError(`Could not keep the key in ${secrets.name}. Unlock it, or use --key-store file.`);
  } else if (mode === 'os') {
    throw new UsageError('This system has no OS secret store dba can use (macOS Keychain, secret-tool on Linux, or DPAPI on Windows). Use --key-store file.');
  }
  return { file: keyFile(key, now), keyProtection: KEY_PROTECTION, store: null };
}

/** Remove a key.json's private part from the OS secret store, if it is there. Never throws. */
export async function forgetDeviceKey(file, { secrets } = {}) {
  if (!file?.key_store || !secrets || secrets.backend !== file.key_store) return;
  await secrets.remove(file.key_store_account).catch(() => {});
}

/** Sign an enrollment request with the device's new key; the server checks it against header.jwk. */
export function signEnrollmentRequest(key, payload) {
  return signJws({ typ: ENROLL_TYP, jwk: key.publicJwk }, payload, key.privateKey);
}

/** Proof that the caller holds the NEW key during rotation (signed by it, naming the credential). */
export function rotationProof(newKey, cid, now = Math.floor(Date.now() / 1000)) {
  return signJws({ typ: ROTATE_TYP, jwk: newKey.publicJwk }, { cid, iat: now }, newKey.privateKey);
}

/** Authorization and DPoP header values for one request. The proof is single use. */
export async function deviceHeaders({ key, credential, method, url }) {
  return { Authorization: `DBA ${credential}`, DPoP: await createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method, url, credential }) };
}

/** Does the credential belong to this key? Catches pairing a credential with the wrong profile. */
export async function credentialMatchesKey(credential, key) {
  return inspectCredential(credential).payload.cnf?.jkt === await jwkThumbprint(key.publicJwk);
}

// curl options whose value is the next argument, so it is never mistaken for the URL.
const CURL_VALUE_OPTIONS = new Set(['-X', '--request', '-H', '--header', '-d', '--data', '--data-raw', '--data-binary', '--data-ascii', '--data-urlencode', '--json',
  '-F', '--form', '--form-string', '-o', '--output', '-u', '--user', '-A', '--user-agent', '-e', '--referer', '-b', '--cookie', '-c', '--cookie-jar', '-T', '--upload-file',
  '-w', '--write-out', '-x', '--proxy', '-m', '--max-time', '--connect-timeout', '-r', '--range', '-E', '--cert', '--key', '--cacert', '--resolve', '--retry', '-K', '--config', '--url']);
const CURL_SHORT_WITH_VALUE = new Set(['X', 'H', 'd', 'F', 'o', 'u', 'A', 'e', 'b', 'c', 'T', 'w', 'x', 'm', 'r', 'E', 'K']);

/**
 * Work out the method and URL a curl command line will use, which the DPoP proof must name.
 * Method: -X/--request; else HEAD for -I, PUT for -T, POST for -d/--data*, --json or -F, unless
 * -G sends the data as a query; else GET. URL: --url, or the first http(s):// argument.
 */
export function curlRequest(args) {
  let method; let url; let data = false; let get = false; let head = false; let upload = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    let name = arg; let value;
    if (arg.startsWith('--') && arg.includes('=')) { name = arg.slice(0, arg.indexOf('=')); value = arg.slice(arg.indexOf('=') + 1); }
    else if (/^-[A-Za-z]./.test(arg) && CURL_SHORT_WITH_VALUE.has(arg[1])) { name = arg.slice(0, 2); value = arg.slice(2); }
    else if (CURL_VALUE_OPTIONS.has(arg)) { value = args[++i]; }
    if (name === '-X' || name === '--request') method = value;
    else if (name === '--url') url ??= value;
    else if (name === '-d' || name.startsWith('--data') || name === '--json' || name === '-F' || name.startsWith('--form')) data = true;
    else if (name === '-T' || name === '--upload-file') upload = true;
    else if (name === '-G' || name === '--get') get = true;
    else if (name === '-I' || name === '--head') head = true;
    else if (value === undefined && !arg.startsWith('-') && /^https?:\/\//i.test(arg)) url ??= arg;
  }
  if (!url) throw new UsageError('dba curl needs an http(s):// URL');
  method ||= head ? 'HEAD' : upload ? 'PUT' : data && !get ? 'POST' : 'GET';
  return { method: method.toUpperCase(), url };
}

/** curl arguments with the credential headers added in front of the caller's own. */
export function curlArgs(args, headers) {
  return [...Object.entries(headers).flatMap(([name, value]) => ['-H', `${name}: ${value}`]), ...args];
}

/**
 * A small client for the devicebasedauth.org API. `device` ({ key, credential }) authenticates a
 * request with the credential and a fresh DPoP proof for that exact method and URL.
 * Failures throw ApiError with the server's { error, code }.
 */
export function createClient({ origin, fetch = (...args) => globalThis.fetch(...args) }) {
  async function request(method, path, { body, device, apiKey } = {}) {
    const url = new URL(path, origin).toString();
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (apiKey) headers.Authorization = `ApiKey ${apiKey}`;
    else if (device) Object.assign(headers, await deviceHeaders({ ...device, method, url }));
    let response;
    try { response = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }); }
    catch (error) { throw new ApiError(`Could not reach ${new URL(url).origin}: ${error.cause?.message || error.message}`, 'network_error'); }
    const text = await response.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON; reported below */ }
    if (!response.ok) throw new ApiError(json?.error || `HTTP ${response.status}`, json?.code || 'http_error', response.status, json);
    if (json === null) throw new ApiError(`Expected JSON from ${url}`, 'invalid_response', response.status);
    return json;
  }
  return { origin, request };
}

/**
 * Poll an enrollment until it is decided, at the interval the server asks for. Network errors
 * are retried until the deadline (a laptop may change networks during a 15-minute wait); error
 * responses are not. Returns the last poll body, or { status: 'timeout' }.
 */
export async function pollEnrollment(client, start, { waitSeconds = 900, sleep = ms => new Promise(r => setTimeout(r, ms)), clock = () => Date.now() } = {}) {
  const deadline = clock() + waitSeconds * 1000;
  let interval = start.interval || 3;
  while (clock() < deadline) {
    await sleep(Math.min(interval * 1000, Math.max(0, deadline - clock())));
    try {
      const result = await client.request('GET', start.poll_url);
      if (result.status !== 'pending') return result;
      interval = result.interval || interval;
    } catch (error) {
      if (error.code !== 'network_error') throw error;
    }
  }
  return { status: 'timeout' };
}

/** "in 3 days", "2 hours ago": enough precision to decide whether to renew. */
export function relativeTime(seconds, now = Math.floor(Date.now() / 1000)) {
  const delta = seconds - now; const abs = Math.abs(delta);
  const [n, unit] = abs >= 86400 * 2 ? [Math.round(abs / 86400), 'day'] : abs >= 7200 ? [Math.round(abs / 3600), 'hour'] : abs >= 120 ? [Math.round(abs / 60), 'minute'] : [abs, 'second'];
  const text = `${n} ${unit}${n === 1 ? '' : 's'}`;
  return delta >= 0 ? `in ${text}` : `${text} ago`;
}

const iso = seconds => new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');

/**
 * A plain-English summary of a decoded credential (or access token) payload: who, what, until
 * when. Decoding proves nothing; callers say so when the signature has not been checked.
 */
export function describeCredential(payload, now = Math.floor(Date.now() / 1000)) {
  const lines = [];
  const device = payload.device ? `"${payload.device.name}" (${payload.device.kind}, key: ${payload.device.key_protection})` : '';
  // Access tokens carry the credential's cid but their own jti, and no key binding.
  const version = typeof payload.jti === 'string' && payload.jti.startsWith(`${payload.cid}.`) ? ` (version ${payload.jti.slice(payload.cid.length + 1)})` : '';
  lines.push(payload.cnf ? `Credential ${payload.cid ?? '?'}${version}` : `Access token for credential ${payload.cid ?? '?'} (bearer: anyone holding it can use it)`);
  lines.push(`Device:    ${payload.sub ?? '?'} ${device}`.trimEnd());
  lines.push(`Account:   ${payload.acct ?? '?'}`);
  lines.push(`Sites:     ${Array.isArray(payload.aud) ? payload.aud.join(', ') : '?'}`);
  if (Number.isSafeInteger(payload.exp)) lines.push(`${payload.exp > now ? 'Expires' : 'Expired'}:   ${iso(payload.exp)} (${relativeTime(payload.exp, now)})`);
  lines.push('Grants:');
  const grants = Array.isArray(payload.grants) ? payload.grants : [];
  grants.forEach((grant, i) => lines.push(`  ${i + 1}. ${describeGrant(grant)}`));
  if (!grants.length) lines.push('  (none)');
  return lines;
}

export const CREDENTIAL_STATES = ['active', 'expired', 'revoked'];

/** The query string for GET /api/v1/credentials from `dba list` options. */
export function listQuery({ status, audience, device, cursor } = {}) {
  if (status !== undefined && !CREDENTIAL_STATES.includes(status)) throw new UsageError(`--status must be one of ${CREDENTIAL_STATES.join(', ')}`);
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries({ status, audience, device, cursor })) if (value !== undefined) params.set(name, value);
  const query = params.toString();
  return `/api/v1/credentials${query ? `?${query}` : ''}`;
}

/**
 * One line per credential for `dba list`: id, state, device name, sites and expiry. Device names
 * are the owner's text; control characters are dropped so a name cannot rewrite the terminal.
 */
export function formatCredentialList(items, now = Math.floor(Date.now() / 1000)) {
  if (!items.length) return ['No credentials.'];
  const clean = text => String(text ?? '').replace(/[\p{Cc}\p{Cf}]/gu, '');
  const rows = items.map(c => [clean(c.cid), clean(c.state), clean(c.device?.name || c.device_id), (c.aud || []).map(clean).join(','), Number.isSafeInteger(c.exp) ? `${c.exp > now ? 'expires' : 'expired'} ${relativeTime(c.exp, now)}` : '']);
  const header = ['CREDENTIAL', 'STATE', 'DEVICE', 'SITES', 'EXPIRY'];
  const widths = header.map((h, i) => Math.min(40, Math.max(h.length, ...rows.map(r => r[i].length))));
  const fit = (text, width) => (text.length > width ? `${text.slice(0, width - 1)}…` : text).padEnd(width);
  return [header, ...rows].map(row => row.map((cell, i) => (i === row.length - 1 ? cell : fit(cell, widths[i]))).join('  ').trimEnd());
}

/** True once two thirds of the lifetime has passed: the point the plan says devices renew. */
export function shouldRenew(payload, now = Math.floor(Date.now() / 1000)) {
  return Number.isSafeInteger(payload.iat) && Number.isSafeInteger(payload.exp) && now >= payload.iat + ((payload.exp - payload.iat) * 2) / 3;
}

export const JWKS_CACHE_SECONDS = 3600;

/**
 * True when the issuer no longer publishes the key that signed this credential: after an issuer key
 * is withdrawn (compromised), relying parties refuse the credential, and the device must renew it
 * (free) to get one signed by the current key. The JWKS is fetched at most once an hour through
 * `cache` ({ read(): {fetched_at, kids} | null, write(entry) }), and again early when the cached copy
 * lacks the kid. Any failure to fetch answers false: never renew on a guess.
 */
export async function issuerKeyWithdrawn({ client, credential, cache, now = Math.floor(Date.now() / 1000) }) {
  const { header } = inspectCredential(credential);
  const cached = await cache.read().catch(() => null);
  if (cached && Array.isArray(cached.kids) && now - cached.fetched_at < JWKS_CACHE_SECONDS && cached.kids.includes(header.kid)) return false;
  let kids;
  try { kids = (await client.request('GET', '/.well-known/jwks.json')).keys.map(k => k.kid); } catch { return false; }
  if (!kids.length) return false;
  await cache.write({ fetched_at: now, kids }).catch(() => {});
  return !kids.includes(header.kid);
}

/**
 * Whether commands that present the credential renew it first when it is due. On by default (the
 * browser SDK does the same); `--no-renew` or DBA_AUTO_RENEW=0 turns it off, for example on a
 * machine whose account owner wants every renewal (25 µ$) to be deliberate.
 */
export function autoRenewEnabled({ flag, env = {} } = {}) {
  if (flag) return false;
  return !['0', 'false', 'no', 'off'].includes(String(env.DBA_AUTO_RENEW ?? '').trim().toLowerCase());
}

/**
 * Renew the device's credential if two thirds of its lifetime have passed and it has not expired.
 * Returns { renewed: false, reason } or { renewed: true, result } after `save(result)` stored the
 * new credential. A failure never stops the caller from using the still-valid credential: it comes
 * back as { renewed: false, reason: 'failed', error } for the caller to warn about. `superseded`
 * means another process renewed first; the caller should re-read its credential file.
 */
export async function renewIfDue({ client, device, save, withdrawn = false, now = Math.floor(Date.now() / 1000) }) {
  const { payload } = inspectCredential(device.credential);
  if (!Number.isSafeInteger(payload.exp) || payload.exp <= now) return { renewed: false, reason: 'expired' };
  if (!withdrawn && !shouldRenew(payload, now)) return { renewed: false, reason: 'not_due' };
  let result;
  try {
    result = await client.request('POST', `/api/v1/credentials/${encodeURIComponent(payload.cid)}/renew`, { device, body: {} });
  } catch (error) {
    if (error.code === 'superseded') return { renewed: false, reason: 'superseded' };
    return { renewed: false, reason: 'failed', error };
  }
  await save(result);
  return { renewed: true, result };
}
