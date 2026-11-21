/**
 * The device key: making it, keeping it (OS secret store, a 0600 file, or the TPM) and loading
 * it back, plus the per-request headers it signs. The private key never leaves this machine.
 */
import { generateKeyPair, exportPublicJwk, importJwk, publicJwk, jwkThumbprint, createProof, inspectCredential, unb64u } from '@devicebasedauth/verify';
import { UsageError } from './errors.js';
import { TPM_BACKEND, TPM_PROTECTION, TPM_NAME, TPM_PARENT, tpmPublicJwk, tpmSigner } from './tpm.js';

/** Keys in a 0600 file say so in the credential; approvers see it. */
export const KEY_PROTECTION = 'software';
/** Keys whose private part is in the OS secret store (macOS Keychain, Secret Service). */
export const KEYCHAIN_PROTECTION = 'os-keychain';

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
export async function loadDeviceKey(file, { secrets, tpm } = {}) {
  if (file?.key_store === TPM_BACKEND) return loadTpmKey(file, tpm);
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

/**
 * The contents of key.json for a key made in the TPM by createTpmKey: the public key and the
 * TPM's blobs (the private one is encrypted by the TPM, so the file is no secret).
 */
export function tpmKeyFile(key, now = new Date()) {
  return { public_jwk: key.publicJwk, key_protection: TPM_PROTECTION, key_store: TPM_BACKEND, tpm_parent: TPM_PARENT, tpm_public: key.blobs.public, tpm_private: key.blobs.private, created_at: now.toISOString() };
}

/** A key.json naming a TPM key: a signer that asks the TPM, after checking the blobs belong to public_jwk. */
function loadTpmKey(file, tpm) {
  if (!tpm) throw new UsageError('key.json says the private key is in a TPM, which this system cannot reach (it needs tpm2-tools).');
  if (file.tpm_parent !== TPM_PARENT || typeof file.tpm_public !== 'string' || typeof file.tpm_private !== 'string') throw new UsageError('key.json names a TPM key this version of dba cannot load.');
  let jwk;
  try { jwk = tpmPublicJwk(unb64u(file.tpm_public)); } catch { throw new UsageError('key.json\'s TPM public area is unreadable.'); }
  if (jwk.x !== file.public_jwk?.x || jwk.y !== file.public_jwk?.y) throw new UsageError('key.json\'s TPM key does not match its public_jwk.');
  const blobs = { public: file.tpm_public, private: file.tpm_private };
  return { privateKey: tpmSigner(tpm.open, blobs), publicJwk: publicJwk(jwk), privateJwk: null, tpm: blobs };
}

/** Does the private key sign for the public key? (not every runtime checks that x, y match d on import) */
async function keyPairMatches(key) {
  const data = crypto.getRandomValues(new Uint8Array(32));
  const algorithm = { name: 'ECDSA', hash: 'SHA-256' };
  const signature = await crypto.subtle.sign(algorithm, key.privateKey, data);
  return crypto.subtle.verify(algorithm, await importJwk(key.publicJwk, 'verify'), signature, data);
}

// ---- OS secret store ----------------------------------------------------------------------

/** Where `dba enroll` keeps the private key: `auto` (the OS secret store when it works, else a file), `os` (fail without one), `file`, or `tpm` (made in the TPM; see tpm.js). */
export const KEY_STORES = ['auto', 'os', 'file', 'tpm'];
export const SECRET_SERVICE = 'org.devicebasedauth.dba';
const STORE_NAMES = { 'macos-keychain': 'the macOS Keychain', 'secret-service': 'the Secret Service keyring (secret-tool)', 'windows-dpapi': 'Windows DPAPI (your Windows account)', [TPM_BACKEND]: TPM_NAME };

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

/** Authorization and DPoP header values for one request. The proof is single use. */
export async function deviceHeaders({ key, credential, method, url }) {
  return { Authorization: `DBA ${credential}`, DPoP: await createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method, url, credential }) };
}

/** Does the credential belong to this key? Catches pairing a credential with the wrong profile. */
export async function credentialMatchesKey(credential, key) {
  return inspectCredential(credential).payload.cnf?.jkt === await jwkThumbprint(key.publicJwk);
}
