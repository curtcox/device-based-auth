/**
 * Device keys inside the TPM on Windows, for `dba enroll --key-store tpm` there (STATUS S13).
 * Windows has no tpm2-tools; it reaches the TPM through CNG's Microsoft Platform Crypto Provider
 * (PCP), which makes a P-256 key inside the TPM and keeps it, TPM-wrapped, under the signed-in
 * user's profile. The private key cannot be exported (export policy none), so every signature,
 * the enrollment request's and each DPoP proof's, is made by the TPM.
 *
 * Talks to CNG through Windows PowerShell 5.1 and the .NET Framework's CngKey and ECDsaCng
 * classes, present on every supported Windows: nothing to install, nothing compiled. Like the
 * DPAPI store (device-key.js) the script goes in -EncodedCommand and the data on stdin.
 * key.json keeps the public key and the key's name in the provider; the name alone is no secret
 * (only this user on this machine's TPM can use the key).
 *
 * `run(command, args, input)` runs a program without a shell and resolves to { code, stdout }.
 *
 * Not done yet: attestation. Windows can prove a PCP key is in its TPM (NCryptCreateClaim with an
 * AIK that Microsoft certified), but no client code makes that claim, so these keys enroll
 * unattested and grants that require hardware attestation deny them.
 */
import { b64u, unb64u } from '@devicebasedauth/verify';
import { powershellEncoded } from './powershell.js';

export const WINDOWS_TPM_BACKEND = 'windows-tpm';
export const WINDOWS_TPM_NAME = 'the TPM (Windows Platform Crypto Provider)';
export const PCP_PROVIDER = 'Microsoft Platform Crypto Provider';
const KEY_NAME = /^dba-[0-9a-f]{32}$/;
const ECS1_MAGIC = 0x31534345; // BCRYPT_ECDSA_PUBLIC_P256_MAGIC, "ECS1"

export class WindowsTpmError extends Error {
  constructor(message) { super(message); this.name = 'WindowsTpmError'; }
}

/** A new key's name in the provider: random, so it is known before the key is. */
export function newKeyName() {
  return `dba-${[...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, '0')).join('')}`;
}

function checkName(name) {
  if (!KEY_NAME.test(name ?? '')) throw new WindowsTpmError('a Windows TPM key name must look like dba-<32 hex digits>');
}

/**
 * The PowerShell script for one operation on key `name`:
 *   create  makes the key; writes base64 of its public BCRYPT_ECCKEY_BLOB
 *   sign    reads base64 data on stdin; writes base64 of its public blob, a dot, and base64 of the
 *           ECDSA P-256 SHA-256 signature (IEEE P1363 r ‖ s, as JOSE wants)
 *   delete  removes the key (no output)
 * A failure writes "error:" and the exception's message, and exits 1. The name is checked
 * before it goes into the script, so it needs no quoting beyond the single quotes.
 */
export function pcpScript(mode, name) {
  checkName(name);
  const open = `$k=[Security.Cryptography.CngKey]::Open('${name}',$p)`;
  const publicBlob = '[Convert]::ToBase64String($k.Export([Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob))';
  const body = {
    create: [
      '$c=New-Object Security.Cryptography.CngKeyCreationParameters',
      '$c.Provider=$p',
      '$c.KeyUsage=[Security.Cryptography.CngKeyUsages]::Signing',
      '$c.ExportPolicy=[Security.Cryptography.CngExportPolicies]::None',
      `$k=[Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::ECDsaP256,'${name}',$c)`,
      `[Console]::Out.Write(${publicBlob})`
    ],
    sign: [
      '$d=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())',
      open,
      '$e=New-Object Security.Cryptography.ECDsaCng($k)',
      '$e.HashAlgorithm=[Security.Cryptography.CngAlgorithm]::Sha256',
      `[Console]::Out.Write(${publicBlob}+'.'+[Convert]::ToBase64String($e.SignData($d)))`
    ],
    delete: [open, '$k.Delete()']
  }[mode];
  if (!body) throw new WindowsTpmError(`unknown PCP operation ${mode}`);
  return [
    "$ErrorActionPreference='Stop'",
    'Add-Type -AssemblyName System.Core',
    `try{$p=New-Object Security.Cryptography.CngProvider('${PCP_PROVIDER}');${body.join(';')}}catch{[Console]::Out.Write('error:'+$_.Exception.Message);exit 1}`
  ].join(';');
}

/** The public JWK of a BCRYPT_ECCPUBLIC_BLOB holding a P-256 key (magic, length, X, Y; little-endian header). */
export function eccPublicBlobJwk(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length !== 72 || view.getUint32(0, true) !== ECS1_MAGIC || view.getUint32(4, true) !== 32) throw new WindowsTpmError('the TPM key is not a P-256 ECDSA key');
  return { kty: 'EC', crv: 'P-256', x: b64u(bytes.subarray(8, 40)), y: b64u(bytes.subarray(40, 72)) };
}

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

/**
 * The Windows TPM for a profile: { backend, name, create(), signer(name, publicJwk), remove(name) }.
 */
export function windowsTpm({ run }) {
  const powershell = async (mode, name, input = '') => {
    const result = await run('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', powershellEncoded(pcpScript(mode, name))], input);
    const output = (result.stdout || '').trim();
    if (result.code === 0) return output;
    if (result.code === null) throw new WindowsTpmError('Windows PowerShell could not run (powershell.exe)');
    throw new WindowsTpmError(output.startsWith('error:') ? `the Platform Crypto Provider refused: ${output.slice(6).trim()}` : `powershell.exe failed (exit ${result.code})`);
  };
  return {
    backend: WINDOWS_TPM_BACKEND,
    name: WINDOWS_TPM_NAME,
    /** Make a key in the TPM. Returns { publicJwk, keyName }. */
    async create() {
      const keyName = newKeyName();
      const output = await powershell('create', keyName);
      if (!BASE64.test(output)) throw new WindowsTpmError('the Platform Crypto Provider returned no public key');
      return { publicJwk: eccPublicBlobJwk(fromBase64(output)), keyName };
    },
    /**
     * A signer for signJws ({ sign(bytes) }). Each signature also returns the key's public part,
     * checked against key.json's, so a key replaced under the same name is caught here and not as
     * a server-side refusal.
     */
    signer(keyName, publicJwk) {
      checkName(keyName);
      return {
        async sign(bytes) {
          const output = await powershell('sign', keyName, toBase64(bytes));
          const [blob, signature] = output.split('.');
          if (!BASE64.test(blob ?? '') || !BASE64.test(signature ?? '')) throw new WindowsTpmError('the Platform Crypto Provider returned no signature');
          const jwk = eccPublicBlobJwk(fromBase64(blob));
          if (jwk.x !== publicJwk.x || jwk.y !== publicJwk.y) throw new WindowsTpmError(`the TPM key ${keyName} does not match key.json's public key`);
          const raw = fromBase64(signature);
          if (raw.length !== 64) throw new WindowsTpmError('the Platform Crypto Provider returned a signature that is not P-256 r ‖ s');
          return raw;
        }
      };
    },
    /** Delete the key from the provider. Never throws (it may already be gone). */
    async remove(keyName) {
      try { checkName(keyName); await powershell('delete', keyName); } catch { /* already gone, or never made */ }
    }
  };
}

// For tests: the blob a real provider exports for a public JWK.
export function eccPublicBlob(jwk) {
  const out = new Uint8Array(72);
  const view = new DataView(out.buffer);
  view.setUint32(0, ECS1_MAGIC, true); view.setUint32(4, 32, true);
  out.set(unb64u(jwk.x), 8); out.set(unb64u(jwk.y), 40);
  return out;
}
