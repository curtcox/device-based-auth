/**
 * Device keys inside a TPM 2.0, for `dba enroll --key-store tpm` (master plan §5.1: "OS keychain /
 * TPM where available"). The P-256 key is generated in the TPM and cannot leave it (fixedTPM,
 * fixedParent, sensitiveDataOrigin), so every signature, the enrollment request's and each DPoP
 * proof's, is made by the TPM. key.json keeps the key's public area and its private area, which
 * the TPM encrypted under its storage root key (SRK): useless anywhere but on this TPM.
 *
 * Talks to the TPM through tpm2-tools 5 (the same calls as docs/samples/tpm/enroll-tpm.sh), which
 * honour TPM2TOOLS_TCTI and otherwise use /dev/tpmrm0. The SRK is not persisted (that would need
 * owner authorization and change the TPM): it is re-created from the fixed TCG template below on
 * each use, which yields the same key every time on the same TPM.
 *
 * I/O is injected as `open()`, resolving to a session in a fresh private directory:
 *   { run(tool, args) → { code, stderr }, write(name, bytes), read(name) → bytes | null, close() }
 * so this file has no Node imports and is tested with a fake and against a software TPM.
 */
import { b64u, unb64u } from '@devicebasedauth/verify';

export const TPM_BACKEND = 'tpm';
export const TPM_PROTECTION = 'tpm';
export const TPM_NAME = 'the TPM (tpm2-tools)';
/** Names the parent template in key.json, so a later version can tell which SRK a blob needs. */
export const TPM_PARENT = 'srk-ecc-p256';
// TCG "Provisioning Guidance" ECC SRK template: P-256, AES-128-CFB, restricted decryption key.
const SRK_ARGS = ['-C', 'o', '-g', 'sha256', '-G', 'ecc256:null:aes128cfb', '-a', 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda', '-c', 'srk.ctx'];
const KEY_ATTRIBUTES = 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign';
const EK_CERT_NV_INDEX = '0x01c00002'; // the RSA-2048 EK certificate (TCG EK Credential Profile)
const ALG_ECC = 0x0023; const ALG_NULL = 0x0010; const ALG_ECDSA = 0x0018; const CURVE_P256 = 0x0003;

export class TpmError extends Error {
  constructor(message) { super(message); this.name = 'TpmError'; }
}

/** Run one tpm2-tools command; throws TpmError with the tool's own message on failure. */
async function tool(session, name, args) {
  const result = await session.run(name, args);
  if (result.code === 0) return result;
  const detail = (result.stderr || '').trim().split('\n').filter(Boolean).slice(-2).join(' ');
  throw new TpmError(result.code === null ? `${name} could not run (is tpm2-tools installed?)` : `${name} failed${detail ? `: ${detail}` : ` (exit ${result.code})`}`);
}

/**
 * Without a resource manager (a swtpm socket, /dev/tpm0) the TPM keeps every object loaded until
 * flushed, and has room for only a few; the kernel's /dev/tpmrm0 flushes them anyway.
 */
async function step(session, name, args) {
  const result = await tool(session, name, args);
  await session.run('tpm2_flushcontext', ['-t']);
  return result;
}

async function withSession(open, work) {
  const session = await open();
  try { return await work(session); } finally { await session.close(); }
}

/** Is there a TPM that tpm2-tools can reach? */
export async function tpmAvailable(open) {
  try { return await withSession(open, async session => (await session.run('tpm2_getcap', ['properties-fixed'])).code === 0); } catch { return false; }
}

/** Read a TPM2B_PUBLIC (or a bare TPMT_PUBLIC) holding a P-256 key: its attributes and point. */
export function parseTpmPublic(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = 0;
  const need = n => { if (at + n > bytes.length) throw new TpmError('truncated TPM public area'); };
  const u16 = () => { need(2); const v = view.getUint16(at); at += 2; return v; };
  const u32 = () => { need(4); const v = view.getUint32(at); at += 4; return v; };
  const sized = () => { const n = u16(); need(n); const v = bytes.subarray(at, at + n); at += n; return v; };
  if (bytes.length >= 2 && view.getUint16(0) === bytes.length - 2) at = 2; // TPM2B size prefix
  if (u16() !== ALG_ECC) throw new TpmError('the TPM key is not an ECC key');
  u16(); // nameAlg
  const attributes = u32();
  sized(); // authPolicy
  if (u16() !== ALG_NULL) { u16(); u16(); } // symmetric: keyBits, mode
  const scheme = u16(); if (scheme !== ALG_NULL) u16();
  const curve = u16();
  if (u16() !== ALG_NULL) u16(); // kdf
  const x = sized(); const y = sized();
  if (curve !== CURVE_P256 || x.length > 32 || y.length > 32) throw new TpmError('the TPM key is not a P-256 key');
  return { attributes, scheme, x: pad32(x), y: pad32(y) };
}

function pad32(bytes) {
  if (bytes.length === 32) return bytes;
  if (bytes.length > 32) { if (bytes.subarray(0, bytes.length - 32).some(b => b)) throw new TpmError('integer longer than 32 bytes'); return bytes.subarray(bytes.length - 32); }
  const out = new Uint8Array(32); out.set(bytes, 32 - bytes.length); return out;
}

/** The public JWK of a TPM key's public area. */
export function tpmPublicJwk(publicBytes) {
  const { x, y } = parseTpmPublic(publicBytes);
  return { kty: 'EC', crv: 'P-256', x: b64u(x), y: b64u(y) };
}

/** A TPMT_SIGNATURE (ECDSA) as JOSE's 64-byte r ‖ s. */
export function parseTpmSignature(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 8 || view.getUint16(0) !== ALG_ECDSA) throw new TpmError('the TPM did not return an ECDSA signature');
  let at = 4; // sigAlg, hashAlg
  const part = () => { const n = view.getUint16(at); at += 2; if (at + n > bytes.length) throw new TpmError('truncated TPM signature'); const v = bytes.subarray(at, at + n); at += n; return pad32(v); };
  const r = part(); const s = part();
  const out = new Uint8Array(64); out.set(r); out.set(s, 32); return out;
}

/** Load the device key under a fresh SRK in this session, as key.ctx. */
async function loadKey(session, blobs) {
  await session.write('key.pub', unb64u(blobs.public));
  await session.write('key.priv', unb64u(blobs.private));
  await step(session, 'tpm2_createprimary', SRK_ARGS);
  await step(session, 'tpm2_load', ['-C', 'srk.ctx', '-u', 'key.pub', '-r', 'key.priv', '-c', 'key.ctx']);
}

/**
 * Generate a P-256 signing key in the TPM. Returns { publicJwk, blobs: { public, private } }
 * (base64url TPM2B_PUBLIC and TPM2B_PRIVATE, for key.json).
 */
export async function createTpmKey(open) {
  return withSession(open, async session => {
    await step(session, 'tpm2_createprimary', SRK_ARGS);
    await step(session, 'tpm2_create', ['-C', 'srk.ctx', '-G', 'ecc256:ecdsa-sha256', '-a', KEY_ATTRIBUTES, '-u', 'key.pub', '-r', 'key.priv']);
    const pub = await session.read('key.pub'); const priv = await session.read('key.priv');
    if (!pub || !priv) throw new TpmError('tpm2_create wrote no key');
    return { publicJwk: tpmPublicJwk(pub), blobs: { public: b64u(pub), private: b64u(priv) } };
  });
}

/**
 * A signer for signJws ({ sign(bytes) }): SHA-256 here, the signature by the TPM. The digest is
 * signed directly (tpm2_sign -d), which an unrestricted key allows, so no TPM2_Hash size limit.
 */
export function tpmSigner(open, blobs) {
  return {
    async sign(bytes) {
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
      return withSession(open, async session => {
        await loadKey(session, blobs);
        await session.write('digest.bin', digest);
        await step(session, 'tpm2_sign', ['-c', 'key.ctx', '-g', 'sha256', '-s', 'ecdsa', '-d', '-o', 'sig.bin', 'digest.bin']);
        const signature = await session.read('sig.bin');
        if (!signature) throw new TpmError('tpm2_sign wrote no signature');
        return parseTpmSignature(signature);
      });
    }
  };
}

/**
 * Prove to the server that the key is in a genuine TPM, by EK credential activation
 * (spec/credential.md §3a, src/services/tpm-activation.js): an attestation key (AK) under the
 * endorsement key certifies the device key; the server checks the EK certificate against TPM
 * manufacturers' CAs and wraps a secret that only this TPM's EK can unwrap, for this AK.
 * `post(path, body)` calls the API. Returns the enrollment's `attestation` member.
 */
export async function tpmAttestation(open, blobs, { post }) {
  return withSession(open, async session => {
    await step(session, 'tpm2_createek', ['-c', 'ek.ctx', '-G', 'rsa', '-u', 'ek.pub']);
    await step(session, 'tpm2_createak', ['-C', 'ek.ctx', '-c', 'ak.ctx', '-G', 'ecc', '-g', 'sha256', '-s', 'ecdsa', '-u', 'ak.pub', '-n', 'ak.name']);
    await loadKey(session, blobs);
    await step(session, 'tpm2_certify', ['-c', 'key.ctx', '-C', 'ak.ctx', '-g', 'sha256', '-o', 'certify.bin', '-s', 'certify.sig']);
    const nv = await session.run('tpm2_nvread', [EK_CERT_NV_INDEX, '-o', 'ek.crt']);
    const ekCertificate = nv.code === 0 ? await session.read('ek.crt') : null;
    if (!ekCertificate?.length) throw new TpmError('this TPM has no RSA EK certificate (NV index 0x01c00002) to prove it is genuine');
    const b64 = async name => { const bytes = await session.read(name); if (!bytes) throw new TpmError(`tpm2-tools wrote no ${name}`); return b64Bytes(bytes); };
    const { challenge } = await post('/api/v1/enrollments/attestation-challenge', {});
    const activation = await post('/api/v1/enrollments/tpm-activation', {
      challenge, ek_certificate: b64Bytes(ekCertificate), ak_pub_area: await b64('ak.pub'), pub_area: await b64('key.pub'), cert_info: await b64('certify.bin'), sig: await b64('certify.sig')
    });
    await session.write('credential.blob', Uint8Array.from(atob(activation.credential_blob), c => c.charCodeAt(0)));
    await tool(session, 'tpm2_startauthsession', ['--policy-session', '-S', 'session.ctx']);
    try {
      await tool(session, 'tpm2_policysecret', ['-S', 'session.ctx', '-c', 'e']); // the EK's policy: endorsement authorization
      await tool(session, 'tpm2_activatecredential', ['-c', 'ak.ctx', '-C', 'ek.ctx', '-i', 'credential.blob', '-o', 'secret.bin', '-P', 'session:session.ctx']);
    } finally {
      await session.run('tpm2_flushcontext', ['session.ctx']);
      await session.run('tpm2_flushcontext', ['-t']);
    }
    return { format: 'tpm-ek', challenge, activation: activation.activation, secret: await b64('secret.bin') };
  });
}

function b64Bytes(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}
