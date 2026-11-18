// A software stand-in for a TPM without a Microsoft-certified attestation key, for testing EK
// credential activation (src/services/tpm-activation.js) without one: an RSA-2048 EK with a
// certificate from a test EK CA, a restricted P-256 attestation key that "certifies" the device
// key, and TPM2_ActivateCredential in software. Interoperability with a real TPM is pinned by the
// swtpm recording in src/services/testdata/tpm-ek-swtpm.json.
import { seq, set, oid, utf8, bool, concat, tlv } from '../src/services/der.js';
import { certificate, ext, spkiOf } from './android-attestation.js';
import { eccPubArea, certInfoFor } from './tpm-attestation.js';
import { kdfa } from '../src/services/tpm-activation.js';

const b64 = bytes => btoa(String.fromCharCode(...bytes));
const fromB64 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const u16 = n => Uint8Array.of(n >> 8, n & 255);
const sized = bytes => concat(u16(bytes.length), bytes);
const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const rsaSign = { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' };
// fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | sign
export const AK_ATTRIBUTES = 0x00050072;

/** A test EK CA. `der` (base64) goes in TPM_EK_TEST_CA. */
export async function ekAuthority({ name = 'Test TPM EK CA' } = {}) {
  const key = await crypto.subtle.generateKey(rsaSign, true, ['sign', 'verify']);
  const der = await certificate({ serial: Uint8Array.of(0x41), issuer: name, subject: name, spki: await spkiOf(key.publicKey), signer: { kind: 'rsa', privateKey: key.privateKey }, notBefore: Date.UTC(2025, 0, 1), notAfter: Date.UTC(2045, 0, 1), extensions: [ext('2.5.29.19', seq(bool(true)), true)] });
  return { name, der, derB64: b64(der), signer: { kind: 'rsa', privateKey: key.privateKey } };
}

/** A TPM: an RSA-2048 EK (with a certificate from `authority`) and a restricted ECC attestation key. */
export async function softwareTpm(authority, { manufacturer = 'id:49465800', ekBits = 2048, issuer = authority.name } = {}) {
  const ek = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: ekBits, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
  const tcg = (id, value) => set(seq(oid(id), utf8(value)));
  const san = manufacturer === null ? [] : [ext('2.5.29.17', seq(tlv(0xa4, seq(tcg('2.23.133.2.1', manufacturer), tcg('2.23.133.2.2', 'SLB9670'), tcg('2.23.133.2.3', 'id:00070055')))), true)];
  const ekCert = await certificate({ serial: Uint8Array.of(0x51, 0x02), issuer, subject: 'EK', spki: await spkiOf(ek.publicKey), signer: authority.signer, notBefore: Date.UTC(2025, 0, 1), notAfter: Date.UTC(9999, 11, 31), extensions: [ext('2.5.29.19', seq(), true), ...san] });
  const ak = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const akJwk = await crypto.subtle.exportKey('jwk', ak.publicKey);
  return { ek, ekCert, ak, akJwk };
}

/**
 * The tpm-activation request for a device key (public JWK) the TPM holds. Overrides for negative
 * tests: akAttributes, keyAttributes, certifiedPubArea, tamper (flip a cert_info byte).
 */
export async function activationRequest(tpm, jwk, { akAttributes = AK_ATTRIBUTES, keyAttributes, certifiedPubArea, tamper = false } = {}) {
  const akPubArea = eccPubArea(fromB64(tpm.akJwk.x), fromB64(tpm.akJwk.y), { attributes: akAttributes });
  const pubArea = eccPubArea(fromB64(jwk.x), fromB64(jwk.y), keyAttributes === undefined ? {} : { attributes: keyAttributes });
  const certInfo = await certInfoFor(certifiedPubArea ?? pubArea, Uint8Array.of(0, 0xff, 0x55, 0xaa));
  const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, tpm.ak.privateKey, certInfo));
  const sig = concat(u16(0x0018), u16(0x000b), sized(raw.subarray(0, 32)), sized(raw.subarray(32)));
  if (tamper) certInfo[40] ^= 1;
  return { ek_certificate: b64(tpm.ekCert), ak_pub_area: b64(sized(akPubArea)), pub_area: b64(pubArea), cert_info: b64(certInfo), sig: b64(sig), akName: concat(u16(0x000b), await sha256(akPubArea)) };
}

/** TPM2_ActivateCredential in software: the secret, or an Error the TPM would also return. */
export async function activateCredential(tpm, { idObject, encryptedSecret }, akName) {
  const seed = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP', label: new TextEncoder().encode('IDENTITY\0') }, tpm.ek.privateKey, encryptedSecret));
  const hmacKey = await kdfa('SHA-256', seed, 'INTEGRITY', new Uint8Array(0), new Uint8Array(0), 256);
  const size = (idObject[0] << 8) | idObject[1];
  const outerHmac = idObject.subarray(2, 2 + size);
  const encIdentity = idObject.subarray(2 + size);
  const key = await crypto.subtle.importKey('raw', hmacKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  if (!await crypto.subtle.verify('HMAC', key, outerHmac, concat(encIdentity, akName))) throw new Error('integrity check failed (wrong object name)');
  const symKey = await kdfa('SHA-256', seed, 'STORAGE', akName, new Uint8Array(0), 128);
  const aes = await crypto.subtle.importKey('raw', symKey, 'AES-CBC', false, ['encrypt']);
  // CFB decryption: keystream block i is E(K, C_{i-1}), C_0 = 0.
  const plain = new Uint8Array(encIdentity.length);
  let previous = new Uint8Array(16);
  for (let offset = 0; offset < encIdentity.length; offset += 16) {
    const stream = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, aes, previous)).subarray(0, 16);
    const chunk = encIdentity.subarray(offset, offset + 16);
    plain.set(chunk.map((b, i) => b ^ stream[i]), offset);
    previous = new Uint8Array(16); previous.set(chunk);
  }
  const length = (plain[0] << 8) | plain[1];
  return plain.subarray(2, 2 + length);
}
