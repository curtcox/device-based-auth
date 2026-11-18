// Builds TPM 2.0 key attestations shaped like Windows' (Microsoft root → AIK CA → AIK certificate
// with the TCG profile), under a test root, so enrollment can be tested without a TPM: an RSA AIK
// "certifies" a P-256 key's TPMT_PUBLIC in a TPMS_ATTEST it signs with RS256.
// Real Windows attestations are tested in src/tpm-attestation.test.js.
import { seq, set, oid, utf8, bool, concat, tlv, integer, time, bits } from '../src/services/der.js';
import { certificate, ext, spkiOf } from './android-attestation.js';

const rsaParams = { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' };
const b64 = bytes => btoa(String.fromCharCode(...bytes));
const b64u = bytes => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const u16 = n => Uint8Array.of(n >> 8, n & 255);
const u32 = n => Uint8Array.of(n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255);
const sized = bytes => concat(u16(bytes.length), bytes);
const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const DEFAULT_ATTRIBUTES = 0x00040072; // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign

/** A test TPM root and AIK CA. `rootSpkiB64u` goes in TPM_ATTESTATION_TEST_ROOT. */
export async function tpmAuthority() {
  const root = await crypto.subtle.generateKey(rsaParams, true, ['sign', 'verify']);
  const inter = await crypto.subtle.generateKey(rsaParams, true, ['sign', 'verify']);
  const rootSpki = await spkiOf(root.publicKey);
  const interCert = await certificate({ serial: Uint8Array.of(0x21), issuer: 'Test TPM Root', subject: 'Test AIK CA', spki: await spkiOf(inter.publicKey), signer: { kind: 'rsa', privateKey: root.privateKey }, notBefore: Date.UTC(2025, 0, 1), notAfter: Date.UTC(2045, 0, 1), extensions: [ext('2.5.29.19', seq(bool(true)), true)] });
  return { rootSpki, rootSpkiB64u: b64u(rootSpki), rootKey: root.privateKey, interCert, interSerial: '21', interSigner: { kind: 'rsa', privateKey: inter.privateKey } };
}

/** TPMT_PUBLIC for a P-256 public key (raw x and y), with SHA-256 names. */
export function eccPubArea(x, y, { attributes = DEFAULT_ATTRIBUTES, curve = 0x0003 } = {}) {
  return concat(u16(0x0023), u16(0x000b), u32(attributes), sized(new Uint8Array(0)), u16(0x0010), u16(0x0010), u16(curve), u16(0x0010), sized(x), sized(y));
}

/** TPMS_ATTEST of TPM2_Certify for `pubArea`. */
export async function certInfoFor(pubArea, extraData) {
  const name = concat(u16(0x000b), await sha256(pubArea));
  return concat(u32(0xff544347), u16(0x8017), sized(concat(u16(0x000b), new Uint8Array(32))), sized(extraData), new Uint8Array(17), new Uint8Array(8), sized(name), sized(concat(u16(0x000b), new Uint8Array(32))));
}

/**
 * The attestation members a Windows device would send for `jwk` (P-256 public JWK) with
 * qualifying data `extraData`. Overrides for negative tests: attributes, curve, certifiedPubArea
 * (certInfo names another key), eku, ca, manufacturer (null for none), notAfter.
 */
export async function tpmAttestation(authority, jwk, extraData, { attributes, curve, certifiedPubArea, eku = '2.23.133.8.3', ca = false, manufacturer = 'id:4E544300', notAfter = Date.UTC(2045, 0, 1) } = {}) {
  const fromB64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const pubArea = eccPubArea(fromB64u(jwk.x), fromB64u(jwk.y), { attributes, curve });
  const certInfo = await certInfoFor(certifiedPubArea ?? pubArea, extraData);
  const aik = await crypto.subtle.generateKey(rsaParams, true, ['sign', 'verify']);
  const tcg = (id, value) => set(seq(oid(id), utf8(value)));
  const san = manufacturer === null ? [] : [ext('2.5.29.17', seq(tlv(0xa4, seq(tcg('2.23.133.2.1', manufacturer), tcg('2.23.133.2.2', 'NPCT75x'), tcg('2.23.133.2.3', 'id:00070002')))), true)];
  const aikCert = await certificate({ serial: Uint8Array.of(0x31, 0x07), issuer: 'Test AIK CA', subject: 'AIK', spki: await spkiOf(aik.publicKey), signer: authority.interSigner, notBefore: Date.UTC(2025, 0, 1), notAfter,
    extensions: [ext('2.5.29.19', seq(...(ca ? [bool(true)] : [])), true), ext('2.5.29.37', seq(oid(eku))), ...san] });
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', aik.privateKey, certInfo));
  return { alg: -257, x5c: [b64(aikCert), b64(authority.interCert)], sig: b64(sig), cert_info: b64(certInfo), pub_area: b64(pubArea) };
}

/** A CRL from the test root revoking `serials` (hex), as Microsoft publishes for its TPM root. */
export async function tpmCrl(authority, serials = [], { thisUpdate = Date.UTC(2025, 0, 1), nextUpdate = Date.UTC(2045, 0, 1) } = {}) {
  const algId = seq(oid('1.2.840.113549.1.1.11'), new Uint8Array([5, 0]));
  const hexBytes = hex => Uint8Array.from(hex.match(/../g), h => parseInt(h, 16));
  const entries = serials.map(serial => seq(integer(hexBytes(serial)), time(thisUpdate)));
  const tbs = seq(integer(Uint8Array.of(1)), algId, seq(set(seq(oid('2.5.4.3'), utf8('Test TPM Root')))), time(thisUpdate), time(nextUpdate), ...(entries.length ? [seq(...entries)] : []));
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', authority.rootKey, tbs));
  return seq(tbs, algId, bits(sig));
}
