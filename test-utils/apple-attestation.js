// Builds Apple App Attest attestation objects shaped like real ones, under a test root, so the
// enrollment flow can be tested without an iPhone: P-384 root → P-384 intermediate → P-256
// credential certificate carrying the nonce extension, wrapped in CBOR with authData.
// Real attestations from Apple are tested in src/apple-attestation.test.js.
import { seq, octets, explicit, bool, concat } from '../src/services/der.js';
import { certificate, ext, spkiOf } from './android-attestation.js';

const NONCE_OID = '1.2.840.113635.100.8.2';
const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const text = value => new TextEncoder().encode(value);
const b64 = bytes => btoa(String.fromCharCode(...bytes));

/** Just enough CBOR encoding for an attestation object (maps, arrays, strings, bytes, small ints). */
export function encodeCbor(value) {
  const head = (major, n) => n < 24 ? Uint8Array.of((major << 5) | n) : n < 256 ? Uint8Array.of((major << 5) | 24, n) : n < 65536 ? Uint8Array.of((major << 5) | 25, n >> 8, n & 255) : Uint8Array.of((major << 5) | 26, n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255);
  if (typeof value === 'number') return head(0, value);
  if (typeof value === 'string') { const b = text(value); return concat(head(3, b.length), b); }
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  if (Array.isArray(value)) return concat(head(4, value.length), ...value.map(encodeCbor));
  const entries = value instanceof Map ? [...value] : Object.entries(value);
  return concat(head(5, entries.length), ...entries.flatMap(([k, v]) => [encodeCbor(k), encodeCbor(v)]));
}

/** A test App Attest root and intermediate. `rootSpki` (base64url) goes in APPLE_ATTESTATION_TEST_ROOT. */
export async function appleAuthority() {
  const root = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']);
  const inter = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']);
  const rootSpki = await spkiOf(root.publicKey);
  const ca = ext('2.5.29.19', seq(bool(true)), true);
  const interCert = await certificate({ serial: Uint8Array.of(0x0a), issuer: 'Test App Attestation Root CA', subject: 'Test App Attestation CA 1', spki: await spkiOf(inter.publicKey), signer: { kind: 'ec', hash: 'SHA-384', privateKey: root.privateKey }, notBefore: Date.UTC(2025, 0, 1), notAfter: Date.UTC(2045, 0, 1), extensions: [ca] });
  return { rootSpki, rootSpkiB64u: b64(rootSpki).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), interCert, interSigner: { kind: 'ec', hash: 'SHA-384', privateKey: inter.privateKey } };
}

/**
 * An attestation object for `clientData` from app `appId`. Returns { object, keyId } in base64,
 * as an iOS app would send them. Overrides for negative tests: environment ('development',
 * 'production' or a raw 16-character aaguid), counter, nonceFor (other client data), rpId,
 * credentialId, keyId, notAfter.
 */
export async function appleAttestation(authority, { appId, clientData, environment = 'production', counter = 0, nonceFor = clientData, rpId = appId, credentialId, keyId, notAfter = Date.UTC(2045, 0, 1) }) {
  const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const point = new Uint8Array(await crypto.subtle.exportKey('raw', key.publicKey));
  const realKeyId = await sha256(point);
  const aaguid = text(environment === 'production' ? 'appattest\0\0\0\0\0\0\0' : environment === 'development' ? 'appattestdevelop' : environment);
  const credId = credentialId ?? realKeyId;
  const counterBytes = Uint8Array.of(counter >>> 24, (counter >> 16) & 255, (counter >> 8) & 255, counter & 255);
  const authData = concat(await sha256(text(rpId)), Uint8Array.of(0x40), counterBytes, aaguid, Uint8Array.of(credId.length >> 8, credId.length & 255), credId, encodeCbor(new Map([[1, 2]])));
  const nonce = await sha256(concat(authData, await sha256(nonceFor)));
  const leaf = await certificate({ serial: Uint8Array.of(0x01, 0x8d), issuer: 'Test App Attestation CA 1', subject: b64(realKeyId), spki: await spkiOf(key.publicKey), signer: authority.interSigner, notBefore: Date.UTC(2025, 0, 1), notAfter, extensions: [ext(NONCE_OID, seq(explicit(1, octets(nonce))))] });
  const object = encodeCbor(new Map([['fmt', 'apple-appattest'], ['attStmt', new Map([['x5c', [leaf, authority.interCert]], ['receipt', Uint8Array.of(0)]])], ['authData', authData]]));
  return { object: b64(object), keyId: b64(keyId ?? realKeyId) };
}
