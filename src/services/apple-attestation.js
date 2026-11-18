// Apple App Attest (STATUS B5), the iOS counterpart of Android Key Attestation in attestation.js.
//
// App Attest cannot attest an arbitrary key: Apple attests a key of its own (DCAppAttestService)
// and says which app on a genuine Apple device holds it. So the iOS app generates its DBA key in
// the Secure Enclave, then asks App Attest to attest with
//   clientDataHash = SHA-256("<challenge>.<JWK thumbprint of the DBA key>")
// which makes the genuine app vouch for that key. The result is only as good as that app, which is
// why grants count it only for apps they name (spec/evaluation.md §3.6, require.app_ids).
//
// The checks follow Apple's "Validating apps that connect to your server": the certificate chain
// to the pinned Apple App Attestation Root CA, the nonce extension, the key id, the app id hash,
// a zero counter, the environment and the credential id.
import { ApiError } from '../utils/errors.js';
import { children, parseOne, expectTag, concat } from './der.js';
import { decodeCbor } from './cbor.js';
import { parseCertificate, signedBy } from './attestation.js';

/**
 * Apple App Attestation Root CA (P-384, valid 2020-03-18 to 2045-03-15), SHA-256 fingerprint
 * 1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932. Apple publishes it at
 * https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem.
 */
export const APPLE_APP_ATTEST_ROOT = 'MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD';
/** SHA-256 of that root's SubjectPublicKeyInfo, checked by a test against the certificate. */
export const APPLE_ROOT_SPKI_SHA256 = 'GudR/SmJbQ8fE/4ibAY/RF1A2JOKzGJFwlHswGeTML0=';

const NONCE_OID = '1.2.840.113635.100.8.2';
const ENVIRONMENTS = { appattestdevelop: 'development', 'appattest\0\0\0\0\0\0\0': 'production' };
/** An Apple app id: 10-character team id, a dot, the bundle id (as in require.app_ids). */
export const APP_ID = /^[A-Z0-9]{10}\.[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$/;
const MAX_OBJECT_BYTES = 16384;
const SKEW_MS = 5 * 60 * 1000;

const invalid = message => new ApiError(400, 'invalid_attestation', `App attestation rejected: ${message}`);
const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const equalBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

/** The root certificate's SubjectPublicKeyInfo (DER). */
export function appleRootSpki() { return parseCertificate(fromBase64(APPLE_APP_ATTEST_ROOT)).spki; }

/** The uncompressed EC point inside a P-256 SubjectPublicKeyInfo. */
function ecPoint(spki) {
  const [, key] = children(parseOne(spki));
  const bits = expectTag(key, 3, 'BIT STRING').content;
  if (bits[0] !== 0 || bits.length !== 66 || bits[1] !== 4) throw new Error('not an uncompressed P-256 key');
  return bits.subarray(1);
}

/** The nonce in the leaf's 1.2.840.113635.100.8.2 extension: SEQUENCE { [1] EXPLICIT OCTET STRING }. */
function certificateNonce(extension) {
  const [tagged] = children(expectTag(parseOne(extension), 16, 'nonce SEQUENCE'));
  if (tagged.cls !== 2 || tagged.tag !== 1) throw new Error('expected [1] nonce');
  return expectTag(children(tagged)[0], 4, 'nonce OCTET STRING').content;
}

/**
 * Verify an App Attest attestation object.
 * options: { object: base64 attestation object; keyId: base64 key id from generateKey();
 * appId: "TEAMID.bundle.id" the app claims to be; clientData: the bytes whose SHA-256 the app
 * passed to attestKey; now (ms); roots: SubjectPublicKeyInfo DERs of trusted roots }.
 * Returns the `device.attestation` claim, or throws invalid_attestation.
 */
export async function verifyAppleAttestation({ object, keyId, appId, clientData, now = Date.now(), roots = [appleRootSpki()] }) {
  if (typeof object !== 'string' || object.length > MAX_OBJECT_BYTES * 2) throw invalid('object must be the base64 attestation object');
  if (typeof appId !== 'string' || appId.length > 200 || !APP_ID.test(appId)) throw invalid('app_id must be TEAMID.bundle.id');
  let keyIdBytes; let decoded;
  try { keyIdBytes = fromBase64(keyId); } catch { throw invalid('key_id must be base64'); }
  if (keyIdBytes.length !== 32) throw invalid('key_id must be 32 bytes');
  try { decoded = decodeCbor(fromBase64(object)); } catch (error) { throw invalid(`unreadable attestation object (${error.message})`); }
  if (!(decoded instanceof Map) || decoded.get('fmt') !== 'apple-appattest') throw invalid('fmt must be apple-appattest');
  const statement = decoded.get('attStmt'); const authData = decoded.get('authData');
  const x5c = statement instanceof Map ? statement.get('x5c') : null;
  if (!Array.isArray(x5c) || x5c.length !== 2 || !x5c.every(c => c instanceof Uint8Array)) throw invalid('x5c must hold the credential certificate and its intermediate');
  if (!(authData instanceof Uint8Array) || authData.length < 55) throw invalid('authData is too short');

  // 1. The chain: leaf signed by the intermediate, the intermediate by a pinned root.
  let leaf; let intermediate;
  try { [leaf, intermediate] = x5c.map(parseCertificate); } catch (error) { throw invalid(`unreadable certificate (${error.message})`); }
  try {
    if (!await signedBy(leaf, intermediate.spki)) throw invalid('the credential certificate is not signed by the intermediate');
    let rooted = false;
    for (const root of roots) rooted = rooted || await signedBy(intermediate, root).catch(() => false);
    if (!rooted) throw invalid('the chain does not end at the Apple App Attestation Root CA');
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw invalid(`unverifiable signature (${error.message})`);
  }
  for (const [i, cert] of [leaf, intermediate].entries()) {
    if (cert.notBefore > now + SKEW_MS || cert.notAfter < now - SKEW_MS) throw invalid(`certificate ${i} is outside its validity period`);
  }
  if (intermediate.extensions.has(NONCE_OID)) throw invalid('only the credential certificate may carry a nonce');

  // 2–4. The nonce binds authData and our client data to the certificate.
  const extension = leaf.extensions.get(NONCE_OID);
  if (!extension) throw invalid('the credential certificate has no nonce');
  let nonce;
  try { nonce = certificateNonce(extension); } catch (error) { throw invalid(`unreadable nonce (${error.message})`); }
  if (!equalBytes(nonce, await sha256(concat(authData, await sha256(clientData))))) throw invalid('the nonce does not match (wrong challenge or key)');

  // 5. The key id is the SHA-256 of the attested public key.
  let point;
  try { point = ecPoint(leaf.spki); } catch (error) { throw invalid(error.message); }
  if (!equalBytes(await sha256(point), keyIdBytes)) throw invalid('key_id does not match the attested key');

  // 6–9. authData: rpIdHash ‖ flags ‖ counter ‖ aaguid ‖ credentialIdLength ‖ credentialId ‖ …
  if (!equalBytes(authData.subarray(0, 32), await sha256(new TextEncoder().encode(appId)))) throw invalid('the attestation is for another app');
  if (!(authData[32] & 0x40)) throw invalid('authData has no attested credential');
  if (authData.subarray(33, 37).some(b => b !== 0)) throw invalid('the counter must be 0');
  const environment = ENVIRONMENTS[String.fromCharCode(...authData.subarray(37, 53))];
  if (!environment) throw invalid('unknown App Attest environment');
  const idLength = authData[53] * 256 + authData[54];
  if (!equalBytes(authData.subarray(55, 55 + idLength), keyIdBytes)) throw invalid('the credential id is not the key id');

  return { format: 'apple-appattest', security_level: 'secure_enclave', app_id: appId, environment };
}

/** The client data an iOS app hashes into attestKey for enrolling the key with this thumbprint. */
export const appleClientData = (challenge, jkt) => new TextEncoder().encode(`${challenge}.${jkt}`);

