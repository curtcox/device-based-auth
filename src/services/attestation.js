// Device key attestation (STATUS B5): evidence from the platform that a device key was generated
// inside secure hardware. Today: Android Key Attestation. A verified attestation becomes
// `device.attestation` in the credential, set only by the issuer (spec/credential.md §3a).
//
// Android: the device generates its key in the Keystore with setAttestationChallenge(challenge)
// and sends the certificate chain (leaf first). We check that the chain is signed up to a pinned
// Google attestation root, nothing in it is on Google's revocation list, the leaf's key is the
// enrolled key, the KeyDescription extension appears in the leaf only (so an attested signing key
// cannot vouch for a forged leaf), and the key was generated (not imported) in a TEE or StrongBox
// as an EC signing key, with our challenge.
import { b64u, unb64u } from '../../packages/verify/src/jose.js';
import { assert, ApiError } from '../utils/errors.js';
import { children, parseOne, expectTag, decodeOid, decodeSmallInt, integerHex, decodeTime, concat } from './der.js';

/**
 * SHA-256 of the SubjectPublicKeyInfo of each Google hardware attestation root, from
 * https://android.googleapis.com/attestation/root (checked 2026-11-18): the RSA-4096 root (also
 * behind the 2016 root certificate) and "Key Attestation CA1" (EC P-384, 2025).
 */
export const ANDROID_ROOT_SPKI_SHA256 = Object.freeze([
  '/rLqdVHuMW7Uu0Q8gpO4hNv96kC2A+4+T0qJfkWA+64=',
  'PuRFEqGvK+s5yIlJDGDqP4LkP11aVTL1q5QZ9nbNB+w='
]);
export const ANDROID_STATUS_URL = 'https://android.googleapis.com/attestation/status';
const KEY_DESCRIPTION_OID = '1.3.6.1.4.1.11129.2.1.17';
const MAX_CHAIN = 8;
const MAX_CERT_BYTES = 8192;
const CHALLENGE_SECONDS = 600;
const SKEW_MS = 5 * 60 * 1000;

const SIGNATURE_ALGORITHMS = {
  '1.2.840.113549.1.1.11': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
  '1.2.840.10045.4.3.2': { name: 'ECDSA', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { name: 'ECDSA', hash: 'SHA-384' },
  '1.2.840.10045.4.3.4': { name: 'ECDSA', hash: 'SHA-512' }
};
const CURVES = { '1.2.840.10045.3.1.7': ['P-256', 32], '1.3.132.0.34': ['P-384', 48], '1.3.132.0.35': ['P-521', 66] };
const SECURITY_LEVELS = { 1: 'tee', 2: 'strongbox' };
const BOOT_STATES = { 0: 'verified', 1: 'self_signed', 2: 'unverified', 3: 'failed' };
// AuthorizationList tags (Android KeyMint): purpose, algorithm, ecCurve, origin, rootOfTrust.
const TAG = { purpose: 1, algorithm: 2, ecCurve: 10, origin: 702, rootOfTrust: 704 };

const invalid = message => new ApiError(400, 'invalid_attestation', `Key attestation rejected: ${message}`);

/** Parse the parts of an X.509 certificate this check needs. */
export function parseCertificate(der) {
  const cert = parseOne(der);
  const [tbs, sigAlg, sigValue] = children(expectTag(cert, 16, 'Certificate'));
  const fields = children(expectTag(tbs, 16, 'TBSCertificate'));
  let i = 0;
  if (fields[0].cls === 2 && fields[0].tag === 0) i++; // [0] version
  const serial = integerHex(fields[i++]);
  i++; // signature algorithm (repeated in the outer certificate)
  i++; // issuer
  const [notBefore, notAfter] = children(expectTag(fields[i++], 16, 'Validity')).map(decodeTime);
  i++; // subject
  const spki = expectTag(fields[i++], 16, 'SubjectPublicKeyInfo');
  const extensions = new Map();
  for (; i < fields.length; i++) {
    if (fields[i].cls !== 2 || fields[i].tag !== 3) continue;
    for (const ext of children(expectTag(children(fields[i])[0], 16, 'Extensions'))) {
      const parts = children(ext);
      const id = decodeOid(parts[0]);
      if (extensions.has(id)) throw new Error('duplicate extension');
      extensions.set(id, expectTag(parts.at(-1), 4, 'extension value').content);
    }
  }
  const signatureBits = expectTag(sigValue, 3, 'BIT STRING').content;
  if (signatureBits[0] !== 0) throw new Error('signature has unused bits');
  return { serial, notBefore, notAfter, spki: spki.raw, tbs: tbs.raw, signatureAlgorithm: decodeOid(children(sigAlg)[0]), signature: signatureBits.subarray(1), extensions };
}

/** Import a certificate's SubjectPublicKeyInfo for verifying signatures made with `algorithm`. */
async function importSpki(spki, algorithm) {
  const [alg] = children(parseOne(spki));
  const [keyOid, params] = children(alg);
  const keyType = decodeOid(keyOid);
  if (keyType === '1.2.840.113549.1.1.1' && algorithm.name === 'RSASSA-PKCS1-v1_5') {
    return { key: await crypto.subtle.importKey('spki', spki, { name: algorithm.name, hash: algorithm.hash }, false, ['verify']) };
  }
  if (keyType === '1.2.840.10045.2.1' && algorithm.name === 'ECDSA') {
    const curve = CURVES[decodeOid(params)];
    if (!curve) throw new Error('unsupported curve');
    return { key: await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: curve[0] }, false, ['verify']), size: curve[1] };
  }
  throw new Error('key and signature algorithms do not match');
}

/** DER Ecdsa-Sig-Value to WebCrypto's fixed-width r‖s. */
function rawEcdsa(der, size) {
  const [r, s] = children(parseOne(der)).map(e => expectTag(e, 2, 'INTEGER').content);
  const out = new Uint8Array(size * 2);
  for (const [value, offset] of [[r, 0], [s, size]]) {
    const trimmed = value.subarray(Math.max(0, value.length - size));
    if (value.length > size && value.subarray(0, value.length - size).some(b => b !== 0)) throw new Error('ECDSA value too large');
    out.set(trimmed, offset + size - trimmed.length);
  }
  return out;
}

/** True when `cert` was signed by the key in `issuerSpki`. */
async function signedBy(cert, issuerSpki) {
  const algorithm = SIGNATURE_ALGORITHMS[cert.signatureAlgorithm];
  if (!algorithm) throw new Error(`unsupported signature algorithm ${cert.signatureAlgorithm}`);
  const { key, size } = await importSpki(issuerSpki, algorithm);
  const signature = algorithm.name === 'ECDSA' ? rawEcdsa(cert.signature, size) : cert.signature;
  return crypto.subtle.verify(algorithm.name === 'ECDSA' ? { name: 'ECDSA', hash: algorithm.hash } : algorithm.name, key, signature, cert.tbs);
}

const sha256b64 = async bytes => btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))));

/** AuthorizationList (SEQUENCE of [tag] EXPLICIT values) as a Map from tag number to element. */
function authorizationList(element) {
  const out = new Map();
  for (const item of children(expectTag(element, 16, 'AuthorizationList'))) {
    if (item.cls !== 2 || !item.constructed) throw new Error('malformed AuthorizationList');
    if (out.has(item.tag)) throw new Error('duplicate authorization tag');
    out.set(item.tag, children(item)[0]);
  }
  return out;
}

/** Parse the Android KeyDescription extension. */
export function parseKeyDescription(bytes) {
  const fields = children(expectTag(parseOne(bytes), 16, 'KeyDescription'));
  if (fields.length < 8) throw new Error('KeyDescription too short');
  return {
    attestationVersion: decodeSmallInt(fields[0]),
    attestationSecurityLevel: decodeSmallInt(fields[1]),
    keymasterVersion: decodeSmallInt(fields[2]),
    keymasterSecurityLevel: decodeSmallInt(fields[3]),
    challenge: expectTag(fields[4], 4, 'attestationChallenge').content,
    softwareEnforced: authorizationList(fields[6]),
    hardwareEnforced: authorizationList(fields[7])
  };
}

/** P-256 SubjectPublicKeyInfo of a JWK, to compare with the attested leaf key. */
function jwkSpki(jwk) {
  const point = concat(Uint8Array.of(4), unb64u(jwk.x), unb64u(jwk.y));
  // SEQUENCE { SEQUENCE { ecPublicKey, prime256v1 }, BIT STRING point } — fixed 91-byte prefix form.
  const prefix = Uint8Array.of(0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00);
  return concat(prefix, point);
}
const equalBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

let revocationCache = null;

/**
 * Google's attestation certificate revocation list as a Set of serials (lowercase hex). Cached
 * per isolate for an hour and at the edge; failures are thrown, so enrollment fails closed.
 */
export async function androidRevokedSerials(fetcher = fetch, now = Date.now()) {
  if (revocationCache && revocationCache.until > now) return revocationCache.serials;
  const response = await fetcher(ANDROID_STATUS_URL, { cf: { cacheTtl: 3600, cacheEverything: true } });
  if (!response.ok) throw new Error(`attestation status list: HTTP ${response.status}`);
  const body = await response.json();
  if (!body || typeof body.entries !== 'object') throw new Error('attestation status list: unexpected format');
  const serials = new Set(Object.keys(body.entries).map(s => s.toLowerCase().replace(/^0+(?=.)/, '')));
  revocationCache = { serials, until: now + 3600_000 };
  return serials;
}
export function resetRevocationCache() { revocationCache = null; }

/**
 * Verify an Android Key Attestation chain for `jwk`.
 * options: { x5c: base64 DER certificates, leaf first; jwk; challenge: bytes the device passed to
 * setAttestationChallenge; now (ms); roots: pinned SPKI SHA-256 list; revoked: Set of serials }.
 * Returns the `device.attestation` claim, or throws invalid_attestation.
 */
export async function verifyAndroidAttestation({ x5c, jwk, challenge, now = Date.now(), roots = ANDROID_ROOT_SPKI_SHA256, revoked }) {
  if (!Array.isArray(x5c) || x5c.length < 2 || x5c.length > MAX_CHAIN || x5c.some(c => typeof c !== 'string' || c.length > MAX_CERT_BYTES * 2)) throw invalid(`x5c must list 2–${MAX_CHAIN} base64 certificates, leaf first`);
  let certs;
  try { certs = x5c.map(c => parseCertificate(Uint8Array.from(atob(c), ch => ch.charCodeAt(0)))); }
  catch (error) { throw invalid(`unreadable certificate (${error.message})`); }

  if (!roots.includes(await sha256b64(certs.at(-1).spki))) throw invalid('the chain does not end at a Google attestation root');
  for (let i = 0; i < certs.length; i++) {
    const issuer = certs[Math.min(i + 1, certs.length - 1)];
    let ok;
    try { ok = await signedBy(certs[i], issuer.spki); } catch (error) { throw invalid(`certificate ${i}: ${error.message}`); }
    if (!ok) throw invalid(`certificate ${i} is not signed by the next one`);
    // Device clocks set the leaf's notBefore, so only its expiry is checked.
    if ((i > 0 && certs[i].notBefore > now + SKEW_MS) || certs[i].notAfter < now - SKEW_MS) throw invalid(`certificate ${i} is outside its validity period`);
    if (revoked.has(certs[i].serial)) throw invalid(`certificate ${i} is revoked by Google`);
    if (i > 0 && certs[i].extensions.has(KEY_DESCRIPTION_OID)) throw invalid('only the leaf certificate may carry a key description');
  }

  const leaf = certs[0];
  if (!equalBytes(leaf.spki, jwkSpki(jwk))) throw invalid('the attested key is not the enrolled key');
  const extension = leaf.extensions.get(KEY_DESCRIPTION_OID);
  if (!extension) throw invalid('the leaf certificate has no key description');
  let description;
  try { description = parseKeyDescription(extension); } catch (error) { throw invalid(`unreadable key description (${error.message})`); }
  const level = SECURITY_LEVELS[description.attestationSecurityLevel];
  if (!level || description.keymasterSecurityLevel !== description.attestationSecurityLevel) throw invalid('the key is not in a TEE or StrongBox');
  if (!equalBytes(description.challenge, challenge)) throw invalid('the attestation challenge does not match');
  const hw = description.hardwareEnforced;
  const int = (tag, list = hw) => { const e = list.get(tag); return e ? decodeSmallInt(e) : undefined; };
  if (int(TAG.origin) !== 0) throw invalid('the key was not generated on the device (origin must be GENERATED)');
  if (int(TAG.algorithm) !== 3) throw invalid('the key is not an EC key');
  if (int(TAG.ecCurve) !== undefined && int(TAG.ecCurve) !== 1) throw invalid('the key is not P-256');
  const purposes = hw.get(TAG.purpose) ? children(expectTag(hw.get(TAG.purpose), 17, 'purpose SET')).map(decodeSmallInt) : [];
  if (!purposes.includes(2)) throw invalid('the key is not a signing key');

  const claim = { format: 'android-key', security_level: level, attestation_version: description.attestationVersion };
  const root = hw.get(TAG.rootOfTrust);
  if (root) {
    const [, locked, state] = children(expectTag(root, 16, 'RootOfTrust'));
    claim.device_locked = expectTag(locked, 1, 'deviceLocked').content[0] !== 0;
    claim.verified_boot = BOOT_STATES[decodeSmallInt(state)] ?? 'unknown';
  }
  return claim;
}

// ---- Challenges ----
// Stateless: 4-byte expiry, 12 random bytes, 16 bytes of HMAC, base64url (43 characters, inside
// Android's 128-byte challenge limit). The device passes the string's ASCII bytes as the challenge.

async function challengeKey(secret) {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(`dba-attestation-challenge:${secret}`), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

/** A fresh attestation challenge, valid for 10 minutes. */
export async function createChallenge(secret, now = Date.now()) {
  const body = new Uint8Array(16);
  new DataView(body.buffer).setUint32(0, Math.floor(now / 1000) + CHALLENGE_SECONDS);
  crypto.getRandomValues(body.subarray(4));
  const tag = new Uint8Array(await crypto.subtle.sign('HMAC', await challengeKey(secret), body)).subarray(0, 16);
  return { challenge: b64u(concat(body, tag)), expires_in: CHALLENGE_SECONDS };
}

/** Check a challenge this service issued and has not expired. */
export async function checkChallenge(challenge, secret, now = Date.now()) {
  let bytes;
  try { bytes = unb64u(challenge); } catch { bytes = null; }
  assert(typeof challenge === 'string' && bytes?.length === 32, 'invalid_attestation', 'Key attestation rejected: unknown challenge');
  const expected = new Uint8Array(await crypto.subtle.sign('HMAC', await challengeKey(secret), bytes.subarray(0, 16))).subarray(0, 16);
  assert(equalBytes(expected, bytes.subarray(16)), 'invalid_attestation', 'Key attestation rejected: unknown challenge');
  assert(new DataView(bytes.buffer, bytes.byteOffset).getUint32(0) * 1000 >= now, 'invalid_attestation', 'Key attestation rejected: the challenge has expired; get a new one');
}

/**
 * Verify the `attestation` member of an enrollment request for `jwk`. Returns the claim to put in
 * `device.attestation`. Formats other than android-key are refused (Apple App Attest and TPM
 * are still backlog).
 */
export async function verifyAttestation(attestation, jwk, env, { now = Date.now(), fetcher = fetch } = {}) {
  assert(attestation && typeof attestation === 'object' && !Array.isArray(attestation), 'invalid_attestation', 'attestation must be an object');
  assert(attestation.format === 'android-key', 'invalid_attestation', 'attestation.format must be android-key');
  await checkChallenge(attestation.challenge, env.TOKEN_SIGNING_KEY, now);
  let revoked;
  try { revoked = await androidRevokedSerials(fetcher, now); }
  catch { throw new ApiError(503, 'attestation_unavailable', 'Google\'s attestation revocation list is unavailable; try again shortly'); }
  // A local server (only) may trust one extra root, so tests can attest with their own chain.
  const roots = env.ENVIRONMENT === 'local' && env.ANDROID_ATTESTATION_TEST_ROOT ? [...ANDROID_ROOT_SPKI_SHA256, env.ANDROID_ATTESTATION_TEST_ROOT] : ANDROID_ROOT_SPKI_SHA256;
  return verifyAndroidAttestation({ x5c: attestation.x5c, jwk, challenge: new TextEncoder().encode(attestation.challenge), now, revoked, roots });
}

