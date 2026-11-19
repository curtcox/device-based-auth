// TPM 2.0 key attestation through EK credential activation (STATUS B5), for TPMs whose attestation
// key has no Microsoft certificate: most Linux machines, and Windows ones outside Windows' own AIK
// enrollment. tpm-attestation.js covers the Microsoft-certified case in one step; this takes two.
//
// 1. The device sends its TPM's endorsement-key (EK) certificate, the public area of an attestation
//    key (AK: restricted, signing, fixedTPM) and a TPM2_Certify of its P-256 device key signed by
//    the AK. We check the EK certificate chains to a TPM manufacturer's CA (tpm-ek-anchors.js), the
//    AK signed the certify, and the certified key is the device key, generated in a TPM and unable
//    to leave it. What that does not show is that the AK lives in the same TPM as the EK.
// 2. So we encrypt a fresh random secret to the EK, bound to the AK's name (TPM2_MakeCredential,
//    done here in software). Only the TPM holding that EK can decrypt it, and it releases it only
//    when an object with that name is loaded in it (TPM2_ActivateCredential). The device returns
//    the secret with its enrollment; a signed activation token carries the secret's hash, so this
//    stays stateless.
//
// TPM2_Certify's qualifyingData is not used: freshness comes from the activation secret, and
// tpm2-tools' tpm2_certify cannot set it. A replayed certify proves nothing new anyway: the key it
// names is TPM-resident, and the enrollment request must be signed with it.
//
// EK certificates' validity periods are not checked: an EK identifies the TPM for its whole life
// (the TCG profile suggests notAfter 9999-12-31), and many genuine TPMs carry certificates from
// intermediates that have since expired. Revocation is checked: the EK certificate and any CA the
// device sends against their issuer's CRL distribution points (checkEkRevocation).
// Only RSA-2048 EKs (TCG template L-1: SHA-256, AES-128-CFB) are supported; every TPM 2.0 has one.
import { ApiError } from '../utils/errors.js';
import { children, parseOne, expectTag, decodeOid, concat, seq, oid, tlv, bits } from './der.js';
import { b64u, jwkThumbprint } from '../../packages/verify/src/jose.js';
import { parseCertificate, signedBy, basicConstraints } from './attestation.js';
import { reader, parseTpmPublic, parseCertInfo, tpmManufacturer, tpmObjectName, REQUIRED_ATTRIBUTES, parseTpmCrl } from './tpm-attestation.js';
import { TPM_EK_ANCHORS } from './tpm-ek-anchors.js';

const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
const RSAES_OAEP = '1.2.840.113549.1.1.7';
const ALG = { rsassa: 0x0014, ecdsa: 0x0018 };
const HASHES = { 0x000b: ['SHA-256', 32], 0x000c: ['SHA-384', 48], 0x000d: ['SHA-512', 64] };
const CURVES = { 0x0003: ['P-256', 32], 0x0004: ['P-384', 48] };
// TPMA_OBJECT: an AK must be restricted (it signs only what the TPM generated) and not decrypt.
const RESTRICTED = 1 << 16;
const DECRYPT = 1 << 17;
const MAX_INTERMEDIATES = 3;
const MAX_PART_BYTES = 8192;
const SECRET_BYTES = 32;
const CREDENTIAL_BLOB_MAGIC = Uint8Array.of(0xba, 0xdc, 0xc0, 0xde, 0, 0, 0, 1);
export const ACTIVATION_PREFIX = 'dbatpm_';
export const ACTIVATION_SECONDS = 600;

const invalid = message => new ApiError(400, 'invalid_attestation', `TPM attestation rejected: ${message}`);
const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const toBase64 = bytes => btoa(String.fromCharCode(...bytes));
const equalBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const u16 = n => Uint8Array.of(n >> 8, n & 255);
const u32 = n => Uint8Array.of(n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255);
const enc = new TextEncoder();

/** Base64 input that may be a TPM2B (2-byte size first) or the bare structure; returns the bare one. */
function unsized(bytes) {
  return bytes.length >= 2 && ((bytes[0] << 8) | bytes[1]) === bytes.length - 2 ? bytes.subarray(2) : bytes;
}

function part(value, name) {
  if (typeof value !== 'string' || value.length > MAX_PART_BYTES * 2) throw invalid(`${name} must be base64`);
  try { return fromBase64(value); } catch { throw invalid(`${name} must be base64`); }
}

// ---- TPM cryptography (TPM 2.0 Library Part 1: §11.4.10 KDFa, §24 credential protection) ----

/** KDFa in counter mode over HMAC; `label` without its terminating zero byte, which is added. */
export async function kdfa(hash, key, label, contextU, contextV, sizeBits) {
  const hmac = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash }, false, ['sign']);
  const out = [];
  let have = 0;
  for (let counter = 1; have < sizeBits / 8; counter++) {
    const block = new Uint8Array(await crypto.subtle.sign('HMAC', hmac, concat(u32(counter), enc.encode(label), Uint8Array.of(0), contextU, contextV, u32(sizeBits))));
    out.push(block); have += block.length;
  }
  return concat(...out).subarray(0, sizeBits / 8);
}

/**
 * AES-CFB128 encryption, by default with the zero IV credential protection uses. WebCrypto has no
 * CFB, so each keystream block is AES-CBC of one block under a zero IV, whose first 16 bytes are
 * E(K, block).
 */
export async function aesCfbEncrypt(keyBytes, data, iv = new Uint8Array(16)) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-CBC', false, ['encrypt']);
  const out = new Uint8Array(data.length);
  let previous = Uint8Array.from(iv);
  for (let offset = 0; offset < data.length; offset += 16) {
    const stream = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, key, previous)).subarray(0, 16);
    const chunk = data.subarray(offset, offset + 16);
    const cipher = chunk.map((b, i) => b ^ stream[i]);
    out.set(cipher, offset);
    previous = new Uint8Array(16); previous.set(cipher);
  }
  return out;
}

/** The EK's RSA public key for RSA-OAEP. Some EK certificates label it id-RSAES-OAEP, which WebCrypto will not import. */
async function ekEncryptionKey(spkiBytes) {
  const [algorithm, key] = children(expectTag(parseOne(spkiBytes), 16, 'SubjectPublicKeyInfo'));
  const keyType = decodeOid(children(algorithm)[0]);
  if (keyType !== RSA_ENCRYPTION && keyType !== RSAES_OAEP) throw invalid('only RSA endorsement keys are supported (the TPM\'s RSA-2048 EK, template L-1)');
  const spki = keyType === RSA_ENCRYPTION ? spkiBytes : seq(seq(oid(RSA_ENCRYPTION), tlv(0x05)), bits(expectTag(key, 3, 'BIT STRING').content.subarray(1)));
  const imported = await crypto.subtle.importKey('spki', spki, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  if (imported.algorithm.modulusLength !== 2048) throw invalid('only RSA-2048 endorsement keys are supported (template L-1)');
  return imported;
}

/**
 * TPM2_MakeCredential for an RSA-2048 EK (nameAlg SHA-256, AES-128-CFB): `secret` wrapped so that
 * only the TPM holding the EK, with an object named `objectName` loaded, can unwrap it.
 * Returns { idObject, encryptedSecret }: the contents of TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET.
 */
export async function makeCredential(ekKey, objectName, secret, seed = crypto.getRandomValues(new Uint8Array(32))) {
  const encryptedSecret = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP', label: enc.encode('IDENTITY\0') }, ekKey, seed));
  const symKey = await kdfa('SHA-256', seed, 'STORAGE', objectName, new Uint8Array(0), 128);
  const encIdentity = await aesCfbEncrypt(symKey, concat(u16(secret.length), secret));
  const hmacKey = await kdfa('SHA-256', seed, 'INTEGRITY', new Uint8Array(0), new Uint8Array(0), 256);
  const hmac = await crypto.subtle.importKey('raw', hmacKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const outerHmac = new Uint8Array(await crypto.subtle.sign('HMAC', hmac, concat(encIdentity, objectName)));
  return { idObject: concat(u16(outerHmac.length), outerHmac, encIdentity), encryptedSecret };
}

/** The file tpm2_makecredential writes and tpm2_activatecredential -i reads. */
export const credentialBlobFile = ({ idObject, encryptedSecret }) => concat(CREDENTIAL_BLOB_MAGIC, u16(idObject.length), idObject, u16(encryptedSecret.length), encryptedSecret);

/** Verify a TPMT_SIGNATURE (RSASSA or ECDSA) by the key in a parsed TPMT_PUBLIC over `data`. */
export async function verifyTpmSignature(pub, signatureBytes, data) {
  const r = reader(signatureBytes);
  const sigAlg = r.u16();
  const hashInfo = HASHES[r.u16()];
  if (!hashInfo) throw new Error('unsupported signature hash');
  const [hash] = hashInfo;
  if (sigAlg === ALG.rsassa && pub.type === 'rsa') {
    const signature = r.sized();
    if (!r.done()) throw new Error('trailing bytes in the signature');
    const key = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: b64u(pub.modulus), e: b64u(trimmed(u32(pub.exponent))) }, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data);
  }
  if (sigAlg === ALG.ecdsa && pub.type === 'ecc') {
    const curve = CURVES[pub.curve];
    if (!curve) throw new Error('unsupported curve');
    const [name, size] = curve;
    const sr = r.sized(); const ss = r.sized();
    if (!r.done()) throw new Error('trailing bytes in the signature');
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: name, x: b64u(fixed(pub.x, size)), y: b64u(fixed(pub.y, size)) }, { name: 'ECDSA', namedCurve: name }, false, ['verify']);
    return crypto.subtle.verify({ name: 'ECDSA', hash }, key, concat(fixed(sr, size), fixed(ss, size)), data);
  }
  throw new Error('the signature must be RSASSA by an RSA key or ECDSA by an ECC key');
}
const trimmed = bytes => { let i = 0; while (i < bytes.length - 1 && bytes[i] === 0) i++; return bytes.subarray(i); };
function fixed(bytes, size) {
  const value = trimmed(bytes);
  if (value.length > size) throw new Error('value too large');
  const out = new Uint8Array(size); out.set(value, size - value.length); return out;
}

// ---- The endorsement key certificate ----

/** The anchors as parsed certificates (once per isolate). */
let parsedAnchors = null;
export function tpmEkAnchors() {
  parsedAnchors ||= TPM_EK_ANCHORS.map(anchor => ({ name: anchor.name, ...parseCertificate(fromBase64(anchor.der)) }));
  return parsedAnchors;
}

/** A malformed basicConstraints counts as "not a CA" (a 400), never a parse error (a 500). */
function isCa(cert) {
  try { return basicConstraints(cert)?.ca === true; } catch { return false; }
}

/**
 * Check an EK certificate chains to an anchor, directly or through up to three CA certificates
 * the device sent. Returns { spki, manufacturer }.
 */
export async function verifyEkCertificate(ekCertificate, chain = [], anchors = tpmEkAnchors()) {
  if (!Array.isArray(chain) || chain.length > MAX_INTERMEDIATES) throw invalid(`ek_chain must list at most ${MAX_INTERMEDIATES} certificates`);
  let ek; let intermediates;
  try {
    ek = parseCertificate(part(ekCertificate, 'ek_certificate'));
    intermediates = chain.map((c, i) => parseCertificate(part(c, `ek_chain[${i}]`)));
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw invalid(`unreadable EK certificate (${error.message})`);
  }
  for (const [i, cert] of intermediates.entries()) if (!isCa(cert)) throw invalid(`ek_chain[${i}] is not a CA certificate`);
  // Walk up by issuer name, trying the anchors first at each step.
  // `path` pairs each certificate with the key that signed it, for the revocation check.
  let current = ek; const path = [];
  for (let depth = 0; depth <= intermediates.length; depth++) {
    for (const anchor of anchors) {
      if (equalBytes(anchor.subject, current.issuer) && await signedBy(current, anchor.spki).catch(() => false)) {
        let manufacturer = null;
        try { const san = ek.extensions.get('2.5.29.17'); manufacturer = san ? tpmManufacturer(san) : null; } catch { manufacturer = null; }
        if (!manufacturer) throw invalid('the EK certificate names no TPM manufacturer');
        path.push({ cert: current, issuerSpki: anchor.spki, issuerNotAfter: anchor.notAfter });
        return { spki: ek.spki, manufacturer, path };
      }
    }
    let next = null;
    for (const cert of intermediates) {
      if (cert !== current && equalBytes(cert.subject, current.issuer) && await signedBy(current, cert.spki).catch(() => false)) { next = cert; break; }
    }
    if (!next) break;
    path.push({ cert: current, issuerSpki: next.spki, issuerNotAfter: next.notAfter });
    current = next;
  }
  throw invalid('the EK certificate does not chain to a known TPM manufacturer CA');
}

// ---- Revocation ----

const CRL_DISTRIBUTION_POINTS = '2.5.29.31';
const MAX_CRL_BYTES = 1 << 20;
const MAX_CRL_URLS = 3;
const CRL_CACHE_MS = 3600_000;
const CRL_CACHE_ENTRIES = 64;
const crlCache = new Map(); // `${url} ${issuer key}` → { serials, until }

/** The http(s) URLs in a certificate's CRL distribution points extension (fullName URIs). */
export function crlDistributionPoints(cert) {
  const value = cert.extensions.get(CRL_DISTRIBUTION_POINTS);
  if (!value) return [];
  const urls = [];
  for (const point of children(expectTag(parseOne(value), 16, 'CRLDistributionPoints'))) {
    const name = children(point).find(e => e.cls === 2 && e.tag === 0); // distributionPoint
    const full = name && children(name).find(e => e.cls === 2 && e.tag === 0); // fullName
    for (const general of full ? children(full) : []) {
      if (general.cls !== 2 || general.tag !== 6) continue; // uniformResourceIdentifier
      const url = new TextDecoder().decode(general.content);
      if (/^https?:\/\/[\x21-\x7e]+$/.test(url)) urls.push(url);
    }
  }
  return urls;
}

/** Serials on the CRL at `url`, which must be signed by `issuerSpki` and current. Cached for an hour. */
async function crlSerials(url, issuerSpki, fetcher, now) {
  const key = `${url} ${b64u(issuerSpki)}`;
  const cached = crlCache.get(key);
  if (cached && cached.until > now) return cached.serials;
  const response = await fetcher(url, { cf: { cacheTtl: 3600, cacheEverything: true } });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  if (Number(response.headers.get('content-length')) > MAX_CRL_BYTES) throw new Error('CRL too large');
  const der = new Uint8Array(await response.arrayBuffer());
  if (der.length > MAX_CRL_BYTES) throw new Error('CRL too large');
  const serials = await parseTpmCrl(der, [issuerSpki], now);
  if (crlCache.size >= CRL_CACHE_ENTRIES) crlCache.delete(crlCache.keys().next().value);
  crlCache.set(key, { serials, until: now + CRL_CACHE_MS });
  return serials;
}
export function resetEkCrlCache() { crlCache.clear(); }

/**
 * Check the EK certificate, and each CA certificate the device sent, against the revocation list
 * its issuer publishes (CRL distribution points). Certificates naming none are not checked; most
 * TPM manufacturers name one. A list that cannot be fetched, is not signed by the issuer or is out
 * of date fails closed with 503, as Google's and Microsoft's lists do. Not checked: certificates
 * whose issuing CA has itself expired (it no longer publishes fresh lists, and many genuine TPMs
 * chain through such CAs; see the top of this file), and the pinned anchors.
 */
export async function checkEkRevocation(path, { fetcher = fetch, now = Date.now() } = {}) {
  for (const [i, { cert, issuerSpki, issuerNotAfter }] of path.entries()) {
    const urls = crlDistributionPoints(cert).slice(0, MAX_CRL_URLS);
    if (!urls.length || (issuerNotAfter && issuerNotAfter < now)) continue;
    let serials = null;
    for (const url of urls) {
      try { serials = await crlSerials(url, issuerSpki, fetcher, now); break; } catch { serials = null; }
    }
    if (!serials) throw new ApiError(503, 'attestation_unavailable', `The TPM manufacturer's revocation list (${urls[0]}) is unavailable; try again shortly`);
    if (serials.has(cert.serial)) throw invalid(i === 0 ? 'the TPM manufacturer has revoked this EK certificate' : 'the TPM manufacturer has revoked a CA certificate in ek_chain');
  }
}

// ---- The two steps ----

/**
 * Step 1: check the EK certificate, the AK, and its certify of the device key; wrap a new secret
 * for the TPM. options: { ekCertificate, ekChain, akPubArea, pubArea, certInfo, sig (base64),
 * anchors }. Returns { jwk, jkt, manufacturer, secret, idObject, encryptedSecret }.
 */
export async function startTpmActivation({ ekCertificate, ekChain = [], akPubArea, pubArea, certInfo, sig, anchors, fetcher = fetch, now = Date.now() }) {
  const { spki, manufacturer, path } = await verifyEkCertificate(ekCertificate, ekChain, anchors);
  const ekKey = await ekEncryptionKey(spki);

  const akBytes = unsized(part(akPubArea, 'ak_pub_area'));
  const keyBytes = unsized(part(pubArea, 'pub_area'));
  const infoBytes = part(certInfo, 'cert_info');
  const signature = part(sig, 'sig');
  let ak; let key; let info;
  try { ak = parseTpmPublic(akBytes); } catch (error) { throw invalid(`unreadable ak_pub_area (${error.message})`); }
  try { key = parseTpmPublic(keyBytes); } catch (error) { throw invalid(`unreadable pub_area (${error.message})`); }
  try { info = parseCertInfo(infoBytes); } catch (error) { throw invalid(`unreadable cert_info (${error.message})`); }

  // The AK: generated in this TPM, kept there, and restricted, so it signs only TPM-made structures.
  for (const [label, bit] of Object.entries({ ...REQUIRED_ATTRIBUTES, restricted: RESTRICTED })) {
    if (!(ak.attributes & bit)) throw invalid(`the attestation key lacks the ${label} attribute`);
  }
  if (ak.attributes & DECRYPT) throw invalid('the attestation key must not be a decryption key');
  let signed;
  try { signed = await verifyTpmSignature(ak, signature, infoBytes); } catch (error) { throw invalid(`unverifiable certify signature (${error.message})`); }
  if (!signed) throw invalid('the attestation key did not sign cert_info');

  // The certified key: exactly pub_area, a P-256 signing key that cannot leave the TPM.
  let akName; let keyName;
  try { akName = await tpmObjectName(akBytes, ak.nameAlg); keyName = await tpmObjectName(keyBytes, key.nameAlg); } catch (error) { throw invalid(error.message); }
  if (!equalBytes(info.name, keyName)) throw invalid('cert_info does not name the key in pub_area');
  if (key.type !== 'ecc' || key.curve !== 0x0003) throw invalid('the device key must be P-256');
  for (const [label, bit] of Object.entries(REQUIRED_ATTRIBUTES)) {
    if (!(key.attributes & bit)) throw invalid(`the key lacks the ${label} attribute (it must be generated in the TPM, unable to leave it, and a signing key)`);
  }
  let jwk;
  try { jwk = { kty: 'EC', crv: 'P-256', x: b64u(fixed(key.x, 32)), y: b64u(fixed(key.y, 32)) }; } catch { throw invalid('the device key is not a P-256 point'); }

  // Last, so a request that fails the checks above costs no fetch.
  await checkEkRevocation(path, { fetcher, now });
  const secret = crypto.getRandomValues(new Uint8Array(SECRET_BYTES));
  const wrapped = await makeCredential(ekKey, akName, secret);
  return { jwk, jkt: await jwkThumbprint(jwk), manufacturer, secret, ...wrapped };
}

/** Step 1 as the API answers it, with the activation token that step 2 checks. */
export async function tpmActivationResponse(result, { challenge, sign, now = Date.now() }) {
  const secretHash = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', result.secret)));
  const activation = await sign({ c: challenge, j: result.jkt, m: result.manufacturer, s: secretHash, exp: Math.floor(now / 1000) + ACTIVATION_SECONDS });
  return {
    activation,
    id_object: toBase64(result.idObject),
    encrypted_secret: toBase64(result.encryptedSecret),
    credential_blob: toBase64(credentialBlobFile(result)),
    jkt: result.jkt,
    expires_in: ACTIVATION_SECONDS
  };
}

/**
 * Step 2, at enrollment: the activation token (already verified, so `payload` is its contents) is
 * for this challenge and key, and `secret` (base64) is the one the TPM unwrapped.
 */
export async function finishTpmActivation({ payload, challenge, secret, jkt }) {
  if (!payload) throw invalid('the activation is unknown or has expired; start again');
  if (payload.c !== challenge) throw invalid('the activation is for another challenge');
  if (payload.j !== jkt) throw invalid('the activation is for another key');
  const bytes = part(secret, 'secret');
  const hash = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
  if (hash !== payload.s) throw invalid('the activation secret is wrong (it was not unwrapped by this TPM)');
  return { format: 'tpm', security_level: 'tpm', tpm_manufacturer: payload.m };
}
