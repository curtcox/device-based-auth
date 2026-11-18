// TPM 2.0 key attestation (STATUS B5), the PC counterpart of Android Key Attestation and Apple App
// Attest. The device creates its P-256 signing key inside the TPM, then has the TPM's attestation
// identity key (AIK) certify it with TPM2_Certify, passing
//   qualifyingData = SHA-256("<challenge>.<JWK thumbprint of the device key>")
// The TPM signs a TPMS_ATTEST naming the key, and the AIK's certificate chains to Microsoft's TPM
// root: Microsoft issues AIK certificates (Windows' "Windows AIK", also behind Windows Hello's
// WebAuthn "tpm" attestations) only after checking the TPM's endorsement certificate from its
// manufacturer. TPMs without such a certificate (most Linux machines) cannot attest this way yet.
//
// The checks follow the WebAuthn "tpm" attestation statement format (§8.3), with our
// qualifyingData in place of WebAuthn's: the AIK chain to the pinned root, the AIK certificate's
// TPM profile (EKU 2.23.133.8.3, not a CA, TPM manufacturer in the SAN), the signature over
// certInfo, certInfo naming exactly the key in pubArea, and pubArea being the enrolled key with
// fixedTPM, fixedParent, sensitiveDataOrigin and sign set. The CA that issued the AIK certificate
// must not be on the root's CRL.
import { ApiError } from '../utils/errors.js';
import { children, parseOne, expectTag, decodeOid, concat, integerHex, decodeTime } from './der.js';
import { unb64u } from '../../packages/verify/src/jose.js';
import { parseCertificate, signedBy } from './attestation.js';

/**
 * Microsoft TPM Root Certificate Authority 2014 (RSA-4096, valid 2014-12-10 to 2039-12-10),
 * SHA-256 fingerprint 870C7A35CEAB3D59979F2C6A524042D404CB71518004350925FB2CED79A999DA, from
 * http://www.microsoft.com/pkiops/certs/Microsoft%20TPM%20Root%20Certificate%20Authority%202014.crt.
 */
export const MICROSOFT_TPM_ROOT = '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';
/** SHA-256 of that root's SubjectPublicKeyInfo, checked by a test against the certificate. */
export const MICROSOFT_TPM_ROOT_SPKI_SHA256 = 'Xq36AYeiTtt0e5hSP4nPktM+6yDsgbnQox4XC3PC27I=';
/** The root's CRL (the CRL distribution point of every AIK CA it issues; ~10 KB, quarterly). */
export const MICROSOFT_TPM_CRL_URL = 'http://www.microsoft.com/pkiops/crl/Microsoft%20TPM%20Root%20Certificate%20Authority%202014.crl';
// A CRL past its nextUpdate is still used for this long, since Microsoft publishes late at times.
const CRL_GRACE_MS = 7 * 86400_000;

const AIK_EKU = '2.23.133.8.3';
const TPM_MANUFACTURER = '2.23.133.2.1';
const TPM_GENERATED = 0xff544347;
const ST_ATTEST_CERTIFY = 0x8017;
const ALG = { rsa: 0x0001, ecc: 0x0023, null: 0x0010 };
export const NAME_ALGS = { 0x000b: 'SHA-256', 0x000c: 'SHA-384', 0x000d: 'SHA-512' };
const ECC_NIST_P256 = 0x0003;
// TPMA_OBJECT bits: fixedTPM, fixedParent, sensitiveDataOrigin, sign.
export const REQUIRED_ATTRIBUTES = { fixedTPM: 1 << 1, fixedParent: 1 << 4, sensitiveDataOrigin: 1 << 5, sign: 1 << 18 };
// The AIK's signature over certInfo. RS1 is what Windows' AIKs produce; SHA-1 is acceptable here
// because the AIK is a restricted key: the TPM signs only structures it generated itself, and the
// caller controls at most the 64 bytes of qualifyingData in them, far too little for a collision.
const SIGNATURE_ALGS = { '-257': 'SHA-256', '-65535': 'SHA-1' };
const MAX_CHAIN = 5;
const MAX_PART_BYTES = 8192;
const SKEW_MS = 5 * 60 * 1000;

const invalid = message => new ApiError(400, 'invalid_attestation', `TPM attestation rejected: ${message}`);
const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const equalBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const digest = async (hash, bytes) => new Uint8Array(await crypto.subtle.digest(hash, bytes));

/** The root certificate's SubjectPublicKeyInfo (DER). */
export function microsoftTpmRootSpki() { return parseCertificate(fromBase64(MICROSOFT_TPM_ROOT)).spki; }

/** A cursor over TPM's big-endian marshalled structures. */
export function reader(bytes) {
  let offset = 0;
  const take = n => {
    if (offset + n > bytes.length) throw new Error('truncated');
    const out = bytes.subarray(offset, offset + n); offset += n; return out;
  };
  const u16 = () => { const b = take(2); return (b[0] << 8) | b[1]; };
  const u32 = () => { const b = take(4); return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0; };
  return { take, u16, u32, sized: () => take(u16()), done: () => offset === bytes.length };
}

/**
 * TPMT_PUBLIC of an RSA or ECC key: { type: 'rsa'|'ecc', nameAlg, attributes, scheme, and
 * curve, x, y (ECC) or modulus, exponent (RSA) }. Other key types are refused.
 */
export function parseTpmPublic(bytes) {
  const r = reader(bytes);
  const type = r.u16();
  if (type !== ALG.ecc && type !== ALG.rsa) throw new Error('the key is neither an RSA nor an ECC key');
  const nameAlg = r.u16();
  const attributes = r.u32();
  r.sized(); // authPolicy
  const symmetric = r.u16();
  if (symmetric !== ALG.null) { r.u16(); r.u16(); } // keyBits, mode
  const scheme = r.u16();
  if (scheme !== ALG.null) r.u16(); // hashAlg
  let out;
  if (type === ALG.ecc) {
    const curve = r.u16();
    const kdf = r.u16();
    if (kdf !== ALG.null) r.u16();
    out = { type: 'ecc', nameAlg, attributes, scheme, curve, x: r.sized(), y: r.sized() };
  } else {
    r.u16(); // keyBits (the modulus says it)
    const exponent = r.u32();
    out = { type: 'rsa', nameAlg, attributes, scheme, exponent: exponent || 65537, modulus: r.sized() };
  }
  if (!r.done()) throw new Error('trailing bytes in pubArea');
  return out;
}

/** TPMT_PUBLIC of an ECC key: { nameAlg, attributes, curve, x, y }. RSA and others are refused. */
export function parsePubArea(bytes) {
  if (bytes.length >= 2 && ((bytes[0] << 8) | bytes[1]) === ALG.rsa) throw new Error('the key is an RSA key, not P-256');
  const pub = parseTpmPublic(bytes);
  if (pub.type !== 'ecc') throw new Error('the key is not an ECC key');
  return pub;
}

/** A TPM object's name: nameAlg ‖ H_nameAlg(TPMT_PUBLIC). */
export async function tpmObjectName(pubAreaBytes, nameAlg) {
  const hash = NAME_ALGS[nameAlg];
  if (!hash) throw new Error('the key name must use SHA-256, SHA-384 or SHA-512');
  return concat(Uint8Array.of(nameAlg >> 8, nameAlg & 255), await digest(hash, pubAreaBytes));
}

/** TPMS_ATTEST of a TPM2_Certify: { extraData, name }. */
export function parseCertInfo(bytes) {
  const r = reader(bytes);
  if (r.u32() !== TPM_GENERATED) throw new Error('certInfo is not TPM-generated');
  if (r.u16() !== ST_ATTEST_CERTIFY) throw new Error('certInfo is not a certify result');
  r.sized(); // qualifiedSigner
  const extraData = r.sized();
  r.take(17); // clockInfo: clock, resetCount, restartCount, safe
  r.take(8); // firmwareVersion
  const name = r.sized();
  r.sized(); // qualifiedName
  if (!r.done()) throw new Error('trailing bytes in certInfo');
  return { extraData, name };
}

/** The TPM manufacturer id (e.g. "NTC", "IFX", "INTC") from an AIK certificate's SAN, or null. */
export function tpmManufacturer(san) {
  for (const general of children(expectTag(parseOne(san), 16, 'SubjectAltName'))) {
    if (general.cls !== 2 || general.tag !== 4) continue; // directoryName
    for (const rdn of children(expectTag(children(general)[0], 16, 'Name'))) {
      for (const attribute of children(rdn)) {
        const [type, value] = children(attribute);
        if (decodeOid(type) !== TPM_MANUFACTURER) continue;
        const match = /^id:([0-9A-Fa-f]{8})$/.exec(new TextDecoder().decode(value.content));
        if (!match) throw new Error('malformed TPM manufacturer');
        const ascii = match[1].match(/../g).map(h => parseInt(h, 16)).filter(c => c !== 0).map(c => String.fromCharCode(c)).join('').trim();
        return /^[A-Za-z0-9 ]{1,4}$/.test(ascii) ? ascii : `id:${match[1].toUpperCase()}`;
      }
    }
  }
  return null;
}

/** Check the AIK certificate's TPM profile (WebAuthn §8.3.1). Returns the TPM manufacturer. */
function checkAikCertificate(aik) {
  const eku = aik.extensions.get('2.5.29.37');
  if (!eku || !children(expectTag(parseOne(eku), 16, 'ExtKeyUsage')).some(e => decodeOid(e) === AIK_EKU)) throw invalid('the certificate is not an attestation identity key certificate (EKU 2.23.133.8.3)');
  const constraints = aik.extensions.get('2.5.29.19');
  if (constraints) {
    const [ca] = children(expectTag(parseOne(constraints), 16, 'BasicConstraints'));
    if (ca && ca.tag === 1 && ca.content[0] !== 0) throw invalid('the attestation key certificate must not be a CA');
  }
  const san = aik.extensions.get('2.5.29.17');
  const manufacturer = san ? tpmManufacturer(san) : null;
  if (!manufacturer) throw invalid('the attestation key certificate names no TPM manufacturer');
  return manufacturer;
}

/**
 * Verify a TPM 2.0 key attestation.
 * options: { alg: COSE algorithm of the AIK signature (-257 RS256 or -65535 RS1); x5c: base64
 * certificates, AIK first, root left out; sig, certInfo, pubArea: base64; jwk: the enrolled P-256
 * key; extraData: the qualifyingData the device passed to TPM2_Certify; now (ms); roots:
 * SubjectPublicKeyInfo DERs of trusted roots; revokedSerials: async () => Set of the serials the
 * root's CRL lists, called only once the chain checks out }.
 * Returns the `device.attestation` claim, or throws invalid_attestation.
 */
export async function verifyTpmAttestation({ alg, x5c, sig, certInfo, pubArea, jwk, extraData, now = Date.now(), roots = [microsoftTpmRootSpki()], revokedSerials = async () => new Set() }) {
  const hash = SIGNATURE_ALGS[String(alg)];
  if (!hash) throw invalid('alg must be -257 (RS256) or -65535 (RS1)');
  if (!Array.isArray(x5c) || x5c.length < 1 || x5c.length > MAX_CHAIN || x5c.some(c => typeof c !== 'string' || c.length > MAX_PART_BYTES * 2)) throw invalid(`x5c must list 1–${MAX_CHAIN} base64 certificates, attestation key first`);
  let parts;
  try { parts = [sig, certInfo, pubArea].map(p => { if (typeof p !== 'string' || p.length > MAX_PART_BYTES * 2) throw new Error('not a string'); return fromBase64(p); }); }
  catch { throw invalid('sig, cert_info and pub_area must be base64'); }
  const [signature, certInfoBytes, pubAreaBytes] = parts;
  let certs;
  try { certs = x5c.map(c => parseCertificate(fromBase64(c))); } catch (error) { throw invalid(`unreadable certificate (${error.message})`); }

  // 1. The chain: each certificate signed by the next, the last by a pinned root.
  try {
    for (let i = 0; i < certs.length - 1; i++) if (!await signedBy(certs[i], certs[i + 1].spki)) throw invalid(`certificate ${i} is not signed by the next one`);
    let rooted = false;
    for (const root of roots) rooted = rooted || await signedBy(certs.at(-1), root).catch(() => false);
    if (!rooted) throw invalid('the chain does not end at the Microsoft TPM Root Certificate Authority');
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw invalid(`unverifiable signature (${error.message})`);
  }
  for (const [i, cert] of certs.entries()) {
    if (cert.notBefore > now + SKEW_MS || cert.notAfter < now - SKEW_MS) throw invalid(`certificate ${i} is outside its validity period`);
  }
  // The root's CRL covers what the root signed: the last certificate. (AIK certificates themselves
  // carry no revocation pointer.)
  if ((await revokedSerials()).has(certs.at(-1).serial)) throw invalid('the attestation key\'s CA is revoked by Microsoft');
  let manufacturer;
  try { manufacturer = checkAikCertificate(certs[0]); } catch (error) {
    if (error instanceof ApiError) throw error;
    throw invalid(`unreadable attestation key certificate (${error.message})`);
  }

  // 2. The AIK signed certInfo.
  let signed;
  try {
    const key = await crypto.subtle.importKey('spki', certs[0].spki, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
    signed = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, certInfoBytes);
  } catch (error) { throw invalid(`unverifiable certInfo signature (${error.message})`); }
  if (!signed) throw invalid('the attestation key did not sign certInfo');

  // 3. certInfo certifies exactly pubArea, for our challenge and key.
  let info; let pub;
  try { info = parseCertInfo(certInfoBytes); } catch (error) { throw invalid(`unreadable certInfo (${error.message})`); }
  try { pub = parsePubArea(pubAreaBytes); } catch (error) { throw invalid(`unreadable pubArea (${error.message})`); }
  if (!equalBytes(info.extraData, extraData)) throw invalid('the qualifying data does not match (wrong challenge or key)');
  const nameHash = NAME_ALGS[pub.nameAlg];
  if (!nameHash) throw invalid('the key name must use SHA-256, SHA-384 or SHA-512');
  const name = concat(Uint8Array.of(pub.nameAlg >> 8, pub.nameAlg & 255), await digest(nameHash, pubAreaBytes));
  if (!equalBytes(info.name, name)) throw invalid('certInfo does not name the key in pubArea');

  // 4. pubArea is the enrolled key, generated inside this TPM and unable to leave it.
  if (pub.curve !== ECC_NIST_P256) throw invalid('the key is not P-256');
  const pad = b => { const out = new Uint8Array(32); out.set(b.subarray(Math.max(0, b.length - 32)), 32 - Math.min(32, b.length)); return out; };
  if (pub.x.length > 32 || pub.y.length > 32 || !equalBytes(pad(pub.x), unb64u(jwk.x)) || !equalBytes(pad(pub.y), unb64u(jwk.y))) throw invalid('the attested key is not the enrolled key');
  for (const [label, bit] of Object.entries(REQUIRED_ATTRIBUTES)) {
    if (!(pub.attributes & bit)) throw invalid(`the key lacks the ${label} attribute (it must be generated in the TPM, unable to leave it, and a signing key)`);
  }
  return { format: 'tpm', security_level: 'tpm', tpm_manufacturer: manufacturer };
}

/**
 * Parse a DER CertificateList and check it was signed by one of `roots` and is current. Returns
 * the revoked serials (lowercase hex, as parseCertificate reports them).
 */
export async function parseTpmCrl(der, roots, now = Date.now()) {
  const [tbs, sigAlg, sigValue] = children(expectTag(parseOne(der), 16, 'CertificateList'));
  const fields = children(expectTag(tbs, 16, 'TBSCertList'));
  let i = fields[0].tag === 2 ? 1 : 0; // version
  i += 2; // signature algorithm, issuer
  i++; // thisUpdate
  const nextUpdate = fields[i] && (fields[i].tag === 0x17 || fields[i].tag === 0x18) ? decodeTime(fields[i++]) : null;
  const serials = new Set();
  if (fields[i] && fields[i].cls === 0 && fields[i].tag === 16) {
    for (const entry of children(fields[i])) serials.add(integerHex(children(entry)[0]));
  }
  const bitsValue = expectTag(sigValue, 3, 'BIT STRING').content;
  const crl = { tbs: tbs.raw, signatureAlgorithm: decodeOid(children(sigAlg)[0]), signature: bitsValue.subarray(1) };
  let signed = false;
  for (const root of roots) signed = signed || await signedBy(crl, root).catch(() => false);
  if (!signed) throw new Error('CRL is not signed by a trusted root');
  if (nextUpdate === null || nextUpdate + CRL_GRACE_MS < now) throw new Error('CRL is out of date');
  return serials;
}

let crlCache = null;

/**
 * Serials of AIK CAs Microsoft's TPM root has revoked. Cached per isolate for an hour and at the
 * edge; failures are thrown, so enrollment fails closed (as for Google's list).
 */
export async function tpmRevokedSerials(roots, fetcher = fetch, now = Date.now()) {
  if (crlCache && crlCache.until > now) return crlCache.serials;
  const response = await fetcher(MICROSOFT_TPM_CRL_URL, { cf: { cacheTtl: 3600, cacheEverything: true } });
  if (!response.ok) throw new Error(`TPM root CRL: HTTP ${response.status}`);
  const serials = await parseTpmCrl(new Uint8Array(await response.arrayBuffer()), roots, now);
  crlCache = { serials, until: now + 3600_000 };
  return serials;
}
export function resetTpmCrlCache() { crlCache = null; }

/** The qualifying data a device passes to TPM2_Certify when enrolling the key with this thumbprint. */
export const tpmQualifyingData = async (challenge, jkt) => digest('SHA-256', new TextEncoder().encode(`${challenge}.${jkt}`));
