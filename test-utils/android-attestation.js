// Builds Android Key Attestation chains shaped like real ones, under a test root, so attestation
// can be tested without a phone: P-384 root → RSA-2048 intermediate → leaf for the device key
// with a KeyDescription extension (ASN.1 per the Android Key Attestation schema).
import { seq, set, octets, bits, utf8, bool, explicit, integer, oid, time, smallInt, contextTag } from '../src/services/der.js';

const ENUM = 0x0a;
const name = cn => seq(set(seq(oid('2.5.4.3'), utf8(cn))));
const ext = (id, value, critical = false) => seq(oid(id), ...(critical ? [bool(true)] : []), octets(value));
const b64 = der => btoa(String.fromCharCode(...der));

async function spkiOf(publicKey) { return new Uint8Array(await crypto.subtle.exportKey('spki', publicKey)); }

async function signTbs(tbs, signer) {
  if (signer.kind === 'ec') {
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: signer.hash }, signer.privateKey, tbs));
    const half = raw.length / 2;
    return seq(tbs, seq(oid(signer.hash === 'SHA-384' ? '1.2.840.10045.4.3.3' : '1.2.840.10045.4.3.2')), bits(seq(integer(raw.slice(0, half)), integer(raw.slice(half)))));
  }
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', signer.privateKey, tbs));
  return seq(tbs, seq(oid('1.2.840.113549.1.1.11'), new Uint8Array([5, 0])), bits(sig));
}

async function certificate({ serial, issuer, subject, spki, signer, notBefore, notAfter, extensions = [] }) {
  const algId = signer.kind === 'ec' ? seq(oid(signer.hash === 'SHA-384' ? '1.2.840.10045.4.3.3' : '1.2.840.10045.4.3.2')) : seq(oid('1.2.840.113549.1.1.11'), new Uint8Array([5, 0]));
  const tbs = seq(explicit(0, integer(Uint8Array.of(2))), integer(serial), algId, name(issuer), seq(time(notBefore), time(notAfter)), name(subject), spki,
    ...(extensions.length ? [explicit(3, seq(...extensions))] : []));
  return signTbs(tbs, signer);
}

/** The KeyDescription extension value. Every field can be overridden for negative tests. */
export function keyDescription({ challenge, securityLevel = 2, keymasterLevel = securityLevel, origin = 0, algorithm = 3, curve = 1, purposes = [2], bootState = 0, locked = true, omitRootOfTrust = false, version = 200 }) {
  const hw = [
    contextTag(1, set(...purposes.map(p => smallInt(p)))), contextTag(2, smallInt(algorithm)), contextTag(3, smallInt(256)), contextTag(10, smallInt(curve)),
    contextTag(702, smallInt(origin)),
    ...(omitRootOfTrust ? [] : [contextTag(704, seq(octets(new Uint8Array(32).fill(7)), bool(locked), smallInt(bootState, ENUM), octets(new Uint8Array(32).fill(9))))])
  ];
  return seq(smallInt(version), smallInt(securityLevel, ENUM), smallInt(300), smallInt(keymasterLevel, ENUM), octets(challenge), octets(new Uint8Array(0)), seq(contextTag(709, octets(Uint8Array.of(1, 2, 3)))), seq(...hw));
}

/** A test root and intermediate, made once per test file. */
export async function attestationAuthority() {
  const root = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']);
  const inter = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const rootSpki = await spkiOf(root.publicKey);
  const ca = ext('2.5.29.19', seq(bool(true)), true);
  const from = Date.UTC(2025, 0, 1); const to = Date.UTC(2045, 0, 1);
  const rootSigner = { kind: 'ec', hash: 'SHA-384', privateKey: root.privateKey };
  const rootCert = await certificate({ serial: Uint8Array.of(1), issuer: 'Test attestation root', subject: 'Test attestation root', spki: rootSpki, signer: rootSigner, notBefore: from, notAfter: to, extensions: [ca] });
  const interCert = await certificate({ serial: Uint8Array.of(0x2a, 0x01), issuer: 'Test attestation root', subject: 'Test StrongBox', spki: await spkiOf(inter.publicKey), signer: rootSigner, notBefore: from, notAfter: to, extensions: [ca] });
  const rootPin = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', rootSpki))));
  return { rootPin, rootCert, interCert, interSigner: { kind: 'rsa', privateKey: inter.privateKey }, rootSigner };
}

/** x5c (base64 DER, leaf first) attesting `publicKey`, with optional description overrides. */
export async function attestationChain(authority, publicKey, { challenge, description = {}, leafKey = publicKey, notAfter = Date.UTC(2045, 0, 1), leafSerial = Uint8Array.of(0x10, 0x01) }) {
  const leaf = await certificate({ serial: leafSerial, issuer: 'Test StrongBox', subject: 'Android Keystore Key', spki: await spkiOf(leafKey), signer: authority.interSigner, notBefore: Date.UTC(1970, 0, 1), notAfter, extensions: [ext('1.3.6.1.4.1.11129.2.1.17', keyDescription({ challenge, ...description }))] });
  return [leaf, authority.interCert, authority.rootCert].map(b64);
}

/**
 * The attack the leaf-only rule stops: a genuinely attested signing key (attestedPair) signs a
 * forged leaf claiming StrongBox for another key. Chain: forged leaf, real leaf, intermediate, root.
 */
export async function forgedChain(authority, attestedPair, forgedPublicKey, { challenge }) {
  const [realLeaf, inter, root] = await attestationChain(authority, attestedPair.publicKey, { challenge });
  const forged = await certificate({ serial: Uint8Array.of(0x66), issuer: 'Android Keystore Key', subject: 'Android Keystore Key', spki: await spkiOf(forgedPublicKey), signer: { kind: 'ec', hash: 'SHA-256', privateKey: attestedPair.privateKey }, notBefore: Date.UTC(1970, 0, 1), notAfter: Date.UTC(2045, 0, 1), extensions: [ext('1.3.6.1.4.1.11129.2.1.17', keyDescription({ challenge }))] });
  return [b64(forged), realLeaf, inter, root];
}
