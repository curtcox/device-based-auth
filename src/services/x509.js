// X.509 client certificates for device keys (STATUS B3), for sites that authenticate with mTLS
// (for example Cloudflare API Shield). A certificate is another short-lived form of a credential,
// like an access token: it binds the device's own public key to its device, credential and
// account ids, signed by a CA certificate derived from the issuer key. It carries no grants.
// mTLS cannot see revocation, so certificates live at most 24 hours (default 1 hour).
import { unb64u } from '../../packages/verify/src/jose.js';

const enc = new TextEncoder();
const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };

function length(n) {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes = []; while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}
const tlv = (tag, ...content) => { const body = concat(...content); return concat(Uint8Array.of(tag), length(body.length), body); };
export const seq = (...items) => tlv(0x30, ...items);
const set = (...items) => tlv(0x31, ...items);
const octets = bytes => tlv(0x04, bytes);
const bits = bytes => tlv(0x03, Uint8Array.of(0), bytes);
const utf8 = text => tlv(0x0c, enc.encode(text));
const bool = value => tlv(0x01, Uint8Array.of(value ? 0xff : 0));
const explicit = (n, ...items) => tlv(0xa0 | n, ...items);

/** A non-negative DER INTEGER from big-endian bytes. */
export function integer(bytes) {
  let i = 0; while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const trimmed = bytes.slice(i);
  return tlv(0x02, trimmed[0] & 0x80 ? concat(Uint8Array.of(0), trimmed) : trimmed);
}

export function oid(dotted) {
  const [a, b, ...rest] = dotted.split('.').map(Number);
  const out = [40 * a + b];
  for (let n of rest) { const chunk = [n & 0x7f]; while ((n >>= 7) > 0) chunk.unshift(0x80 | (n & 0x7f)); out.push(...chunk); }
  return tlv(0x06, Uint8Array.from(out));
}

/** UTCTime before 2050, GeneralizedTime after (RFC 5280 §4.1.2.5). */
function time(ms) {
  const d = new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/[-:T]/g, '').replace('.000', '');
  return d.startsWith('20') && Number(d.slice(0, 4)) < 2050 ? tlv(0x17, enc.encode(d.slice(2))) : tlv(0x18, enc.encode(d));
}

const OID = {
  ecPublicKey: '1.2.840.10045.2.1', p256: '1.2.840.10045.3.1.7', ecdsaSha256: '1.2.840.10045.4.3.2',
  cn: '2.5.4.3', o: '2.5.4.10', subjectKeyId: '2.5.29.14', keyUsage: '2.5.29.15', subjectAltName: '2.5.29.17',
  basicConstraints: '2.5.29.19', authorityKeyId: '2.5.29.35', extKeyUsage: '2.5.29.37', clientAuth: '1.3.6.1.5.5.7.3.2'
};
const SIG_ALG = seq(oid(OID.ecdsaSha256));

const name = (cn, org) => seq(set(seq(oid(OID.o), utf8(org))), set(seq(oid(OID.cn), utf8(cn))));
const extension = (id, critical, value) => seq(oid(id), ...(critical ? [bool(true)] : []), octets(value));

/** SubjectPublicKeyInfo for a P-256 public JWK. */
export function spki(jwk) {
  if (jwk?.kty !== 'EC' || jwk.crv !== 'P-256') throw new Error('Only P-256 keys are supported');
  return seq(seq(oid(OID.ecPublicKey), oid(OID.p256)), bits(concat(Uint8Array.of(4), unb64u(jwk.x), unb64u(jwk.y))));
}

/** Key identifier: the first 20 bytes of SHA-256 over the public point (RFC 7093 §2 method 1). */
async function keyId(jwk) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', concat(Uint8Array.of(4), unb64u(jwk.x), unb64u(jwk.y))));
  return digest.slice(0, 20);
}

/** WebCrypto's raw r‖s ECDSA signature as a DER Ecdsa-Sig-Value. */
function derSignature(raw) { return seq(integer(raw.slice(0, 32)), integer(raw.slice(32))); }

async function sign(tbs, privateKey) {
  const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, tbs));
  return seq(tbs, SIG_ALG, bits(derSignature(raw)));
}

export function pem(der, label = 'CERTIFICATE') {
  const base64 = btoa(String.fromCharCode(...der));
  return `-----BEGIN ${label}-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
}

const CA_ORG = 'devicebasedauth.org';
export const caName = kid => `devicebasedauth.org device CA ${kid}`;

/**
 * The CA certificate for one issuer key: self-signed, valid 2026–2046, path length 0. The serial
 * and key identifier are derived from the key, so every isolate makes an equivalent certificate.
 */
export async function caCertificate({ kid, publicJwk, privateKey }) {
  const ski = await keyId(publicJwk);
  const serial = concat(Uint8Array.of(0x01), ski.slice(0, 15));
  const tbs = seq(
    explicit(0, integer(Uint8Array.of(2))), integer(serial), SIG_ALG, name(caName(kid), CA_ORG),
    seq(time(Date.UTC(2026, 0, 1)), time(Date.UTC(2046, 0, 1))), name(caName(kid), CA_ORG), spki(publicJwk),
    explicit(3, seq(
      extension(OID.basicConstraints, true, seq(bool(true), integer(Uint8Array.of(0)))),
      extension(OID.keyUsage, true, tlv(0x03, Uint8Array.of(1, 0x06))), // keyCertSign, cRLSign
      extension(OID.subjectKeyId, false, octets(ski))
    )));
  return sign(tbs, privateKey);
}

/** URIs naming the device, credential and account, put in the certificate's subjectAltName. */
export const deviceUris = ({ sub, cid, acct }) => [`urn:devicebasedauth:device:${sub}`, `urn:devicebasedauth:credential:${cid}`, `urn:devicebasedauth:account:${acct}`];

/**
 * A client certificate for a device key: subject CN is the device id; subjectAltName URIs name
 * the device, credential and account; extended key usage clientAuth only.
 */
export async function deviceCertificate({ devicePublicJwk, payload, notBefore, notAfter, issuer }) {
  const serial = crypto.getRandomValues(new Uint8Array(16)); serial[0] = (serial[0] & 0x7f) | 0x01;
  const tbs = seq(
    explicit(0, integer(Uint8Array.of(2))), integer(serial), SIG_ALG, name(caName(issuer.kid), CA_ORG),
    seq(time(notBefore), time(notAfter)), name(payload.sub, CA_ORG), spki(devicePublicJwk),
    explicit(3, seq(
      extension(OID.basicConstraints, true, seq()),
      extension(OID.keyUsage, true, tlv(0x03, Uint8Array.of(7, 0x80))), // digitalSignature
      extension(OID.extKeyUsage, false, seq(oid(OID.clientAuth))),
      extension(OID.subjectAltName, false, seq(...deviceUris(payload).map(uri => tlv(0x86, enc.encode(uri))))),
      extension(OID.subjectKeyId, false, octets(await keyId(devicePublicJwk))),
      extension(OID.authorityKeyId, false, seq(tlv(0x80, await keyId(issuer.publicJwk))))
    )));
  return { der: await sign(tbs, issuer.privateKey), serial: [...serial].map(b => b.toString(16).padStart(2, '0')).join('') };
}
