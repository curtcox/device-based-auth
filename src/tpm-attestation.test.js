import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifyTpmAttestation, microsoftTpmRootSpki, MICROSOFT_TPM_ROOT_SPKI_SHA256, parsePubArea, parseTpmCrl } from './services/tpm-attestation.js';
import { parseCertificate, requireCaChain } from './services/attestation.js';
import { tpmAuthority, tpmAttestation, tpmCrl, eccPubArea, certInfoFor } from '../test-utils/tpm-attestation.js';
import { certificate, ext, spkiOf } from '../test-utils/android-attestation.js';
import { seq, set, oid, utf8, tlv, bool, smallInt, bits } from './services/der.js';
import { b64u } from '../packages/verify/src/jose.js';

const fixtures = JSON.parse(readFileSync(new URL('./services/testdata/tpm-windows-hello.json', import.meta.url)));
const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const sha256b64 = async bytes => btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))));
const code = promise => promise.then(() => 'ok', e => `${e.code}: ${e.message}`);
// The recorded attestations' AIK certificates were all valid in early 2025.
const FIXTURE_TIME = Date.UTC(2025, 1, 1);

/** The P-256 JWK in a recorded pubArea (the "enrolled key" for the real attestations). */
const jwkOf = pubArea => { const { x, y } = parsePubArea(fromBase64(pubArea)); return { kty: 'EC', crv: 'P-256', x: b64u(x), y: b64u(y) }; };
const fixtureInput = f => ({ alg: f.alg, x5c: f.x5c, sig: f.sig, certInfo: f.cert_info, pubArea: f.pub_area, extraData: fromBase64(f.extra_data), now: FIXTURE_TIME });

describe('TPM attestation with real Windows attestations', () => {
  it('pins the Microsoft TPM root by its public key', async () => {
    expect(await sha256b64(microsoftTpmRootSpki())).toBe(MICROSOFT_TPM_ROOT_SPKI_SHA256);
  });

  it('accepts a P-256 key certified by a Microsoft-issued AIK (RS1) and names the TPM maker', async () => {
    const f = fixtures.ecc;
    expect(await verifyTpmAttestation({ ...fixtureInput(f), jwk: jwkOf(f.pub_area) })).toEqual({ format: 'tpm', security_level: 'tpm', tpm_manufacturer: 'NTC' });
  });

  it('refuses it for another key, qualifying data, time, root or signature', async () => {
    const f = fixtures.ecc;
    const base = { ...fixtureInput(f), jwk: jwkOf(f.pub_area) };
    const tampered = fromBase64(f.cert_info); tampered[40] ^= 1;
    const cases = {
      'another key': [{ jwk: { ...base.jwk, x: base.jwk.y } }, 'not the enrolled key'],
      'another challenge': [{ extraData: new Uint8Array(20) }, 'qualifying data does not match'],
      'expired certificate': [{ now: Date.UTC(2027, 6, 1) }, 'outside its validity period'],
      'untrusted root': [{ roots: [(await tpmAuthority()).rootSpki] }, 'Microsoft TPM Root'],
      'tampered certInfo': [{ certInfo: btoa(String.fromCharCode(...tampered)) }, 'did not sign certInfo'],
      'unknown alg': [{ alg: -7 }, 'alg must be'],
      'no certificates': [{ x5c: [] }, 'x5c must list'],
      'garbage sig': [{ sig: '!!' }, 'must be base64']
    };
    for (const [label, [override, message]] of Object.entries(cases)) {
      const result = await code(verifyTpmAttestation({ ...base, ...override }));
      expect(result, label).toMatch(/^invalid_attestation: /);
      expect(result, label).toContain(message);
    }
  });

  it('refuses an RSA device key, which a DBA credential cannot use', async () => {
    const f = fixtures.rsa;
    const result = await code(verifyTpmAttestation({ ...fixtureInput(f), jwk: jwkOf(fixtures.ecc.pub_area) }));
    expect(result).toContain('RSA key');
  });
});

describe('TPM attestation, synthetic chains', () => {
  let authority; let jwk;
  const extraData = new Uint8Array(32).fill(7);
  beforeAll(async () => {
    authority = await tpmAuthority();
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  });
  const verify = async (overrides = {}, input = {}) => {
    const a = await tpmAttestation(authority, jwk, extraData, overrides);
    return verifyTpmAttestation({ alg: a.alg, x5c: a.x5c, sig: a.sig, certInfo: a.cert_info, pubArea: a.pub_area, jwk, extraData, roots: [authority.rootSpki], ...input });
  };

  it('accepts a well-formed attestation (RS256)', async () => {
    expect(await verify()).toEqual({ format: 'tpm', security_level: 'tpm', tpm_manufacturer: 'NTC' });
  });

  it('refuses keys that could leave the TPM, were imported, or cannot sign', async () => {
    expect(await code(verify({ attributes: 0x00040070 }))).toContain('fixedTPM');
    expect(await code(verify({ attributes: 0x00040062 }))).toContain('fixedParent');
    expect(await code(verify({ attributes: 0x00040052 }))).toContain('sensitiveDataOrigin');
    expect(await code(verify({ attributes: 0x00020072 }))).toContain('sign');
    expect(await code(verify({ curve: 0x0004 }))).toContain('not P-256');
  });

  it('refuses certInfo for another key and AIK certificates without the TPM profile', async () => {
    const other = await tpmAttestation(authority, jwk, extraData);
    const otherPub = fromBase64(other.pub_area); otherPub[5] ^= 0x01; // another attribute set, so another name
    expect(await code(verify({ certifiedPubArea: otherPub }))).toContain('does not name the key');
    expect(await code(verify({ eku: '1.3.6.1.5.5.7.3.2' }))).toContain('EKU 2.23.133.8.3');
    expect(await code(verify({ ca: true }))).toContain('basicConstraints with cA false');
    expect(await code(verify({ manufacturer: null }))).toContain('no TPM manufacturer');
    expect(await code(verify({ manufacturer: 'NTC' }))).toContain('malformed TPM manufacturer');
  });

  it('refuses a certificate issued by an attestation key (a TPM signs any TBS) for a software key', async () => {
    // A real AIK certificate whose key the attacker can use (a restricted TPM key signs data that
    // does not start with TPM_GENERATED, and a TBSCertificate starts with 0x30).
    const rsa = { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' };
    const tcg = (id, v) => set(seq(oid(id), utf8(v)));
    const san = ext('2.5.29.17', seq(tlv(0xa4, seq(tcg('2.23.133.2.1', 'id:4E544300')))), true);
    const from = Date.UTC(2025, 0, 1); const to = Date.UTC(2045, 0, 1);
    const aik = await crypto.subtle.generateKey(rsa, true, ['sign', 'verify']);
    const aikCert = await certificate({ serial: Uint8Array.of(0x31), issuer: 'Test AIK CA', subject: 'AIK', spki: await spkiOf(aik.publicKey), signer: authority.interSigner, notBefore: from, notAfter: to, extensions: [ext('2.5.29.19', seq(), true), ext('2.5.29.37', seq(oid('2.23.133.8.3'))), san] });
    const soft = await crypto.subtle.generateKey(rsa, true, ['sign', 'verify']);
    const softSpki = await spkiOf(soft.publicKey);
    const forged = await certificate({ serial: Uint8Array.of(0x41), issuer: 'AIK', subject: 'forged', spki: softSpki, signer: { kind: 'rsa', privateKey: aik.privateKey }, notBefore: from, notAfter: to, extensions: [ext('2.5.29.19', seq(), true), ext('2.5.29.37', seq(oid('2.23.133.8.3'))), san] });
    const pubArea = eccPubArea(fromBase64(jwk.x.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - jwk.x.length % 4) % 4)), fromBase64(jwk.y.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - jwk.y.length % 4) % 4)));
    const certInfo = await certInfoFor(pubArea, extraData);
    const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', soft.privateKey, certInfo));
    const b64 = bytes => btoa(String.fromCharCode(...bytes));
    const input = x5c => verifyTpmAttestation({ alg: -257, x5c: x5c.map(b64), sig: b64(sig), certInfo: b64(certInfo), pubArea: b64(pubArea), jwk, extraData, roots: [authority.rootSpki] });
    expect(await code(input([forged, aikCert, authority.interCert]))).toContain('certificate 1 is not a CA certificate');
    // The same check covers keyUsage and pathLenConstraint on real CAs.
    const caWith = async extensions => certificate({ serial: Uint8Array.of(0x32), issuer: 'Test AIK CA', subject: 'AIK', spki: await spkiOf(aik.publicKey), signer: authority.interSigner, notBefore: from, notAfter: to, extensions });
    expect(await code(input([forged, await caWith([ext('2.5.29.19', seq(bool(true)), true), ext('2.5.29.15', bits(Uint8Array.of(0x80)), true)]), authority.interCert]))).toContain('may not sign certificates');
  });

  it('enforces basicConstraints and pathLenConstraint on every certificate above the leaf', () => {
    const cert = (...items) => ({ extensions: new Map(items.length ? [['2.5.29.19', seq(...items)]] : []) });
    const leaf = { extensions: new Map() };
    const check = certs => { try { requireCaChain(certs); return 'ok'; } catch (error) { return error.message; } };
    expect(check([leaf, cert(bool(true)), cert(bool(true))])).toBe('ok');
    expect(check([leaf, cert(bool(true), smallInt(0)), cert(bool(true))])).toBe('ok');
    expect(check([leaf, cert(bool(true)), cert(bool(true), smallInt(0))])).toContain('certificate 2 allows a shorter chain');
    expect(check([leaf, cert()])).toContain('certificate 1 is not a CA certificate');
    expect(check([leaf, cert(bool(false))])).toContain('not a CA');
    expect(check([leaf, { extensions: new Map([['2.5.29.19', oid('1.2.3')]]) }])).toContain('unreadable constraints');
  });

  it('refuses an attestation key certificate without basicConstraints (WebAuthn §8.3.1)', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' }, true, ['sign', 'verify']);
    const tcg = (id, v) => set(seq(oid(id), utf8(v)));
    const san = ext('2.5.29.17', seq(tlv(0xa4, seq(tcg('2.23.133.2.1', 'id:4E544300')))), true);
    const leaf = await certificate({ serial: Uint8Array.of(0x33), issuer: 'Test AIK CA', subject: 'AIK', spki: await spkiOf(pair.publicKey), signer: authority.interSigner, notBefore: Date.UTC(2025, 0, 1), notAfter: Date.UTC(2045, 0, 1), extensions: [ext('2.5.29.37', seq(oid('2.23.133.8.3'))), san] });
    const a = await tpmAttestation(authority, jwk, extraData);
    const b64 = bytes => btoa(String.fromCharCode(...bytes));
    expect(await code(verifyTpmAttestation({ alg: a.alg, x5c: [b64(leaf), ...a.x5c.slice(1)], sig: a.sig, certInfo: a.cert_info, pubArea: a.pub_area, jwk, extraData, roots: [authority.rootSpki] }))).toContain('basicConstraints with cA false');
  });

  it('refuses a chain that does not reach the trusted root', async () => {
    expect(await code(verify({}, { roots: [microsoftTpmRootSpki()] }))).toContain('Microsoft TPM Root');
  });
});

describe('Microsoft TPM root CRL', () => {
  const crl = new Uint8Array(readFileSync(new URL('./services/testdata/microsoft-tpm-root-2026-11.crl', import.meta.url)));
  const CRL_TIME = Date.UTC(2026, 10, 18); // published 2026-11-09, next update 2027-02-08

  it('reads the real CRL, signed by the pinned root', async () => {
    const serials = await parseTpmCrl(crl, [microsoftTpmRootSpki()], CRL_TIME);
    expect(serials.size).toBe(178);
    expect(serials.has('330000015e34399d0c39e51d2900000000015e')).toBe(true);
    // The AIK CA of the recorded Windows attestation is not revoked.
    const aikCa = parseCertificate(fromBase64(fixtures.ecc.x5c[1]));
    expect(serials.has(aikCa.serial)).toBe(false);
  });

  it('refuses a CRL from another root or a stale one', async () => {
    await expect(parseTpmCrl(crl, [(await tpmAuthority()).rootSpki], CRL_TIME)).rejects.toThrow(/not signed by a trusted root/);
    await expect(parseTpmCrl(crl, [microsoftTpmRootSpki()], Date.UTC(2027, 1, 20))).rejects.toThrow(/out of date/);
    const tampered = crl.slice(); tampered[300] ^= 1;
    await expect(parseTpmCrl(tampered, [microsoftTpmRootSpki()], CRL_TIME)).rejects.toThrow();
  });

  it('refuses an attestation whose AIK CA the root revoked, after the chain checks out', async () => {
    const f = fixtures.ecc;
    const aikCa = parseCertificate(fromBase64(f.x5c[1]));
    const result = await code(verifyTpmAttestation({ ...fixtureInput(f), jwk: jwkOf(f.pub_area), revokedSerials: async () => new Set([aikCa.serial]) }));
    expect(result).toContain('revoked by Microsoft');
    let asked = false;
    await code(verifyTpmAttestation({ ...fixtureInput(f), jwk: jwkOf(f.pub_area), roots: [(await tpmAuthority()).rootSpki], revokedSerials: async () => { asked = true; return new Set(); } }));
    expect(asked).toBe(false);
  });

  it('reads test CRLs with and without entries', async () => {
    const authority = await tpmAuthority();
    expect([...await parseTpmCrl(await tpmCrl(authority, ['21', '0a0b']), [authority.rootSpki])]).toEqual(['21', 'a0b']);
    expect((await parseTpmCrl(await tpmCrl(authority), [authority.rootSpki])).size).toBe(0);
  });
});
