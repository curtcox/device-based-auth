import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { startTpmActivation, finishTpmActivation, makeCredential, credentialBlobFile, aesCfbEncrypt, kdfa, verifyEkCertificate, tpmEkAnchors, tpmActivationResponse } from './services/tpm-activation.js';
import { TPM_EK_ANCHORS } from './services/tpm-ek-anchors.js';
import { parseCertificate } from './services/attestation.js';
import { seq, bool } from './services/der.js';
import { certificate, ext, spkiOf } from '../test-utils/android-attestation.js';
import { ekAuthority, softwareTpm, activationRequest, activateCredential, AK_ATTRIBUTES } from '../test-utils/tpm-ek.js';
import { newDevice } from '../test-utils/env.js';
import { jwkThumbprint } from '../packages/verify/src/jose.js';

const fixture = JSON.parse(readFileSync(new URL('./services/testdata/tpm-ek-swtpm.json', import.meta.url)));
const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const hex = text => Uint8Array.from(text.match(/../g), h => parseInt(h, 16));
const toHex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
const code = promise => promise.then(() => 'ok', e => `${e.code}: ${e.message}`);
const anchorOf = der => ({ name: 'test', ...parseCertificate(der) });
const fromFixture = f => ({ ekCertificate: f.ek_certificate, akPubArea: f.ak_pub_area, pubArea: f.pub_area, certInfo: f.cert_info, sig: f.sig, anchors: [anchorOf(fromBase64(f.ek_ca))] });

describe('TPM EK anchors', () => {
  it('holds the manufacturers\' CA certificates, each matching its recorded fingerprint', async () => {
    expect(TPM_EK_ANCHORS.length).toBe(50);
    for (const anchor of TPM_EK_ANCHORS) {
      const fingerprint = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', fromBase64(anchor.der)))).toUpperCase();
      expect(fingerprint, anchor.name).toBe(anchor.sha256);
    }
    const names = tpmEkAnchors().map(a => a.name);
    expect(names).toEqual(expect.arrayContaining(['IFX_RSA_RT', 'INF_RSA_010RT', 'NTC1', 'NUVO_2110', 'STM_RSA_RT', 'GS_TPM_RT', 'INTEL_RT']));
    expect(names.some(n => /alibaba/i.test(n))).toBe(false);
  });
});

describe('credential protection primitives', () => {
  it('AES-CFB128 matches NIST SP 800-38A F.3.13', async () => {
    const out = await aesCfbEncrypt(hex('2b7e151628aed2a6abf7158809cf4f3c'), hex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'), hex('000102030405060708090a0b0c0d0e0f'));
    expect(toHex(out)).toBe('3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b');
    expect((await aesCfbEncrypt(hex('2b7e151628aed2a6abf7158809cf4f3c'), hex('6bc1be'), hex('000102030405060708090a0b0c0d0e0f'))).length).toBe(3);
  });

  it('KDFa truncates to the requested size and depends on every input', async () => {
    const key = new Uint8Array(32).fill(1);
    const a = await kdfa('SHA-256', key, 'STORAGE', Uint8Array.of(1), new Uint8Array(0), 128);
    expect(a.length).toBe(16);
    expect((await kdfa('SHA-256', key, 'STORAGE', Uint8Array.of(1), new Uint8Array(0), 512)).length).toBe(64);
    expect(toHex(await kdfa('SHA-256', key, 'INTEGRITY', Uint8Array.of(1), new Uint8Array(0), 128))).not.toBe(toHex(a));
    expect(toHex(await kdfa('SHA-256', key, 'STORAGE', Uint8Array.of(2), new Uint8Array(0), 128))).not.toBe(toHex(a));
  });
});

describe('EK credential activation with a recorded swtpm TPM', () => {
  it('accepts the real TPM\'s EK certificate, attestation key and certify, naming the manufacturer', async () => {
    const result = await startTpmActivation(fromFixture(fixture));
    expect(result.jkt).toBe(fixture.jkt);
    expect(result.manufacturer).toBe('id:00001014');
    expect(await jwkThumbprint(result.jwk)).toBe(fixture.jkt);
    expect(result.idObject.length).toBe(2 + 32 + 34);
    expect(result.encryptedSecret.length).toBe(256);
  });

  it('wraps a secret exactly as the TPM unwrapped it (fixed seed, recorded result)', async () => {
    const ek = parseCertificate(fromBase64(fixture.ek_certificate));
    const ekKey = await crypto.subtle.importKey('spki', ek.spki, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    const wrapped = await makeCredential(ekKey, fromBase64(fixture.ak_name), fromBase64(fixture.secret), fromBase64(fixture.seed));
    expect(btoa(String.fromCharCode(...wrapped.idObject))).toBe(fixture.id_object);
    const file = credentialBlobFile(wrapped);
    expect(toHex(file.subarray(0, 10))).toBe('badcc0de000000010044');
    expect(file.length).toBe(8 + 2 + 68 + 2 + 256);
  });

  it('refuses the swtpm EK under the real manufacturers\' CAs', async () => {
    expect(await code(startTpmActivation({ ...fromFixture(fixture), anchors: undefined }))).toContain('does not chain to a known TPM manufacturer CA');
  });
});

describe('EK credential activation, software TPM', () => {
  let authority; let tpm; let device; let anchors;
  beforeAll(async () => {
    authority = await ekAuthority();
    tpm = await softwareTpm(authority);
    device = await newDevice();
    anchors = [anchorOf(authority.der)];
  });
  const start = async (overrides = {}, tpmOverride) => {
    const r = await activationRequest(tpmOverride ?? tpm, device.publicJwk, overrides);
    return { request: r, run: () => startTpmActivation({ ekCertificate: r.ek_certificate, akPubArea: r.ak_pub_area, pubArea: r.pub_area, certInfo: r.cert_info, sig: r.sig, anchors }) };
  };

  it('round-trips: the TPM unwraps the secret, and the token finishes the attestation', async () => {
    const { request, run } = await start();
    const result = await run();
    expect(result.jkt).toBe(await jwkThumbprint(device.publicJwk));
    expect(result.manufacturer).toBe('IFX');
    const secret = await activateCredential(tpm, result, request.akName);
    expect(toHex(secret)).toBe(toHex(result.secret));
    let signed;
    const response = await tpmActivationResponse(result, { challenge: 'c1', sign: async payload => { signed = payload; return 'dbatpm_x'; } });
    expect(response).toMatchObject({ activation: 'dbatpm_x', jkt: result.jkt, expires_in: 600 });
    expect(fromBase64(response.credential_blob).length).toBe(8 + 2 + 68 + 2 + 256);
    const secretB64 = btoa(String.fromCharCode(...secret));
    expect(await finishTpmActivation({ payload: signed, challenge: 'c1', secret: secretB64, jkt: result.jkt })).toEqual({ format: 'tpm', security_level: 'tpm', tpm_manufacturer: 'IFX' });
    const finish = overrides => code(finishTpmActivation({ payload: signed, challenge: 'c1', secret: secretB64, jkt: result.jkt, ...overrides }));
    expect(await finish({ secret: btoa('x'.repeat(32)) })).toContain('secret is wrong');
    expect(await finish({ jkt: 'other' })).toContain('another key');
    expect(await finish({ challenge: 'c2' })).toContain('another challenge');
    expect(await finish({ payload: null })).toContain('unknown or has expired');
  });

  it('wraps for the attestation key\'s name only: another object cannot unwrap it', async () => {
    const { run } = await start();
    const result = await run();
    const other = await activationRequest(await softwareTpm(authority), device.publicJwk);
    await expect(activateCredential(tpm, result, other.akName)).rejects.toThrow(/integrity/);
  });

  it('refuses unrestricted, decrypting or exportable attestation keys, and exportable device keys', async () => {
    const cases = {
      'unrestricted AK': [{ akAttributes: AK_ATTRIBUTES & ~(1 << 16) }, 'lacks the restricted attribute'],
      'decrypting AK': [{ akAttributes: AK_ATTRIBUTES | (1 << 17) }, 'must not be a decryption key'],
      'AK not fixedTPM': [{ akAttributes: AK_ATTRIBUTES & ~(1 << 1) }, 'attestation key lacks the fixedTPM'],
      'key not fixedTPM': [{ keyAttributes: 0x00040070 }, 'key lacks the fixedTPM'],
      'tampered certify': [{ tamper: true }, 'did not sign cert_info'],
      'certify of another key': [{ certifiedPubArea: new Uint8Array(10) }, 'does not name the key']
    };
    for (const [label, [override, message]] of Object.entries(cases)) {
      const result = await code((await start(override)).run());
      expect(result, label).toMatch(/^invalid_attestation: /);
      expect(result, label).toContain(message);
    }
  });

  it('refuses EK certificates from unknown CAs, without a manufacturer, or not RSA-2048', async () => {
    expect(await code((await start({}, await softwareTpm(await ekAuthority()))).run())).toContain('does not chain');
    expect(await code((await start({}, await softwareTpm(authority, { manufacturer: null }))).run())).toContain('names no TPM manufacturer');
    expect(await code((await start({}, await softwareTpm(authority, { ekBits: 3072 }))).run())).toContain('RSA-2048');
    expect(await code(verifyEkCertificate('!!', [], anchors))).toContain('must be base64');
  });

  it('follows CA certificates the device sends up to an anchor, but not non-CA ones', async () => {
    const inter = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' }, true, ['sign', 'verify']);
    const build = async ca => certificate({ serial: Uint8Array.of(0x42), issuer: authority.name, subject: 'Test EK Intermediate', spki: await spkiOf(inter.publicKey), signer: authority.signer, notBefore: Date.UTC(2025, 0, 1), notAfter: Date.UTC(2045, 0, 1), extensions: [ext('2.5.29.19', seq(...(ca ? [bool(true)] : [])), true)] });
    const leafTpm = await softwareTpm({ name: 'Test EK Intermediate', signer: { kind: 'rsa', privateKey: inter.privateKey } });
    const ek = btoa(String.fromCharCode(...leafTpm.ekCert));
    const b64 = bytes => btoa(String.fromCharCode(...bytes));
    expect(await code(verifyEkCertificate(ek, [], anchors))).toContain('does not chain');
    expect((await verifyEkCertificate(ek, [b64(await build(true))], anchors)).manufacturer).toBe('IFX');
    expect(await code(verifyEkCertificate(ek, [b64(await build(false))], anchors))).toContain('not a CA certificate');
    expect(await code(verifyEkCertificate(ek, ['a', 'b', 'c', 'd'], anchors))).toContain('at most 3');
  });
});
