import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifyTpmAttestation, microsoftTpmRootSpki, MICROSOFT_TPM_ROOT_SPKI_SHA256, parsePubArea } from './services/tpm-attestation.js';
import { tpmAuthority, tpmAttestation } from '../test-utils/tpm-attestation.js';
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
    expect(await code(verify({ ca: true }))).toContain('must not be a CA');
    expect(await code(verify({ manufacturer: null }))).toContain('no TPM manufacturer');
    expect(await code(verify({ manufacturer: 'NTC' }))).toContain('malformed TPM manufacturer');
  });

  it('refuses a chain that does not reach the trusted root', async () => {
    expect(await code(verify({}, { roots: [microsoftTpmRootSpki()] }))).toContain('Microsoft TPM Root');
  });
});
