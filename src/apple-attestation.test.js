import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifyAppleAttestation, appleRootSpki, APPLE_APP_ATTEST_ROOT, APPLE_ROOT_SPKI_SHA256, appleClientData } from './services/apple-attestation.js';
import { decodeCbor } from './services/cbor.js';
import { appleAuthority, appleAttestation, encodeCbor } from '../test-utils/apple-attestation.js';

const fixtures = JSON.parse(readFileSync(new URL('./services/testdata/apple-appattest.json', import.meta.url)));
const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const sha256b64 = async bytes => btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))));
const code = promise => promise.then(() => 'ok', e => `${e.code}: ${e.message}`);
// The real attestations' certificates were valid in early 2024.
const FIXTURE_TIME = Date.UTC(2024, 2, 1);
const APP = 'ABCDE12345.org.example.wallet';

describe('Apple App Attest with real attestations from Apple', () => {
  for (const environment of ['development', 'production']) {
    it(`accepts the ${environment} attestation and reports its environment`, async () => {
      const f = fixtures[environment];
      const claim = await verifyAppleAttestation({ object: f.attestation, keyId: f.key_id, appId: fixtures.app_id, clientData: fromBase64(f.challenge), now: FIXTURE_TIME });
      expect(claim).toEqual({ format: 'apple-appattest', security_level: 'secure_enclave', app_id: fixtures.app_id, environment });
    });
  }

  it('refuses them for another app, challenge, key id or time', async () => {
    const f = fixtures.production;
    const base = { object: f.attestation, keyId: f.key_id, appId: fixtures.app_id, clientData: fromBase64(f.challenge), now: FIXTURE_TIME };
    const cases = {
      'another app': [{ appId: 'V8H6LQ9448.io.example.other' }, 'for another app'],
      'another challenge': [{ clientData: new TextEncoder().encode('other') }, 'nonce does not match'],
      'another key id': [{ keyId: fixtures.development.key_id }, 'key_id does not match'],
      'expired certificate': [{ now: Date.UTC(2026, 10, 18) }, 'outside its validity period'],
      'untrusted root': [{ roots: [(await appleAuthority()).rootSpki] }, 'Apple App Attestation Root CA'],
      'malformed app id': [{ appId: 'io.example.app' }, 'TEAMID.bundle.id'],
      'garbage object': [{ object: 'AAAA' }, 'unreadable attestation object']
    };
    for (const [label, [override, message]] of Object.entries(cases)) {
      const result = await code(verifyAppleAttestation({ ...base, ...override }));
      expect(result, label).toMatch(/^invalid_attestation: /);
      expect(result, label).toContain(message);
    }
  });

  it('pins exactly the Apple App Attestation Root CA', async () => {
    const der = fromBase64(APPLE_APP_ATTEST_ROOT);
    // The certificate's SHA-256 fingerprint as Apple publishes it.
    const fingerprint = [...new Uint8Array(await crypto.subtle.digest('SHA-256', der))].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    expect(fingerprint).toBe('1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932');
    expect(await sha256b64(appleRootSpki())).toBe(APPLE_ROOT_SPKI_SHA256);
  });
});

describe('Apple App Attest checks (synthetic chains)', () => {
  let authority; let roots;
  const clientData = appleClientData('challenge', 'thumbprint');
  beforeAll(async () => { authority = await appleAuthority(); roots = [authority.rootSpki]; });
  const verify = async (options = {}, extra = {}) => {
    const { object, keyId } = await appleAttestation(authority, { appId: APP, clientData, ...options });
    return code(verifyAppleAttestation({ object, keyId, appId: APP, clientData, now: Date.UTC(2026, 10, 18), roots, ...extra }));
  };

  it('accepts a well-formed attestation', async () => {
    expect(await verify()).toBe('ok');
    const { object, keyId } = await appleAttestation(authority, { appId: APP, clientData, environment: 'development' });
    expect(await verifyAppleAttestation({ object, keyId, appId: APP, clientData, now: Date.UTC(2026, 10, 18), roots })).toMatchObject({ environment: 'development' });
  });

  it('rejects what it must', async () => {
    const cases = {
      'nonzero counter': [{ counter: 1 }, 'counter must be 0'],
      'unknown environment': [{ environment: 'somethingelse!!!' }, 'unknown App Attest environment'],
      'nonce for other data': [{ nonceFor: new TextEncoder().encode('x') }, 'nonce does not match'],
      'credential id is not the key id': [{ credentialId: new Uint8Array(32) }, 'credential id is not the key id'],
      'rpId for another app': [{ rpId: 'ABCDE12345.org.example.other' }, 'for another app'],
      'key id of another key': [{ keyId: new Uint8Array(32).fill(1) }, 'key_id does not match'],
      'expired leaf': [{ notAfter: Date.UTC(2026, 0, 1) }, 'certificate 0 is outside its validity period']
    };
    for (const [label, [options, message]] of Object.entries(cases)) {
      const result = await verify(options);
      expect(result, label).toMatch(/^invalid_attestation: /);
      expect(result, label).toContain(message);
    }
    expect(await verify({}, { keyId: btoa('short') })).toContain('key_id must be 32 bytes');
  });

  it('refuses a chain whose intermediate is not under the root', async () => {
    const other = await appleAuthority();
    const { object, keyId } = await appleAttestation(other, { appId: APP, clientData });
    expect(await code(verifyAppleAttestation({ object, keyId, appId: APP, clientData, now: Date.UTC(2026, 10, 18), roots }))).toContain('Apple App Attestation Root CA');
  });
});

describe('CBOR decoder', () => {
  it('round-trips what attestation objects use', () => {
    const value = decodeCbor(encodeCbor(new Map([['a', [1, 300, 70000, 'x']], ['b', Uint8Array.of(1, 2)], [3, 'c']])));
    expect(value.get('a')).toEqual([1, 300, 70000, 'x']);
    expect([...value.get('b')]).toEqual([1, 2]);
    expect(value.get(3)).toBe('c');
    expect(decodeCbor(Uint8Array.of(0x20))).toBe(-1);
    expect(decodeCbor(Uint8Array.of(0xf5))).toBe(true);
  });

  it('refuses truncated, trailing, indefinite, tagged, duplicate and deep input', () => {
    for (const bad of [[0x62, 0x61], [0x01, 0x01], [0x5f], [0xc0, 0x01], [0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02], Array(40).fill(0x81).concat([0x01]), [0xfb, 0, 0, 0, 0, 0, 0, 0, 0]]) {
      expect(() => decodeCbor(Uint8Array.from(bad)), JSON.stringify(bad.slice(0, 4))).toThrow(/malformed CBOR/);
    }
  });
});
