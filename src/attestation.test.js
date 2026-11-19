import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifyAndroidAttestation, parseCertificate, createChallenge, checkChallenge, androidRevokedSerials, resetRevocationCache, ANDROID_ROOT_SPKI_SHA256 } from './services/attestation.js';
import { exportPublicJwk } from '../packages/verify/src/jose.js';
import { attestationAuthority, attestationChain, forgedChain, applicationId } from '../test-utils/android-attestation.js';

const NOW = Date.UTC(2026, 10, 18);
const challenge = new TextEncoder().encode('test-challenge');
const p256 = () => crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const REASONS = {
  'untrusted root': 'does not end at a Google attestation root', 'another key in the leaf': 'not the enrolled key',
  'wrong challenge': 'challenge does not match', 'software key': 'not in a TEE or StrongBox', 'imported key': 'origin must be GENERATED',
  'not a signing key': 'not a signing key', 'RSA algorithm claimed': 'not an EC key', 'mismatched levels': 'not in a TEE or StrongBox',
  'expired leaf': 'certificate 0 is outside its validity period', 'revoked leaf': 'certificate 0 is revoked by Google',
  'forged leaf signed by an attested key': 'certificate 1 is not a CA certificate', 'too short': 'x5c must list', garbage: 'unreadable certificate'
};
const code = promise => promise.then(() => 'ok', e => `${e.code}: ${e.message}`);

describe('Android key attestation', () => {
  let authority; let device; let jwk; let verify;
  beforeAll(async () => {
    authority = await attestationAuthority();
    device = await p256();
    jwk = await exportPublicJwk(device.publicKey);
    verify = (x5c, extra = {}) => verifyAndroidAttestation({ x5c, jwk, challenge, now: NOW, roots: [authority.rootPin], revoked: new Set(), ...extra });
  });

  it('accepts a StrongBox key generated on a locked, verified device', async () => {
    const claim = await verify(await attestationChain(authority, device.publicKey, { challenge }));
    expect(claim).toEqual({ format: 'android-key', security_level: 'strongbox', attestation_version: 200, device_locked: true, verified_boot: 'verified' });
  });

  it('reports TEE keys and unlocked bootloaders as they are', async () => {
    const claim = await verify(await attestationChain(authority, device.publicKey, { challenge, description: { securityLevel: 1, locked: false, bootState: 2 } }));
    expect(claim).toMatchObject({ security_level: 'tee', device_locked: false, verified_boot: 'unverified' });
  });

  it('names the app that made the key: package and signing certificate digest', async () => {
    const claim = await verify(await attestationChain(authority, device.publicKey, { challenge, description: { application: applicationId() } }));
    expect(claim.app_id).toBe(`android:io.example.app:${'ab'.repeat(32)}`);
  });

  it('names no app when the app identity is ambiguous or unreadable', async () => {
    const two = new Uint8Array(32).fill(0xcd);
    for (const [label, application] of Object.entries({
      'shared UID (two packages)': applicationId({ packages: [['io.example.app', 1], ['io.example.helper', 1]] }),
      'rotated signing key (two digests)': applicationId({ digests: [new Uint8Array(32).fill(0xab), two] }),
      'no signer': applicationId({ digests: [] }),
      'short digest': applicationId({ digests: [new Uint8Array(20)] }),
      'not a package name': applicationId({ packages: [['io.example.app:evil', 1]] }),
      'one-part package': applicationId({ packages: [['app', 1]] }),
      'garbage': Uint8Array.of(1, 2, 3)
    })) {
      const claim = await verify(await attestationChain(authority, device.publicKey, { challenge, description: { application } }));
      expect(claim.app_id, label).toBeUndefined();
      expect(claim.security_level, label).toBe('strongbox');
    }
  });

  it('rejects what it must', async () => {
    const other = await p256();
    const cases = {
      'untrusted root': [await attestationChain(authority, device.publicKey, { challenge }), { roots: ANDROID_ROOT_SPKI_SHA256 }],
      'another key in the leaf': [await attestationChain(authority, other.publicKey, { challenge })],
      'wrong challenge': [await attestationChain(authority, device.publicKey, { challenge: Uint8Array.of(1) })],
      'software key': [await attestationChain(authority, device.publicKey, { challenge, description: { securityLevel: 0 } })],
      'imported key': [await attestationChain(authority, device.publicKey, { challenge, description: { origin: 2 } })],
      'not a signing key': [await attestationChain(authority, device.publicKey, { challenge, description: { purposes: [0, 1] } })],
      'RSA algorithm claimed': [await attestationChain(authority, device.publicKey, { challenge, description: { algorithm: 1 } })],
      'mismatched levels': [await attestationChain(authority, device.publicKey, { challenge, description: { keymasterLevel: 0 } })],
      'expired leaf': [await attestationChain(authority, device.publicKey, { challenge, notAfter: Date.UTC(2026, 0, 1) })],
      'revoked leaf': [await attestationChain(authority, device.publicKey, { challenge, leafSerial: Uint8Array.of(0x0b, 0xad) }), { revoked: new Set(['bad']) }],
      'forged leaf signed by an attested key': [await forgedChain(authority, other, device.publicKey, { challenge })],
      'too short': [[authority.rootCert]],
      'garbage': [['AAAA', 'AAAA']]
    };
    for (const [label, [x5c, extra]] of Object.entries(cases)) {
      const result = await code(verify(x5c?.map?.(c => typeof c === 'string' ? c : btoa(String.fromCharCode(...c))), extra));
      expect(result, label).toMatch(/^invalid_attestation: /);
      expect(result, label).toContain(REASONS[label]);
    }
  });

  it('reads Google\'s published roots and pins exactly their keys', async () => {
    const roots = JSON.parse(readFileSync(new URL('./services/testdata/android-attestation-roots.json', import.meta.url)));
    const pins = [];
    for (const pem of roots) {
      const der = Uint8Array.from(atob(pem.replace(/-----[^-]+-----|\s/g, '')), c => c.charCodeAt(0));
      const cert = parseCertificate(der);
      pins.push(btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', cert.spki)))));
    }
    expect(pins.sort()).toEqual([...ANDROID_ROOT_SPKI_SHA256].sort());
  });
});

describe('attestation challenges', () => {
  it('round-trips, expires and resists tampering', async () => {
    const { challenge: c } = await createChallenge('k', NOW);
    expect(c).toMatch(/^[\w-]{43}$/);
    await expect(checkChallenge(c, 'k', NOW + 599_000)).resolves.toBeUndefined();
    expect(await code(checkChallenge(c, 'k', NOW + 601_000))).toMatch(/expired/);
    expect(await code(checkChallenge(c, 'other', NOW))).toMatch(/unknown challenge/);
    expect(await code(checkChallenge(`${c.slice(0, 5)}${c[5] === 'A' ? 'B' : 'A'}${c.slice(6)}`, 'k', NOW))).toMatch(/unknown challenge/);
    expect(await code(checkChallenge('short', 'k', NOW))).toMatch(/unknown challenge/);
  });
});

describe('Google revocation list', () => {
  it('normalizes serials, caches for an hour and fails on errors', async () => {
    resetRevocationCache();
    let calls = 0;
    const fetcher = async () => { calls++; return Response.json({ entries: { '0A1b': { status: 'REVOKED' } } }); };
    expect([...await androidRevokedSerials(fetcher, NOW)]).toEqual(['a1b']);
    await androidRevokedSerials(fetcher, NOW + 3599_000);
    expect(calls).toBe(1);
    await expect(androidRevokedSerials(async () => new Response('no', { status: 500 }), NOW + 3601_000)).rejects.toThrow(/HTTP 500/);
    resetRevocationCache();
  });
});
