import { describe, it, expect, beforeEach } from 'vitest';
import { price } from './utils/pricing.js';
import { X509Certificate } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';
import { inspectCredential } from '../packages/verify/src/index.js';
import { integer, oid } from './services/x509.js';

const hasOpenssl = spawnSync('openssl', ['version']).status === 0;
let env;
beforeEach(async () => { env = await testEnv(); await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } }); });

async function certificateFor(body) {
  const device = await newDevice();
  const credential = (await enroll(env, 'alice', device)).approve.body.credential;
  const path = '/api/v1/certificate';
  const response = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body });
  return { device, credential, response };
}

describe('X.509 client certificates (B3)', () => {
  it('encodes DER integers and object identifiers', () => {
    expect([...integer(Uint8Array.of(0x80))]).toEqual([2, 2, 0, 0x80]);
    expect([...integer(Uint8Array.of(0, 0, 5))]).toEqual([2, 1, 5]);
    expect([...oid('1.2.840.10045.2.1')]).toEqual([6, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1]);
  });

  it('issues a certificate for the device key, chained to the published CA', async () => {
    const { device, credential, response } = await certificateFor({ lifetime_seconds: 600 });
    expect(response.status).toBe(200);
    expect(response.body.cost_microdollars).toBe(price('token'));
    const { payload } = inspectCredential(credential);
    const leaf = new X509Certificate(response.body.certificate);
    const bundle = await call(env, 'GET', '/.well-known/dba-ca.pem');
    expect(bundle.headers.get('Content-Type')).toBe('application/x-pem-file');
    const ca = new X509Certificate(bundle.body);
    expect(ca.ca).toBe(true);
    expect(response.body.ca).toBe(bundle.body);
    expect(leaf.checkIssued(ca)).toBe(true);
    expect(leaf.verify(ca.publicKey)).toBe(true);
    expect(ca.verify(ca.publicKey)).toBe(true);
    expect(leaf.ca).toBe(false);
    expect(leaf.subject).toContain(`CN=${payload.sub}`);
    expect(leaf.subjectAltName).toBe(`URI:urn:devicebasedauth:device:${payload.sub}, URI:urn:devicebasedauth:credential:${payload.cid}, URI:urn:devicebasedauth:account:alice`);
    expect(leaf.keyUsage).toEqual(['1.3.6.1.5.5.7.3.2']);
    expect(leaf.serialNumber.toLowerCase()).toBe(response.body.serial);
    // The certified key is the device's own.
    const jwk = leaf.publicKey.export({ format: 'jwk' });
    expect({ x: jwk.x, y: jwk.y }).toEqual({ x: device.publicJwk.x, y: device.publicJwk.y });
    const lifetime = (Date.parse(leaf.validTo) - Date.parse(leaf.validFrom)) / 1000;
    expect(lifetime).toBe(660); // 600 s plus 60 s of back-dating for clock skew

    if (hasOpenssl) {
      const dir = mkdtempSync(join(tmpdir(), 'dba-x509-'));
      writeFileSync(join(dir, 'ca.pem'), bundle.body); writeFileSync(join(dir, 'leaf.pem'), response.body.certificate);
      expect(execFileSync('openssl', ['verify', '-x509_strict', '-purpose', 'sslclient', '-CAfile', join(dir, 'ca.pem'), join(dir, 'leaf.pem')]).toString()).toContain(': OK');
    }
  });

  it('never outlives the credential, and checks the lifetime', async () => {
    expect((await certificateFor({ lifetime_seconds: 86401 })).response.body.code).toBe('invalid_lifetime');
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { lifetime_seconds: 600 })).approve.body.credential;
    const path = '/api/v1/certificate';
    const response = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: { lifetime_seconds: 86400 } });
    expect(Date.parse(response.body.not_after) / 1000).toBe(inspectCredential(credential).payload.exp);
  });

  it('needs the device key, and refuses revoked credentials', async () => {
    expect((await call(env, 'POST', '/api/v1/certificate', { auth: 'alice', body: {} })).status).toBe(403);
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device)).approve.body.credential;
    await call(env, 'DELETE', `/api/v1/credentials/${inspectCredential(credential).payload.cid}`, { auth: 'alice' });
    const path = '/api/v1/certificate';
    expect((await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: {} })).body.code).toBe('revoked');
  });
});
