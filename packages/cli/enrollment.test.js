import { describe, it, expect } from 'vitest';
import { UsageError, ApiError } from './errors.js';
import { secondsOption } from './args.js';
import { audiencesFromOption, grantsFromOptions, enrollmentPayload, signEnrollmentRequest, rotationProof, pollEnrollment } from './enrollment.js';
import { newDeviceKey, keyFile, loadDeviceKey, deviceHeaders } from './device-key.js';
import { verifyJws, verifyProof, inspectCredential, jwkThumbprint, sha256b64u } from '../verify/src/index.js';

describe('enrollment requests', () => {
  it('collects audiences from repeated and comma-separated --aud', () => {
    expect(audiencesFromOption(['hashbin.org,cronly.org', 'hashbin.org'])).toEqual(['hashbin.org', 'cronly.org']);
    expect(() => audiencesFromOption([])).toThrow(/--aud/);
  });

  it('builds grants from --action and --grant, and checks them locally', () => {
    expect(grantsFromOptions({ action: ['hashbin:content:write', 'hashbin:content:extend'] })).toEqual([{ actions: ['hashbin:content:write', 'hashbin:content:extend'] }]);
    const weekdays = { actions: ['cronly:run'], when: { tz: 'America/Chicago', windows: [{ days: ['mon'], from: '08:00', to: '18:00' }] } };
    expect(grantsFromOptions({ grant: [JSON.stringify(weekdays), JSON.stringify([{ actions: ['a:b'] }])], action: ['c:d'] })).toEqual([weekdays, { actions: ['a:b'] }, { actions: ['c:d'] }]);
    expect(() => grantsFromOptions({ grant: ['{nope'] })).toThrow(/not valid JSON/);
    expect(() => grantsFromOptions({ grant: ['{"actions":["a:b"],"colour":"red"}'] })).toThrow(/Invalid grants/);
    expect(() => grantsFromOptions({})).toThrow(/--action/);
  });

  it('parses whole seconds only', () => {
    expect(secondsOption(undefined, 'wait')).toBeUndefined();
    expect(secondsOption('3600', 'lifetime')).toBe(3600);
    for (const bad of ['0', '-5', '1.5', '1h']) expect(() => secondsOption(bad, 'lifetime')).toThrow(UsageError);
  });

  it('signs a request with the new key, which the server can verify from the header alone', async () => {
    const key = await newDeviceKey();
    const payload = enrollmentPayload({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], name: 'Laptop', lifetime: 3600, now: 1800000000 });
    expect(payload).toEqual({ iat: 1800000000, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], device: { name: 'Laptop', kind: 'cli', key_protection: 'software' }, lifetime_seconds: 3600 });
    const jws = await signEnrollmentRequest(key, payload);
    const { header } = inspectCredential(jws);
    expect(header).toEqual({ typ: 'dba-enroll+jwt', jwk: key.publicJwk, alg: 'ES256' });
    expect((await verifyJws(jws, header.jwk)).payload).toEqual(payload);
    expect(() => enrollmentPayload({ aud: ['a'], grants: [], kind: 'toaster' })).toThrow(/--kind/);
  });

  it('round-trips the key through key.json without keeping anything but the key', async () => {
    const key = await newDeviceKey();
    const file = JSON.parse(JSON.stringify(keyFile(key, new Date(0))));
    expect(Object.keys(file.private_jwk).sort()).toEqual(['crv', 'd', 'kty', 'x', 'y']);
    expect(file).toMatchObject({ public_jwk: key.publicJwk, key_protection: 'software', created_at: '1970-01-01T00:00:00.000Z' });
    const loaded = await loadDeviceKey(file);
    expect(loaded.publicJwk).toEqual(key.publicJwk);
    const proof = await rotationProof(loaded, 'crd_ABCDEFGH', 1800000000);
    expect((await verifyJws(proof, key.publicJwk)).payload).toEqual({ cid: 'crd_ABCDEFGH', iat: 1800000000 });
    expect(inspectCredential(proof).header).toMatchObject({ typ: 'dba-rotate+jwt', jwk: key.publicJwk });
    await expect(loadDeviceKey({ public_jwk: key.publicJwk })).rejects.toThrow(/no private key/);
  });

  it('says where the key lives in the enrollment request', () => {
    expect(enrollmentPayload({ aud: ['a.org'], grants: [{ actions: ['a:b'] }], keyProtection: 'os-keychain' }).device.key_protection).toBe('os-keychain');
  });

  it('binds request headers to the method, URL and credential', async () => {
    const key = await newDeviceKey();
    const credential = 'e30.e30.AA';
    const headers = await deviceHeaders({ key, credential, method: 'post', url: 'https://hashbin.org/api/content?x=1' });
    expect(headers.Authorization).toBe(`DBA ${credential}`);
    const proof = await verifyProof(headers.DPoP, { method: 'POST', url: 'https://hashbin.org/api/content', credential, jkt: await jwkThumbprint(key.publicJwk) });
    expect(proof).toMatchObject({ htm: 'POST', htu: 'https://hashbin.org/api/content', ath: await sha256b64u(credential) });
  });
});

describe('enrollment polling', () => {
  const start = { poll_url: '/poll', interval: 2 };
  const fakeClock = () => { let t = 0; return { clock: () => t, sleep: async ms => { t += ms; } }; };

  it('waits at the server\'s interval and retries network errors', async () => {
    const replies = [new ApiError('down', 'network_error'), { status: 'pending', interval: 5 }, { status: 'approved', credential: 'c' }];
    const { clock, sleep } = fakeClock(); const waits = [];
    const client = { request: async () => { const r = replies.shift(); if (r instanceof Error) throw r; return r; } };
    const result = await pollEnrollment(client, start, { clock, sleep: async ms => { waits.push(ms); await sleep(ms); } });
    expect(result).toEqual({ status: 'approved', credential: 'c' });
    expect(waits).toEqual([2000, 2000, 5000]);
  });

  it('stops at the deadline and on error responses', async () => {
    const { clock, sleep } = fakeClock();
    expect(await pollEnrollment({ request: async () => ({ status: 'pending' }) }, start, { waitSeconds: 7, clock, sleep })).toEqual({ status: 'timeout' });
    await expect(pollEnrollment({ request: async () => { throw new ApiError('bad', 'invalid_poll_token', 401); } }, start, { clock, sleep })).rejects.toMatchObject({ code: 'invalid_poll_token' });
  });
});
