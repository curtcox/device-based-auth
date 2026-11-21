import { describe, it, expect, beforeEach } from 'vitest';
import { ApiError } from './errors.js';
import { splitCommand } from './args.js';
import { describeCredential, shouldRenew, relativeTime, autoRenewEnabled, renewIfDue, issuerKeyWithdrawn, listQuery, formatCredentialList } from './credentials.js';
import { createClient } from './client.js';
import { enrollmentPayload, signEnrollmentRequest, pollEnrollment } from './enrollment.js';
import { newDeviceKey } from './device-key.js';
import { inspectCredential, generateKeyPair } from '../verify/src/index.js';
import { testEnv, call, worker, ORIGIN } from '../../test-utils/env.js';

describe('describing credentials', () => {
  const payload = { cid: 'crd_ABCDEFGH', jti: 'crd_ABCDEFGH.2', cnf: { jkt: 'x' }, sub: 'dev_ABCDEFGH', acct: 'alice', aud: ['hashbin.org'], iat: 1000, exp: 4000, device: { name: 'Laptop', kind: 'cli', key_protection: 'software' }, grants: [{ actions: ['hashbin:content:write'] }] };

  it('prints the device, sites, expiry and grants in English', () => {
    expect(describeCredential(payload, 1000)).toEqual([
      'Credential crd_ABCDEFGH (version 2)',
      'Device:    dev_ABCDEFGH "Laptop" (cli, key: software)',
      'Account:   alice',
      'Sites:     hashbin.org',
      'Expires:   1970-01-01T01:06:40Z (in 50 minutes)',
      'Grants:',
      '  1. May "hashbin:content:write", on any resource.'
    ]);
    expect(describeCredential(payload, 5000)[4]).toMatch(/^Expired: .*\(17 minutes ago\)/);
    const access = { ...payload, jti: 'tok_ABCDEFGH' };
    delete access.cnf;
    expect(describeCredential(access, 1000)[0]).toBe('Access token for credential crd_ABCDEFGH (bearer: anyone holding it can use it)');
  });

  it('says when to renew and how long is left', () => {
    expect(shouldRenew(payload, 2999)).toBe(false);
    expect(shouldRenew(payload, 3000)).toBe(true);
    expect(relativeTime(100, 100)).toBe('in 0 seconds');
    expect(relativeTime(100 + 3 * 86400, 100)).toBe('in 3 days');
    expect(relativeTime(100, 100 + 7200)).toBe('2 hours ago');
  });
});

describe('automatic renewal', () => {
  it('is on unless --no-renew or DBA_AUTO_RENEW turns it off', () => {
    expect(autoRenewEnabled()).toBe(true);
    expect(autoRenewEnabled({ env: { DBA_AUTO_RENEW: '1' } })).toBe(true);
    expect(autoRenewEnabled({ flag: true })).toBe(false);
    for (const value of ['0', 'false', 'OFF', ' no ']) expect(autoRenewEnabled({ env: { DBA_AUTO_RENEW: value } })).toBe(false);
    expect(splitCommand(['--no-renew', 'token', '--aud', 'x'])).toEqual({ globals: { 'no-renew': true }, command: 'token', rest: ['--aud', 'x'] });
  });

  let env; let client;
  beforeEach(async () => {
    env = await testEnv();
    client = createClient({ origin: ORIGIN, fetch: (url, init) => worker.fetch(new Request(url, init), env) });
  });

  async function enrolledDevice() {
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
    const key = await newDeviceKey();
    const request = await signEnrollmentRequest(key, enrollmentPayload({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], name: 'Renewing', lifetime: 3000 }));
    const start = await client.request('POST', '/api/v1/enrollments', { body: { request } });
    await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: start.request } });
    return { key, credential: (await pollEnrollment(client, start, { sleep: async () => {} })).credential };
  }

  it('renews only once two thirds of the lifetime has passed, and saves the new version', async () => {
    const device = await enrolledDevice();
    const { iat, exp, cid } = inspectCredential(device.credential).payload;
    const saved = [];
    const save = async result => { saved.push(result.credential); };
    expect(await renewIfDue({ client, device, save, now: iat + 10 })).toEqual({ renewed: false, reason: 'not_due' });
    expect(await renewIfDue({ client, device, save, now: exp })).toEqual({ renewed: false, reason: 'expired' });
    const outcome = await renewIfDue({ client, device, save, now: iat + 2001 });
    expect(outcome).toMatchObject({ renewed: true, result: { cid, jti: `${cid}.2`, rotated: false } });
    expect(saved).toEqual([outcome.result.credential]);
    // A second process still holding version 1 is told it was superseded, not given an error.
    expect(await renewIfDue({ client, device, save, now: iat + 2001 })).toEqual({ renewed: false, reason: 'superseded' });
  });

  it('reports a refused renewal without throwing, so the current credential is still used', async () => {
    const device = await enrolledDevice();
    const { iat } = inspectCredential(device.credential).payload;
    const broke = { request: async () => { throw new ApiError('Balance too low', 'insufficient_balance', 402); } };
    const outcome = await renewIfDue({ client: broke, device, save: async () => { throw new Error('must not save'); }, now: iat + 2500 });
    expect(outcome).toMatchObject({ renewed: false, reason: 'failed', error: { code: 'insufficient_balance' } });
  });

  it('renews early, for free, when the issuer withdraws the key that signed the credential', async () => {
    const device = await enrolledDevice();
    const { iat } = inspectCredential(device.credential).payload;
    let stored = null; let fetches = 0;
    const counting = { request: (method, path, options) => { if (path.includes('jwks')) fetches++; return client.request(method, path, options); } };
    const cache = { read: async () => stored, write: async entry => { stored = entry; } };
    expect(await issuerKeyWithdrawn({ client: counting, credential: device.credential, cache, now: iat })).toBe(false);
    expect(await issuerKeyWithdrawn({ client: counting, credential: device.credential, cache, now: iat + 60 })).toBe(false);
    expect(fetches).toBe(1);

    const [old] = JSON.parse(env.ISSUER_KEYS);
    const pair = await generateKeyPair(true);
    env.ISSUER_KEYS = JSON.stringify([{ kid: 'test-2', jwk: await crypto.subtle.exportKey('jwk', pair.privateKey) }, { ...old, withdrawn: true }]);
    // The cached JWKS still lists the old key for up to an hour; after that the CLI notices.
    expect(await issuerKeyWithdrawn({ client: counting, credential: device.credential, cache, now: iat + 120 })).toBe(false);
    expect(await issuerKeyWithdrawn({ client: counting, credential: device.credential, cache, now: iat + 3700 })).toBe(true);
    // A failed fetch never triggers a renewal.
    const offline = { request: async () => { throw new ApiError('offline', 'network_error'); } };
    expect(await issuerKeyWithdrawn({ client: offline, credential: device.credential, cache: { read: async () => null, write: async () => {} } })).toBe(false);

    expect(await renewIfDue({ client, device, save: async () => {}, now: iat + 10 })).toEqual({ renewed: false, reason: 'not_due' });
    const outcome = await renewIfDue({ client, device, save: async () => {}, withdrawn: true, now: iat + 10 });
    expect(outcome).toMatchObject({ renewed: true, result: { recovered: true, cost_microdollars: 0 } });
    expect(inspectCredential(outcome.result.credential).header.kid).toBe('test-2');
  });
});

describe('dba list', () => {
  it('builds the query and refuses unknown states', () => {
    expect(listQuery()).toBe('/api/v1/credentials');
    expect(listQuery({ status: 'active', audience: 'hashbin.org', cursor: 'cred:crd_x' })).toBe('/api/v1/credentials?status=active&audience=hashbin.org&cursor=cred%3Acrd_x');
    expect(() => listQuery({ status: 'superseded' })).toThrow(/--status must be one of/);
  });

  it('prints aligned rows and strips terminal control characters from device names', () => {
    const now = 1_800_000_000;
    const lines = formatCredentialList([
      { cid: 'crd_aaaaaaaa', state: 'active', device: { name: 'Laptop' }, aud: ['hashbin.org', 'cronly.org'], exp: now + 3 * 86400 },
      { cid: 'crd_bbbbbbbb', state: 'revoked', device: { name: 'Evil\u001b[2Jname' }, aud: ['hashbin.org'], exp: now - 7200 }
    ], now);
    expect(lines[0]).toMatch(/^CREDENTIAL\s+STATE\s+DEVICE\s+SITES\s+EXPIRY$/);
    expect(lines[1]).toMatch(/^crd_aaaaaaaa\s+active\s+Laptop\s+hashbin.org,cronly.org\s+expires in 3 days$/);
    expect(lines[2]).toContain('Evil[2Jname');
    expect(lines[2]).not.toContain('\u001b');
    expect(lines[2]).toMatch(/expired 2 hours ago$/);
    expect(formatCredentialList([])).toEqual(['No credentials.']);
  });

  it('lists through the API with an API key, or with a device that holds dba:credentials:read', async () => {
    const env = await testEnv();
    const client = createClient({ origin: ORIGIN, fetch: (url, init) => worker.fetch(new Request(url, init), env) });
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
    const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'cli', scopes: ['credentials:read'] } })).body.secret;
    const reader = await newDeviceKey();
    const issued = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: reader.publicJwk, aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:credentials:read'] }] } });
    expect(issued.status).toBe(200);
    const byKey = await client.request('GET', listQuery({ status: 'active' }), { apiKey: key });
    expect(byKey.items.map(c => c.cid)).toEqual([issued.body.cid]);
    expect(byKey.cost_microdollars).toBe(5);
    const byDevice = await client.request('GET', listQuery(), { device: { key: reader, credential: issued.body.credential } });
    expect(byDevice.items).toHaveLength(1);
    await expect(client.request('GET', listQuery(), { apiKey: 'dbak_nonsense' })).rejects.toMatchObject({ code: 'invalid_auth', status: 401 });
  });
});
