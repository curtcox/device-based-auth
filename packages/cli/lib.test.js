import { describe, it, expect, beforeEach } from 'vitest';
import {
  UsageError, ApiError, parseArgs, splitCommand, configPaths, resolveOrigin, audiencesFromOption, grantsFromOptions, secondsOption,
  enrollmentPayload, enrollmentTokenOption, newDeviceKey, keyFile, loadDeviceKey, keyStoreOption, osSecretStore, saveDeviceKey, forgetDeviceKey, SECRET_SERVICE, signEnrollmentRequest, rotationProof, deviceHeaders, credentialMatchesKey,
  curlRequest, curlArgs, createClient, pollEnrollment, describeCredential, shouldRenew, relativeTime, DEFAULT_ORIGIN, autoRenewEnabled, renewIfDue, issuerKeyWithdrawn, listQuery, formatCredentialList
} from './lib.js';
import { verifyJws, verifyProof, inspectCredential, jwkThumbprint, sha256b64u, generateKeyPair } from '../verify/src/index.js';
import { testEnv, call, worker, ORIGIN } from '../../test-utils/env.js';

describe('argument parsing', () => {
  const spec = { values: ['name'], booleans: ['force'], repeatable: ['aud', 'action'] };

  it('reads values, repeated values, booleans and positionals', () => {
    const { options, positionals } = parseArgs(['--aud', 'a.org', '--aud=b.org', '--action', 'x:y', '--name=My laptop', '--force', 'extra'], spec);
    expect(options).toEqual({ aud: ['a.org', 'b.org'], action: ['x:y'], name: 'My laptop', force: true });
    expect(positionals).toEqual(['extra']);
  });

  it('stops at -- and treats - as a positional', () => {
    expect(parseArgs(['-', '--', '--force'], spec).positionals).toEqual(['-', '--force']);
  });

  it('refuses unknown options, missing values and values on booleans', () => {
    expect(() => parseArgs(['--grnat', '{}'], spec)).toThrow(UsageError);
    expect(() => parseArgs(['--name'], spec)).toThrow(/needs a value/);
    expect(() => parseArgs(['--force=yes'], spec)).toThrow(/does not take a value/);
  });

  it('splits global options from the command', () => {
    expect(splitCommand(['--profile', 'work', '--origin=http://localhost:8788', 'curl', '-sS', 'https://x.org/'])).toEqual({ globals: { profile: 'work', origin: 'http://localhost:8788' }, command: 'curl', rest: ['-sS', 'https://x.org/'] });
    expect(splitCommand(['--help'])).toEqual({ globals: { help: true }, command: undefined, rest: [] });
  });
});

describe('configuration', () => {
  it('puts each profile in its own directory', () => {
    expect(configPaths({ env: {}, home: '/home/u' }).dir).toBe('/home/u/.config/dba/default');
    expect(configPaths({ env: { XDG_CONFIG_HOME: '/x' }, home: '/home/u', profile: 'work' }).key).toBe('/x/dba/work/key.json');
    expect(configPaths({ env: { DBA_HOME: '/tmp/dba/' }, home: '/home/u' })).toEqual({ dir: '/tmp/dba/default', key: '/tmp/dba/default/key.json', credential: '/tmp/dba/default/credential.jwt', config: '/tmp/dba/default/config.json', certificate: '/tmp/dba/default/client.crt', certificateKey: '/tmp/dba/default/client.key', ca: '/tmp/dba/default/ca.crt' });
  });

  it('refuses profile names that could escape the directory', () => {
    for (const profile of ['..', '../x', 'a/b', '', '.hidden']) expect(() => configPaths({ env: {}, home: '/h', profile })).toThrow(UsageError);
  });

  it('prefers --origin, then $DBA_ORIGIN, then the enrolled origin', () => {
    expect(resolveOrigin({})).toBe(DEFAULT_ORIGIN);
    expect(resolveOrigin({ saved: 'http://localhost:8788' })).toBe('http://localhost:8788');
    expect(resolveOrigin({ env: { DBA_ORIGIN: 'http://localhost:9/' }, saved: 'http://localhost:8788' })).toBe('http://localhost:9');
    expect(resolveOrigin({ flag: 'https://example.org/x', env: { DBA_ORIGIN: 'http://localhost:9' } })).toBe('https://example.org');
    expect(() => resolveOrigin({ flag: 'ftp://x' })).toThrow(UsageError);
  });
});

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

describe('curl handling', () => {
  it('finds the method and URL the way curl would', () => {
    expect(curlRequest(['-sS', 'https://hashbin.org/api/content'])).toEqual({ method: 'GET', url: 'https://hashbin.org/api/content' });
    expect(curlRequest(['https://x.org/a', '-d', '{"a":1}'])).toEqual({ method: 'POST', url: 'https://x.org/a' });
    expect(curlRequest(['--data-binary', '@file', 'https://x.org/a'])).toMatchObject({ method: 'POST' });
    expect(curlRequest(['--json', '{}', 'https://x.org/a'])).toMatchObject({ method: 'POST' });
    expect(curlRequest(['-F', 'f=@x', 'https://x.org/a'])).toMatchObject({ method: 'POST' });
    expect(curlRequest(['-G', '-d', 'q=1', 'https://x.org/a'])).toMatchObject({ method: 'GET' });
    expect(curlRequest(['-X', 'delete', 'https://x.org/a'])).toMatchObject({ method: 'DELETE' });
    expect(curlRequest(['-XPUT', '-d', 'x', 'https://x.org/a'])).toMatchObject({ method: 'PUT' });
    expect(curlRequest(['--request=PATCH', 'https://x.org/a'])).toMatchObject({ method: 'PATCH' });
    expect(curlRequest(['-I', 'https://x.org/a'])).toMatchObject({ method: 'HEAD' });
    expect(curlRequest(['-T', 'file.txt', 'https://x.org/a'])).toMatchObject({ method: 'PUT' });
  });

  it('never mistakes an option value for the URL', () => {
    expect(curlRequest(['-H', 'https://not-the-url/', '-d', 'https://data/', 'https://x.org/real']).url).toBe('https://x.org/real');
    expect(curlRequest(['--url', 'https://x.org/u', 'https://x.org/other']).url).toBe('https://x.org/u');
    expect(() => curlRequest(['-sS', 'x.org'])).toThrow(/URL/);
  });

  it('adds the headers before the caller\'s arguments', () => {
    expect(curlArgs(['-sS', 'https://x.org/'], { Authorization: 'DBA c', DPoP: 'p' })).toEqual(['-H', 'Authorization: DBA c', '-H', 'DPoP: p', '-sS', 'https://x.org/']);
  });
});

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

describe('the client against the Worker', () => {
  let env; let client;
  beforeEach(async () => {
    env = await testEnv();
    client = createClient({ origin: ORIGIN, fetch: (url, init) => worker.fetch(new Request(url, init), env) });
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
  });

  async function enrolled(key, grants = [{ actions: ['hashbin:content:write'] }]) {
    const request = await signEnrollmentRequest(key, enrollmentPayload({ aud: ['hashbin.org'], grants, name: 'CLI test' }));
    const start = await client.request('POST', '/api/v1/enrollments', { body: { request } });
    expect(start.approval_url).toBe(`${ORIGIN}/approve.html#${start.request}`);
    await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: start.request } });
    const result = await pollEnrollment(client, start, { sleep: async () => {} });
    expect(result.status).toBe('approved');
    return result.credential;
  }

  it('enrolls, reads whoami, gets an access token, renews with rotation and revokes', async () => {
    const key = await newDeviceKey();
    const credential = await enrolled(key);
    expect(inspectCredential(credential).payload).toMatchObject({ acct: 'alice', device: { name: 'CLI test', kind: 'cli', key_protection: 'software' } });
    expect(await credentialMatchesKey(credential, key)).toBe(true);
    expect(await credentialMatchesKey(credential, await newDeviceKey())).toBe(false);

    const device = { key, credential };
    const me = await client.request('GET', '/api/v1/whoami', { device });
    expect(me).toMatchObject({ account: 'alice', kind: 'device', descriptions: ['May "hashbin:content:write", on any resource.'] });

    const token = await client.request('POST', '/api/v1/token', { device, body: { audience: 'hashbin.org' } });
    expect(inspectCredential(token.access_token).header.typ).toBe('dba-access+jwt');
    await expect(client.request('POST', '/api/v1/token', { device, body: { audience: 'cronly.org' } })).rejects.toMatchObject({ code: 'invalid_audience', status: 400 });

    const { cid } = inspectCredential(credential).payload;
    const next = await newDeviceKey();
    const renewed = await client.request('POST', `/api/v1/credentials/${cid}/renew`, { device, body: { new_key_proof: await rotationProof(next, cid) } });
    expect(renewed).toMatchObject({ cid, rotated: true, jti: `${cid}.2` });
    expect(await credentialMatchesKey(renewed.credential, next)).toBe(true);

    const fresh = { key: next, credential: renewed.credential };
    expect((await client.request('POST', '/api/v1/self/revoke', { device: fresh, body: {} })).count).toBe(1);
    await expect(client.request('GET', '/api/v1/whoami', { device: fresh })).rejects.toMatchObject({ code: 'revoked', status: 401 });
    const inspected = await client.request('POST', '/api/v1/inspect', { body: { credential: renewed.credential } });
    expect(inspected).toMatchObject({ signature_valid: true, revoked: true, valid: false });
  });

  it('enrolls with an enrollment token, taking the template when the request leaves it out', async () => {
    const created = await call(env, 'POST', '/api/v1/enrollment-tokens', { auth: 'alice', body: { aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], max_uses: 1 } });
    const token = enrollmentTokenOption({ env: { DBA_ENROLLMENT_TOKEN: ` ${created.body.token}\n` } });
    const key = await newDeviceKey();
    const payload = enrollmentPayload({ name: 'fleet box' });
    expect(payload.aud).toBeUndefined();
    const issued = await client.request('POST', '/api/v1/enrollments/redeem', { body: { request: await signEnrollmentRequest(key, payload), enrollment_token: token } });
    expect(inspectCredential(issued.credential).payload).toMatchObject({ aud: ['hashbin.org'], device: { name: 'fleet box' } });
    expect(await credentialMatchesKey(issued.credential, key)).toBe(true);
    expect(enrollmentTokenOption({ flag: 'dbae_x', env: { DBA_ENROLLMENT_TOKEN: 'dbae_y' } })).toBe('dbae_x');
    expect(enrollmentTokenOption({ env: {} })).toBeNull();
    expect(() => enrollmentTokenOption({ flag: 'dbak_x' })).toThrow(UsageError);
  });

  it('reports unreachable servers as network errors', async () => {
    const offline = createClient({ origin: ORIGIN, fetch: async () => { throw new TypeError('fetch failed', { cause: new Error('ECONNREFUSED') }); } });
    await expect(offline.request('GET', '/health')).rejects.toMatchObject({ code: 'network_error', message: `Could not reach ${ORIGIN}: ECONNREFUSED` });
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

/** A secret store backed by a Map, standing in for osSecretStore. */
function memoryStore({ saves = true, reads = true } = {}) {
  const entries = new Map();
  return {
    entries, backend: 'secret-service', name: 'the test keyring', removed: [],
    async save(account, secret) { if (saves) entries.set(account, secret); return true; },
    async load(account) { return reads ? entries.get(account) ?? null : null; },
    async remove(account) { this.removed.push(account); entries.delete(account); }
  };
}

describe('OS secret store', () => {
  function recorder(results = {}) {
    const calls = [];
    return { calls, run: async (command, args, input) => { calls.push({ command, args, input }); return results[args[0]] ?? { code: 0, stdout: '' }; } };
  }

  it('keeps the secret off the command line on macOS (security -i reads it from stdin)', async () => {
    const { calls, run } = recorder({ 'find-generic-password': { code: 0, stdout: 'c2VjcmV0\n' } });
    const store = osSecretStore({ platform: 'darwin', run });
    const account = 'A'.repeat(43);
    expect(await store.save(account, 'c2VjcmV0')).toBe(true);
    expect(await store.load(account)).toBe('c2VjcmV0');
    await store.remove(account);
    expect(calls[0]).toEqual({ command: 'security', args: ['-i'], input: `add-generic-password -U -s ${SECRET_SERVICE} -a ${account} -l dba-cli-device-key -w c2VjcmV0\n` });
    expect(calls[1].args).toEqual(['find-generic-password', '-s', SECRET_SERVICE, '-a', account, '-w']);
    expect(calls[2].args).toEqual(['delete-generic-password', '-s', SECRET_SERVICE, '-a', account]);
    for (const call of calls) expect(call.args.join(' ')).not.toContain('c2VjcmV0');
  });

  it('uses secret-tool on Linux, with the secret on stdin', async () => {
    const { calls, run } = recorder({ lookup: { code: 0, stdout: 'c2VjcmV0' } });
    const store = osSecretStore({ platform: 'linux', run });
    const account = 'B'.repeat(43);
    await store.save(account, 'c2VjcmV0');
    expect(await store.load(account)).toBe('c2VjcmV0');
    await store.remove(account);
    expect(calls.map(call => [call.command, ...call.args])).toEqual([
      ['secret-tool', 'store', '--label=dba CLI device key', 'service', SECRET_SERVICE, 'account', account],
      ['secret-tool', 'lookup', 'service', SECRET_SERVICE, 'account', account],
      ['secret-tool', 'clear', 'service', SECRET_SERVICE, 'account', account]
    ]);
    expect(calls[0].input).toBe('c2VjcmV0');
  });

  it('reports a missing or failing program as no entry, and has no store on Windows', async () => {
    const store = osSecretStore({ platform: 'linux', run: async () => ({ code: null, stdout: '' }) });
    expect(await store.save('C'.repeat(43), 'abc')).toBe(false);
    expect(await store.load('C'.repeat(43))).toBeNull();
    expect(osSecretStore({ platform: 'win32', run: async () => ({ code: 0, stdout: '' }) })).toBeNull();
  });

  it('refuses entry names and secrets that would need quoting', async () => {
    const store = osSecretStore({ platform: 'darwin', run: async () => ({ code: 0, stdout: '' }) });
    await expect(store.save('x -w y', 'abc')).rejects.toThrow(/thumbprint/);
    await expect(store.save('D'.repeat(43), 'a b\nadd-generic-password')).rejects.toThrow(/base64url/);
  });

  it('chooses the store from --key-store, then DBA_KEY_STORE, then auto', () => {
    expect(keyStoreOption({})).toBe('auto');
    expect(keyStoreOption({ env: { DBA_KEY_STORE: 'file' } })).toBe('file');
    expect(keyStoreOption({ flag: 'OS', env: { DBA_KEY_STORE: 'file' } })).toBe('os');
    expect(() => keyStoreOption({ flag: 'tpm' })).toThrow(UsageError);
  });

  it('keeps only the public key in key.json when the store works, and loads it back', async () => {
    const secrets = memoryStore();
    const key = await newDeviceKey();
    const saved = await saveDeviceKey(key, { secrets, now: new Date(0) });
    const account = await jwkThumbprint(key.publicJwk);
    expect(saved.keyProtection).toBe('os-keychain');
    expect(saved.file).toEqual({ public_jwk: key.publicJwk, key_protection: 'os-keychain', key_store: 'secret-service', key_store_account: account, created_at: '1970-01-01T00:00:00.000Z' });
    expect(JSON.stringify(saved.file)).not.toContain(key.privateJwk.d);
    expect(secrets.entries.get(account)).toBe(key.privateJwk.d);

    const loaded = await loadDeviceKey(saved.file, { secrets });
    const proof = await rotationProof(loaded, 'crd_ABCDEFGH', 1800000000);
    expect((await verifyJws(proof, key.publicJwk)).payload.cid).toBe('crd_ABCDEFGH');
    expect(loaded.privateJwk.d).toBe(key.privateJwk.d);

    await expect(loadDeviceKey(saved.file)).rejects.toThrow(/cannot reach/);
    await expect(loadDeviceKey(saved.file, { secrets: { ...secrets, backend: 'macos-keychain' } })).rejects.toThrow(/cannot reach/);
    const other = await newDeviceKey();
    secrets.entries.set(account, other.privateJwk.d);
    await expect(loadDeviceKey(saved.file, { secrets })).rejects.toThrow(/does not belong/);
    await forgetDeviceKey(saved.file, { secrets });
    expect(secrets.entries.has(account)).toBe(false);
    await expect(loadDeviceKey(saved.file, { secrets })).rejects.toThrow(/missing from the Secret Service/);
  });

  it('falls back to the file when the store cannot keep the key, unless told not to', async () => {
    const key = await newDeviceKey();
    const silent = memoryStore({ reads: false }); // reports success, keeps nothing (a locked keyring)
    const fallback = await saveDeviceKey(key, { secrets: silent });
    expect(fallback.keyProtection).toBe('software');
    expect(fallback.file.private_jwk.d).toBe(key.privateJwk.d);
    expect(silent.removed).toEqual([await jwkThumbprint(key.publicJwk)]);
    expect((await saveDeviceKey(key, { secrets: null })).keyProtection).toBe('software');
    await expect(saveDeviceKey(key, { mode: 'os', secrets: silent })).rejects.toThrow(/Could not keep the key in the test keyring/);
    await expect(saveDeviceKey(key, { mode: 'os', secrets: null })).rejects.toThrow(/no OS secret store/);
    const unused = memoryStore();
    expect((await saveDeviceKey(key, { mode: 'file', secrets: unused })).keyProtection).toBe('software');
    expect(unused.entries.size).toBe(0);
    await forgetDeviceKey(fallback.file, { secrets: unused }); // a file key: nothing to remove
    expect(unused.removed).toEqual([]);
  });
});
