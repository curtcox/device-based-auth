  /**
   * A stand-in for powershell.exe that checks the -EncodedCommand is one of the two DPAPI scripts
   * and "seals" by tagging the input with the entry's entropy, so a blob only unseals for its entry.
   */
  function fakePowershell({ code = 0 } = {}) {
    const calls = [];
    const run = async (command, args, input) => {
      calls.push({ command, args, input });
      const script = new TextDecoder('utf-16le').decode(Uint8Array.from(atob(args.at(-1)), c => c.charCodeAt(0)));
      const entropy = /GetBytes\('([^']+)'\)/.exec(script)[1];
      if (code !== 0) return { code, stdout: '' };
      if (script === dpapiScript('protect', entropy.split('/')[1])) return { code: 0, stdout: `${btoa(`${entropy}|${input}`)}\r\n` };
      if (script === dpapiScript('unprotect', entropy.split('/')[1])) {
        const [tag, secret] = atob(input).split('|');
        return tag === entropy ? { code: 0, stdout: secret } : { code: 1, stdout: '' };
      }
      return { code: 1, stdout: '' };
    };
    return { calls, run };
  }
  function memoryFiles() {
    const map = new Map();
    return { map, read: async path => map.get(path) ?? null, write: async (path, text) => { map.set(path, text); }, remove: async path => { map.delete(path); } };
  }

  it('seals with DPAPI on Windows, blob in the profile directory, secret and blob on stdin', async () => {
    const { calls, run } = fakePowershell();
    const files = memoryFiles();
    const store = osSecretStore({ platform: 'win32', run, files, dir: 'C:/Users/me/.config/dba/default' });
    expect(store.backend).toBe('windows-dpapi');
    const account = 'E'.repeat(43);
    expect(await store.save(account, 'c2VjcmV0')).toBe(true);
    const path = `C:/Users/me/.config/dba/default/${account}.dpapi`;
    expect([...files.map.keys()]).toEqual([path]);
    expect(files.map.get(path)).not.toContain('\n');
    expect(await store.load(account)).toBe('c2VjcmV0');
    for (const call of calls) {
      expect(call.command).toBe('powershell.exe');
      expect(call.args.slice(0, -1)).toEqual(['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand']);
      expect(call.args.join(' ')).not.toContain('c2VjcmV0');
    }
    expect(calls[0].input).toBe('c2VjcmV0');
    expect(calls[1].input).toBe(files.map.get(path));
    // A blob moved to another entry's name does not unseal there (the entropy names the entry).
    const other = 'F'.repeat(43);
    files.map.set(`C:/Users/me/.config/dba/default/${other}.dpapi`, files.map.get(path));
    expect(await store.load(other)).toBeNull();
    await store.remove(account);
    expect(files.map.has(path)).toBe(false);
    expect(await store.load(account)).toBeNull();
  });

  it('reports DPAPI failures as no entry and writes nothing', async () => {
    const files = memoryFiles();
    const store = osSecretStore({ platform: 'win32', run: fakePowershell({ code: 1 }).run, files, dir: 'C:/d' });
    expect(await store.save('G'.repeat(43), 'abc')).toBe(false);
    expect(files.map.size).toBe(0);
    files.map.set(`C:/d/${'G'.repeat(43)}.dpapi`, 'not base64!');
    expect(await store.load('G'.repeat(43))).toBeNull();
    await expect(store.save('x y', 'abc')).rejects.toThrow(/thumbprint/);
  });

  it('encodes PowerShell commands as base64 UTF-16LE', () => {
    expect(powershellEncoded('dir')).toBe('ZABpAHIA');
    expect(dpapiScript('protect', 'H'.repeat(43))).toContain(`'${SECRET_SERVICE}/${'H'.repeat(43)}'`);
    expect(dpapiScript('protect', 'x')).toContain('Protect(');
    expect(dpapiScript('unprotect', 'x')).toContain('Unprotect(');
  });

import { describe, it, expect, beforeEach } from 'vitest';
import {
  UsageError, ApiError, parseArgs, splitCommand, configPaths, resolveOrigin, audiencesFromOption, grantsFromOptions, secondsOption,
  enrollmentPayload, enrollmentTokenOption, newDeviceKey, keyFile, loadDeviceKey, keyStoreOption, osSecretStore, powershellEncoded, dpapiScript, saveDeviceKey, forgetDeviceKey, SECRET_SERVICE, signEnrollmentRequest, rotationProof, deviceHeaders, credentialMatchesKey,
  curlRequest, curlArgs, curlHeaderFile, createClient, pollEnrollment, describeCredential, shouldRenew, relativeTime, DEFAULT_ORIGIN, autoRenewEnabled, renewIfDue, issuerKeyWithdrawn, listQuery, formatCredentialList,
  needsConfirmation, currentConfirmation, waitForConfirmation, confirmationHeaders, formatGateList, gateInputFromOptions, describeGateRequest, answerFor,
  curlWaitOption, pendingGate, waitThroughGates, describePendingGate
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
    expect(configPaths({ env: { DBA_HOME: '/tmp/dba/' }, home: '/home/u' })).toEqual({ dir: '/tmp/dba/default', key: '/tmp/dba/default/key.json', credential: '/tmp/dba/default/credential.jwt', config: '/tmp/dba/default/config.json', confirmation: '/tmp/dba/default/confirmation.jwt', certificate: '/tmp/dba/default/client.crt', certificateKey: '/tmp/dba/default/client.key', ca: '/tmp/dba/default/ca.crt' });
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

  it('reads the headers from a file, never from the command line, before the caller\'s arguments', () => {
    expect(curlArgs(['-sS', 'https://x.org/'], '/tmp/dba-curl-x/headers')).toEqual(['-H', '@/tmp/dba-curl-x/headers', '-sS', 'https://x.org/']);
    expect(curlHeaderFile({ Authorization: 'DBA c', DPoP: 'p' })).toBe('Authorization: DBA c\nDPoP: p\n');
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

describe('gates, approvals and confirmation (STATUS B7 G9)', () => {
  it('builds gate bodies from options and refuses kinds that need the dashboard', () => {
    expect(gateInputFromOptions({ kind: 'dba-device', label: 'Phone', device: 'dev_abcdefgh' })).toEqual({ kind: 'dba-device', label: 'Phone', device_id: 'dev_abcdefgh' });
    expect(gateInputFromOptions({ kind: 'webhook', label: 'Ops', url: 'https://ops.example.com/dba', 'public-jwk': '{"kty":"EC"}' })).toEqual({ kind: 'webhook', label: 'Ops', url: 'https://ops.example.com/dba', public_jwk: { kty: 'EC' } });
    expect(() => gateInputFromOptions({ kind: 'totp', label: 'x' })).toThrow(/dashboard/);
    expect(() => gateInputFromOptions({ kind: 'dba-device', label: 'x' })).toThrow(/--device/);
    expect(() => gateInputFromOptions({ kind: 'webhook', label: 'x', url: 'https://a.example', 'public-jwk': 'nope' })).toThrow(/JSON Web Key/);
    expect(() => gateInputFromOptions({ kind: 'dba-device', device: 'dev_x' })).toThrow(/--label/);
  });

  it('prints gates and requests without control characters', () => {
    const gates = formatGateList([{ id: 'owner', kind: 'owner', label: 'Account owner' }, { id: 'gate_abcdefgh', kind: 'dba-device', state: 'active', label: 'Ph\u001b[2Jone', device_id: 'dev_x' }]);
    expect(gates[0]).toMatch(/^GATE\s+KIND\s+STATE\s+LABEL$/);
    expect(gates[2]).toMatch(/^gate_abcdefgh\s+dba-device\s+active\s+Ph\[2Jone \(dev_x\)$/);
    expect(formatGateList([])).toEqual(['No gates.']);
    const lines = describeGateRequest({ id: 'gtr_1', purpose: 'authorize', device_name: 'Laptop\u0007', action: 'hashbin:content:delete', audience: 'hashbin.org', number: '42', status: 'pending', entries: [{ expires_in: 90, on_timeout: 'allow', outcome: null }] });
    expect(lines).toEqual(['gtr_1  Laptop asks to hashbin:content:delete on hashbin.org', '  Number: 42 (check it matches what the device shows)', '  Status: pending, 90 s left (then allowed by timeout)']);
    expect(describeGateRequest({ id: 'gtr_2', purpose: 'sign_in', audience: 'cronly.org', status: 'pending', entries: [] })[1]).toMatch(/--number NN/);
  });

  it('picks the device\'s own gate to answer with', () => {
    const req = { id: 'gtr_1', answer_as: [{ entry: 0, gate: 'gate_a' }, { entry: 1, gate: 'gate_b' }] };
    expect(answerFor(req, { decision: 'allow' })).toEqual({ entry: 0, gate: 'gate_a', decision: 'allow' });
    expect(answerFor(req, { decision: 'allow', entry: 1, number: '07' })).toEqual({ entry: 1, gate: 'gate_b', decision: 'allow', number: '07' });
    expect(answerFor(req, { decision: 'deny', number: '07' })).toEqual({ entry: 0, gate: 'gate_a', decision: 'deny' });
    expect(() => answerFor(req, { decision: 'allow', entry: 2 })).toThrow(/no gate that can still answer/);
    expect(() => answerFor({ id: 'x' }, { decision: 'allow' })).toThrow(UsageError);
    expect(() => answerFor(req, { decision: 'allow', number: '7' })).toThrow(/two-digit/);
    expect(() => answerFor(req, { decision: 'maybe' })).toThrow(/allow or deny/);
  });

  it('answers as a dba-device gate, and confirms a credential, against the Worker', async () => {
    const env = await testEnv();
    let now = Date.now();
    const client = createClient({ origin: ORIGIN, fetch: (url, init) => worker.fetch(new Request(url, init), env) });
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
    // The phone: a device holding dba:approvals:answer, registered as a gate with an API key.
    const phone = await newDeviceKey();
    const phoneCred = (await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: phone.publicJwk, aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:approvals:answer'] }] } })).body.credential;
    const apiKey = (await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'cli', scopes: ['gates:read', 'gates:write'] } })).body.secret;
    const gate = await client.request('POST', '/api/v1/gates', { apiKey, body: gateInputFromOptions({ kind: 'dba-device', label: 'Phone', device: inspectCredential(phoneCred).payload.sub }) });
    expect(formatGateList((await client.request('GET', '/api/v1/gates', { apiKey })).items)[2]).toContain(gate.id);

    // The laptop: a credential that needs confirmation by the phone every hour.
    const laptop = await newDeviceKey();
    const issued = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: laptop.publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], confirm: { gates: [{ any: [gate.id], timeout_s: 120 }], every_s: 3600 } } });
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    const device = { key: laptop, credential: issued.body.credential };
    const payload = inspectCredential(device.credential).payload;
    expect(needsConfirmation(payload)).toBe(true);
    expect(currentConfirmation(null, payload)).toBeNull();

    // While the laptop waits, the phone lists the request and allows it.
    const phoneDevice = { key: phone, credential: phoneCred };
    let pending = null; let polls = 0;
    const result = await waitForConfirmation(client, device, {
      onPending: req => { pending = req; },
      clock: () => now,
      sleep: async ms => {
        now += ms;
        if (++polls !== 2) return;
        const { items } = await client.request('GET', '/api/v1/gate-requests', { device: phoneDevice });
        expect(items).toHaveLength(1);
        expect(describeGateRequest(items[0])[0]).toContain('confirm it is still trusted');
        const req = await client.request('GET', `/api/v1/gate-requests/${items[0].id}`, { device: phoneDevice });
        await client.request('POST', `/api/v1/gate-requests/${req.id}/answer`, { device: phoneDevice, body: answerFor(req, { decision: 'allow' }) });
      }
    });
    expect(pending).toMatchObject({ purpose: 'confirm', retry_after: expect.any(Number) });
    expect(result).toMatchObject({ status: 'confirmed', by_timeout: false });
    const confirmation = currentConfirmation(result.confirmation, payload, { now: Math.floor(now / 1000) });
    expect(confirmation).toBe(result.confirmation);
    expect(confirmationHeaders(confirmation)).toEqual({ 'DBA-Confirmation': confirmation });
    expect(confirmationHeaders(null)).toEqual({});
    // It runs out: ask again 30 s before it ends. Another credential's confirmation is not used.
    expect(currentConfirmation(confirmation, payload, { now: result.expires_at - 29 })).toBeNull();
    expect(currentConfirmation(confirmation, { ...payload, cid: 'crd_other' })).toBeNull();

    // A denial comes back as denied, and a wait with nobody answering as a timeout.
    const denied = await waitForConfirmation(client, device, {
      sleep: async () => {
        const [req] = (await client.request('GET', '/api/v1/gate-requests', { device: phoneDevice })).items;
        if (req) await client.request('POST', `/api/v1/gate-requests/${req.id}/answer`, { device: phoneDevice, body: answerFor(req, { decision: 'deny' }) });
      }
    });
    expect(denied).toMatchObject({ status: 'denied', code: 'gate_denied' });
    await expect(client.request('DELETE', `/api/v1/gates/${gate.id}`, { device: phoneDevice })).rejects.toMatchObject({ status: 403 });
    await client.request('DELETE', `/api/v1/gates/${gate.id}`, { apiKey });
  });

  it('gives up waiting for a confirmation at the deadline', async () => {
    let now = 0;
    const client = { request: async () => ({ status: 'pending', gate_request: { id: 'gtr_x', retry_after: 2 } }) };
    const device = { credential: [{ alg: 'ES256' }, { cid: 'crd_x' }].map(p => Buffer.from(JSON.stringify(p)).toString('base64url')).join('.') + '.sig' };
    const result = await waitForConfirmation(client, device, { waitSeconds: 5, clock: () => now, sleep: async ms => { now += ms; } });
    expect(result).toEqual({ status: 'timeout', gate_request: { id: 'gtr_x', retry_after: 2 } });
    expect(now).toBe(4000);
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
    expect(osSecretStore({ platform: 'aix', run: async () => ({ code: 0, stdout: '' }), files: {}, dir: '/x' })).toBeNull();
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
    expect(() => keyStoreOption({ flag: 'hsm' })).toThrow(UsageError);
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

describe('dba curl --dba-wait (STATUS B7 G9)', () => {
  it('takes --dba-wait out of curl\'s arguments and refuses options that hide the response', () => {
    expect(curlWaitOption(['-sS', 'https://x.org/'])).toEqual({ args: ['-sS', 'https://x.org/'], waitSeconds: null });
    expect(curlWaitOption(['--dba-wait', '-X', 'DELETE', 'https://x.org/'])).toEqual({ args: ['-X', 'DELETE', 'https://x.org/'], waitSeconds: 300 });
    expect(curlWaitOption(['https://x.org/', '--dba-wait=45']).waitSeconds).toBe(45);
    expect(() => curlWaitOption(['--dba-wait=soon', 'https://x.org/'])).toThrow(UsageError);
    for (const bad of [['-o', 'out'], ['--output=out'], ['-O'], ['-i'], ['--fail'], ['-sSf'], ['-D', '-'], ['-w', '%{http_code}']]) {
      expect(() => curlWaitOption(['--dba-wait', ...bad, 'https://x.org/'])).toThrow(/drop -/);
    }
    // A value that merely looks like one of them is not an option; nor is -H's header text.
    expect(curlWaitOption(['--dba-wait', '-H', '-o: x', '-d', '-i', 'https://x.org/']).args).toHaveLength(5);
    // In a short cluster, letters after one that takes a value are that value.
    expect(curlWaitOption(['--dba-wait', '-Hfoo: bar', 'https://x.org/']).args).toHaveLength(2);
    expect(() => curlWaitOption(['--dba-wait', '-sHfoo: bar', 'https://x.org/'])).not.toThrow();
  });

  it('knows a gate_pending answer from any other', () => {
    expect(pendingGate(403, JSON.stringify({ code: 'gate_pending', gate_request: { id: 'gtr_1', retry_after: 2 } }))).toEqual({ id: 'gtr_1', retry_after: 2 });
    expect(pendingGate(403, JSON.stringify({ code: 'gate_pending' }))).toEqual({});
    expect(pendingGate(403, JSON.stringify({ code: 'gate_denied' }))).toBeNull();
    expect(pendingGate(200, JSON.stringify({ code: 'gate_pending' }))).toBeNull();
    expect(pendingGate(403, '<html>')).toBeNull();
  });

  it('retries every retry_after seconds until the site answers otherwise or the wait runs out', async () => {
    let now = 0; const sleeps = []; const told = [];
    const pending = { status: 403, body: JSON.stringify({ code: 'gate_pending', gate_request: { id: 'gtr_9', retry_after: 3 } }) };
    const answers = [pending, pending, { status: 200, body: 'ok' }];
    const result = await waitThroughGates(async () => answers.shift(), { waitSeconds: 60, onPending: g => told.push(g.id), sleep: async ms => { sleeps.push(ms); now += ms; }, clock: () => now });
    expect(result).toEqual({ response: { status: 200, body: 'ok' }, gaveUp: false });
    expect(sleeps).toEqual([3000, 3000]);
    expect(told).toEqual(['gtr_9']);
    now = 0;
    const timedOut = await waitThroughGates(async () => pending, { waitSeconds: 10, sleep: async ms => { now += ms; }, clock: () => now });
    expect(timedOut.gaveUp).toBe(true);
    expect(now).toBe(9000);
  });

  it('says where to approve, without the site\'s control characters', () => {
    expect(describePendingGate({ id: 'gtr_1\u001b[2J', approve_url: 'https://devicebasedauth.org/gate.html#dbag_x' })).toBe("dba: waiting for this request's gates (request gtr_1[2J). Approve it at https://devicebasedauth.org/gate.html#dbag_x, or from the dashboard's Approvals page or `dba approvals` on a gate device.");
    expect(describePendingGate({ approve_url: 'javascript:alert(1)' })).not.toContain('javascript');
  });
});
