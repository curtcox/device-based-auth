import { describe, it, expect, beforeEach } from 'vitest';
import { UsageError } from './errors.js';
import { createClient } from './client.js';
import { enrollmentPayload, enrollmentTokenOption, signEnrollmentRequest, rotationProof, pollEnrollment } from './enrollment.js';
import { newDeviceKey, credentialMatchesKey } from './device-key.js';
import { inspectCredential } from '../verify/src/index.js';
import { testEnv, call, worker, ORIGIN } from '../../test-utils/env.js';

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
