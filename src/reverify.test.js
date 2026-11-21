import { describe, it, expect, beforeEach } from 'vitest';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';
import { factorAgeMinutes, hasDbaAction } from './auth/reverify.js';

// A stand-in for Clerk's verifier: the "session token" is base64 JSON claims.
const session = (sub, fva) => `Bearer ${btoa(JSON.stringify({ sub, sid: 'sess_1', ...(fva ? { fva } : {}) }))}`;
const fresh = sub => session(sub, [2, -1]);
const stale = sub => session(sub, [45, -1]);
const DBA_GRANTS = [{ actions: ['dba:credentials:read'] }];

let env;
beforeEach(async () => {
  env = await testEnv({ CLERK_SECRET_KEY: 'sk_test', CLERK_VERIFY_TOKEN: async token => JSON.parse(atob(token)) });
  for (const who of ['alice']) await call(env, 'POST', '/api/v1/dev/deposit', { auth: who, body: { amount_microdollars: 1_000_000 } });
});

describe('recent sign-in for account-control operations (S8)', () => {
  it('reads the fva claim', () => {
    expect(factorAgeMinutes({ fva: [3, -1] })).toBe(3);
    expect(factorAgeMinutes({ fva: [30, 1] })).toBe(1);
    expect(factorAgeMinutes({ fva: [-1, -1] })).toBeNull();
    expect(factorAgeMinutes({})).toBeNull();
    expect(hasDbaAction([{ actions: ['hashbin:content:write'] }])).toBe(false);
    expect(hasDbaAction([{ actions: ['hashbin:content:write'] }, { actions: ['dba:session'] }])).toBe(true);
  });

  it('needs a recent sign-in to create API keys', async () => {
    const body = { name: 'k', scopes: ['credentials:read'] };
    const refused = await call(env, 'POST', '/api/v1/keys', { auth: stale('alice'), body });
    expect(refused.status).toBe(403);
    expect(refused.body).toMatchObject({ code: 'reverification_required', max_age_minutes: 10, clerk_error: { reason: 'reverification-error' } });
    expect((await call(env, 'POST', '/api/v1/keys', { auth: session('alice'), body })).body.code).toBe('reverification_required');
    expect((await call(env, 'POST', '/api/v1/keys', { auth: fresh('alice'), body })).status).toBe(200);
    // Reading is fine with any session.
    expect((await call(env, 'GET', '/api/v1/keys', { auth: stale('alice') })).status).toBe(200);
  });

  it('needs a recent sign-in to approve or issue dba:* grants, not other grants', async () => {
    const device = await newDevice();
    const start = await call(env, 'POST', '/api/v1/enrollments', { body: { request: await device.enrollRequest({ aud: ['devicebasedauth.org'], grants: DBA_GRANTS, device: { name: 'admin box' } }) } });
    expect((await call(env, 'POST', '/api/v1/enrollments/approve', { auth: stale('alice'), body: { request: start.body.request } })).body.code).toBe('reverification_required');
    expect((await call(env, 'POST', '/api/v1/enrollments/approve', { auth: fresh('alice'), body: { request: start.body.request } })).status).toBe(200);

    const plain = await newDevice();
    const other = await call(env, 'POST', '/api/v1/enrollments', { body: { request: await plain.enrollRequest({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }] }) } });
    expect((await call(env, 'POST', '/api/v1/enrollments/approve', { auth: stale('alice'), body: { request: other.body.request } })).status).toBe(200);
    // Narrowing a dba:* request down to other grants at approval needs no re-sign-in either.
    const narrowed = await call(env, 'POST', '/api/v1/enrollments', { body: { request: await (await newDevice()).enrollRequest({ aud: ['devicebasedauth.org', 'hashbin.org'], grants: [...DBA_GRANTS, { actions: ['hashbin:content:write'] }] }) } });
    expect((await call(env, 'POST', '/api/v1/enrollments/approve', { auth: stale('alice'), body: { request: narrowed.body.request, grants: [{ actions: ['hashbin:content:write'] }] } })).status).toBe(200);

    const jwk = (await newDevice()).publicJwk;
    expect((await call(env, 'POST', '/api/v1/credentials', { auth: stale('alice'), body: { public_jwk: jwk, aud: ['devicebasedauth.org'], grants: DBA_GRANTS } })).body.code).toBe('reverification_required');
    expect((await call(env, 'POST', '/api/v1/enrollment-tokens', { auth: stale('alice'), body: { aud: ['devicebasedauth.org'], grants: DBA_GRANTS } })).body.code).toBe('reverification_required');
    expect((await call(env, 'POST', '/api/v1/credentials', { auth: fresh('alice'), body: { public_jwk: jwk, aud: ['devicebasedauth.org'], grants: DBA_GRANTS } })).status).toBe(200);
  });

  it('refuses a dashboard device that has not re-verified through a gate, but lets it issue other grants', async () => {
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }] })).approve.body.credential;
    const path = '/api/v1/credentials';
    const jwk = (await newDevice()).publicJwk;
    const refused = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: { public_jwk: jwk, aud: ['devicebasedauth.org'], grants: DBA_GRANTS } });
    expect(refused.status).toBe(403);
    expect(refused.body.error).toContain('/api/v1/session/reverify');
    expect(refused.body.reverify).toEqual({ url: '/api/v1/session/reverify', method: 'POST' });
    const ok = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: { public_jwk: jwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }] } });
    expect(ok.status).toBe(200);
  });

  it('needs a recent sign-in to raise a budget limit, never to lower one', async () => {
    const patch = (auth, body) => call(env, 'PATCH', '/api/v1/account/settings', { auth, body });
    expect((await patch(stale('alice'), { max_issues_per_day: 100 })).status).toBe(200);
    expect((await patch(stale('alice'), { max_renewals_per_credential_per_month: 5 })).status).toBe(200);
    expect((await patch(stale('alice'), { max_issues_per_day: 1000 })).body.code).toBe('reverification_required');
    expect((await patch(stale('alice'), { max_renewals_per_credential_per_month: null })).body.code).toBe('reverification_required');
    expect((await patch(stale('alice'), { max_renewals_per_credential_per_month: 4 })).status).toBe(200);
    expect((await patch(fresh('alice'), { max_issues_per_day: 1000, max_renewals_per_credential_per_month: null })).status).toBe(200);
  });

  it('lets an API key grant only the dba:* actions within its own scopes', async () => {
    const created = await call(env, 'POST', '/api/v1/keys', { auth: fresh('alice'), body: { name: 'ci', scopes: ['credentials:issue', 'credentials:read'] } });
    const key = `ApiKey ${created.body.secret}`;
    const issue = async grants => call(env, 'POST', '/api/v1/credentials', { auth: key, body: { public_jwk: (await newDevice()).publicJwk, aud: ['devicebasedauth.org', 'hashbin.org'], grants } });
    // A key with only credentials:issue once minted a dba:session device with every scope.
    for (const grants of [[{ actions: ['dba:session'] }], [{ actions: ['dba:*'] }], [{ actions: ['dba:credentials:*'] }], [{ actions: ['dba:credentials:revoke'] }], [{ actions: ['hashbin:content:write'] }, { actions: ['dba:audiences:write'] }]]) {
      const refused = await issue(grants);
      expect(refused.status, JSON.stringify(grants)).toBe(403);
      expect(refused.body.code).toBe('insufficient_scope');
    }
    expect((await issue([{ actions: ['dba:credentials:issue', 'dba:credentials:read'] }, { actions: ['hashbin:*'] }])).status).toBe(200);
    const token = await call(env, 'POST', '/api/v1/enrollment-tokens', { auth: key, body: { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }] } });
    expect(token.body.code).toBe('insufficient_scope');
    expect((await call(env, 'POST', '/api/v1/enrollment-tokens', { auth: key, body: { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:credentials:read'] }] } })).status).toBe(200);
    // A person signed in recently is not limited this way.
    expect((await call(env, 'POST', '/api/v1/credentials', { auth: fresh('alice'), body: { public_jwk: (await newDevice()).publicJwk, aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }] } })).status).toBe(200);
  });
});
