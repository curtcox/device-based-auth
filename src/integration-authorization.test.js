import { describe, it, expect, beforeEach } from 'vitest';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';
import { createProof, signJws, inspectCredential } from '../packages/verify/src/index.js';
import { price } from './utils/pricing.js';
import { fund, verifierFor, requestWith } from '../test-utils/integration.js';

// End to end through the Worker: online authorization, where a site asks DBA to decide a request
// (usage limits, replay, step-up approval, billing the audience).

let env;
beforeEach(async () => { env = await testEnv(); });

describe('online authorization', () => {
  async function setup(grants) {
    await fund(env, 'alice'); await fund(env, 'operator');
    const key = await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'hashbin verifier', scopes: ['authorize'] } });
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { grants })).approve.body.credential;
    const ask = async (action = 'hashbin:content:write', extra = {}) => {
      const url = 'https://hashbin.org/api/content';
      const proof = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential });
      return call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key.body.secret}`, body: { credential, proof, request: { method: 'POST', url }, audience: 'hashbin.org', action, ...extra } });
    };
    return { ask, credential, device };
  }

  it('enforces usage limits and bills the audience for every decision', async () => {
    const { ask, credential, device } = await setup([{ actions: ['hashbin:content:write'], limits: { uses: { count: 2, per: 'day' } } }]);
    expect((await ask()).body).toMatchObject({ allow: true, grant_index: 0, cost_microdollars: price('decision') });
    expect((await ask('hashbin:content:write', { context: { network: { country: 'us', region: 'TX', lat: 30.27, lon: -97.74, ip: '203.0.113.9' } } })).body.allow).toBe(true);
    expect((await ask()).body).toMatchObject({ allow: false, reasons: ['usage_limit_reached'] });
    expect((await call(env, 'GET', '/api/v1/account', { auth: 'operator' })).body.today.aggregates.decision).toEqual({ count: 3, amount: 3 * price('decision') });
    // The audience console shows the owner its decisions and spend; nobody else may read them.
    const usage = await call(env, 'GET', '/api/v1/audiences/hashbin.org/usage', { auth: 'operator' });
    expect(usage.body.items[0]).toMatchObject({ decisions: 3, logins: 0, spent_microdollars: 3 * price('decision') });
    expect((await call(env, 'GET', '/api/v1/audiences/hashbin.org/usage', { auth: 'alice' })).status).toBe(403);
    const offline = await verifierFor(env).verifyRequest(await requestWith(device, credential), { action: 'hashbin:content:write' });
    expect(offline).toMatchObject({ allow: false, code: 'online_required', online_required: true });
    const { cid } = inspectCredential(credential).payload;
    const decisions = await call(env, 'GET', `/api/v1/credentials/${cid}/decisions`, { auth: 'alice' });
    expect(decisions.body.items.map(d => d.allow)).toEqual([false, true, true]);
    // Only the coarse country of a decision is kept (master plan §10), never coordinates or IPs.
    expect(decisions.body.items.map(d => d.country)).toEqual([null, 'US', null]);
    expect(JSON.stringify(decisions.body)).not.toMatch(/30\.27|203\.0\.113|TX/);
  });

  it('rejects replayed proofs and revoked credentials immediately', async () => {
    const { credential, device } = await setup([{ actions: ['hashbin:content:write'] }]);
    const key = await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'k', scopes: ['authorize'] } });
    const url = 'https://hashbin.org/api/content';
    const proof = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential });
    const body = { credential, proof, request: { method: 'POST', url }, audience: 'hashbin.org', action: 'hashbin:content:write' };
    expect((await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key.body.secret}`, body })).body.allow).toBe(true);
    expect((await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key.body.secret}`, body })).body.code).toBe('replayed_proof');
    await call(env, 'DELETE', `/api/v1/credentials/${inspectCredential(credential).payload.cid}`, { auth: 'alice' });
    const proof2 = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential });
    expect((await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key.body.secret}`, body: { ...body, proof: proof2 } })).body.code).toBe('revoked');
  });

  it('refuses a credential version whose key was rotated away (STATUS L12)', async () => {
    const { ask, credential, device } = await setup([{ actions: ['hashbin:content:write'] }]);
    const { cid } = inspectCredential(credential).payload;
    const next = await newDevice();
    const path = `/api/v1/credentials/${cid}/renew`;
    const keyProof = await signJws({ typ: 'dba-rotate+jwt', jwk: next.publicJwk }, { cid, iat: Math.floor(Date.now() / 1000) }, next.privateKey);
    const rotated = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: { new_key_proof: keyProof } });
    expect(rotated.body.rotated).toBe(true);
    // The old key (perhaps the reason for rotating) still signs proofs for the old, unexpired version.
    expect((await ask()).body).toMatchObject({ allow: false, code: 'revoked' });
  });

  it('refuses access tokens once the audience stops accepting them', async () => {
    const { credential, device } = await setup([{ actions: ['hashbin:content:write'] }]);
    const token = (await call(env, 'POST', '/api/v1/token', { headers: await device.headers('POST', '/api/v1/token', credential), body: { audience: 'hashbin.org' } })).body.access_token;
    const key = await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'k', scopes: ['authorize', 'audiences:write'] } });
    const body = { credential: token, audience: 'hashbin.org', action: 'hashbin:content:write' };
    expect(token).toBeTruthy();
    // (Online decisions cache the audience record for a minute, so this asks only after the change.)
    expect((await call(env, 'PATCH', '/api/v1/audiences/hashbin.org', { auth: `ApiKey ${key.body.secret}`, body: { accept_access_tokens: false } })).status).toBe(200);
    const refused = await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key.body.secret}`, body });
    expect(refused.body).toMatchObject({ allow: false, code: 'access_tokens_refused' });
  });

  it('does not spend a step-up approval, or ask for one, when the grant is out of uses', async () => {
    const { ask } = await setup([{ actions: ['hashbin:content:delete'], require: { step_up: true }, limits: { uses: { count: 1, per: 'day' } } }]);
    const first = await ask('hashbin:content:delete');
    expect(first.body.code).toBe('step_up_required');
    await call(env, 'POST', `/api/v1/step-ups/${first.body.step_up.id}/approve`, { auth: 'alice', body: {} });
    expect((await ask('hashbin:content:delete')).body.allow).toBe(true);
    expect((await ask('hashbin:content:delete')).body).toMatchObject({ allow: false, code: 'forbidden', reasons: ['usage_limit_reached'] });
    expect((await call(env, 'GET', '/api/v1/step-ups', { auth: 'alice' })).body.items).toHaveLength(0);
  });

  it('refuses require.confirmation set by hand, and gates that do not exist (STATUS B7)', async () => {
    await fund(env, 'alice');
    for (const [require, code] of [[{ confirmation: true }, 'invalid_grants'], [{ gates: [{ any: ['gate_NOSUCHGATE1'] }] }, 'unknown_gate']]) {
      const { approve } = await enroll(env, 'alice', await newDevice(), { grants: [{ actions: ['hashbin:content:write'], require }] });
      expect(approve.body.code).toBe(code);
      expect(approve.status).toBe(400);
    }
  });

  it('requires owner approval for step-up grants', async () => {
    const { ask } = await setup([{ actions: ['hashbin:content:delete'], require: { step_up: true } }]);
    const first = await ask('hashbin:content:delete');
    expect(first.body).toMatchObject({ allow: false, code: 'step_up_required' });
    const pending = await call(env, 'GET', '/api/v1/step-ups', { auth: 'alice' });
    expect(pending.body.items).toHaveLength(1);
    await call(env, 'POST', `/api/v1/step-ups/${first.body.step_up.id}/approve`, { auth: 'alice', body: {} });
    expect((await ask('hashbin:content:delete')).body.allow).toBe(true);
    expect((await ask('hashbin:content:delete')).body.code).toBe('step_up_required');
  });

  it('does not let a dashboard device approve its own step-up request (STATUS L12)', async () => {
    await fund(env, 'alice'); await fund(env, 'operator');
    const key = await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'k', scopes: ['authorize'] } });
    const device = await newDevice();
    const grants = [{ actions: ['dba:session'] }, { actions: ['hashbin:content:delete'], require: { step_up: true } }];
    const credential = (await enroll(env, 'alice', device, { aud: ['hashbin.org', 'devicebasedauth.org'], grants })).approve.body.credential;
    const url = 'https://hashbin.org/api/content';
    const ask = async () => call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key.body.secret}`, body: { credential, proof: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential }), request: { method: 'POST', url }, audience: 'hashbin.org', action: 'hashbin:content:delete' } });
    const { step_up } = (await ask()).body;
    const path = `/api/v1/step-ups/${step_up.id}/approve`;
    const self = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: {} });
    expect(self).toMatchObject({ status: 403, body: { code: 'self_approval' } });
    expect((await ask()).body.code).toBe('step_up_required');
    // Another dashboard device, or the signed-in owner, may approve it.
    const laptop = await newDevice();
    const other = (await enroll(env, 'alice', laptop, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }] })).approve.body.credential;
    expect((await call(env, 'POST', path, { headers: await laptop.headers('POST', path, other), body: {} })).status).toBe(200);
    expect((await ask()).body.allow).toBe(true);
  });

  it('asks once per thing to approve, deletes an approval when spent, and lets a denial stand', async () => {
    const { ask } = await setup([{ actions: ['hashbin:content:delete', 'hashbin:content:write'], require: { step_up: true } }]);
    const first = (await ask('hashbin:content:delete')).body;
    // Retrying while the request waits reuses it (no new row, no new notice).
    expect((await ask('hashbin:content:delete')).body.step_up.id).toBe(first.step_up.id);
    const other = (await ask('hashbin:content:write')).body;
    expect(other.step_up.id).not.toBe(first.step_up.id);
    expect((await call(env, 'GET', '/api/v1/step-ups', { auth: 'alice' })).body.items).toHaveLength(2);
    await call(env, 'POST', `/api/v1/step-ups/${first.step_up.id}/approve`, { auth: 'alice', body: {} });
    expect((await call(env, 'POST', `/api/v1/step-ups/${first.step_up.id}/deny`, { auth: 'alice', body: {} })).status).toBe(404);
    expect((await ask('hashbin:content:delete')).body.allow).toBe(true);
    const account = [...env.ACCOUNTS.objects.values()].find(o => o.storage.rows.has(`gatereq:${other.step_up.id}`));
    expect(account.storage.rows.has(`gatereq:${first.step_up.id}`)).toBe(false);
    await call(env, 'POST', `/api/v1/step-ups/${other.step_up.id}/deny`, { auth: 'alice', body: {} });
    expect((await ask('hashbin:content:write')).body).toMatchObject({ allow: false, code: 'step_up_denied', reasons: ['step_up_denied'] });
    expect((await call(env, 'GET', '/api/v1/step-ups', { auth: 'alice' })).body.items).toHaveLength(0);
  });

  it('only lets an audience owner ask, and needs funds', async () => {
    const { credential } = await setup([{ actions: ['hashbin:content:write'] }]);
    const mallory = await call(env, 'POST', '/api/v1/keys', { auth: 'mallory', body: { name: 'k', scopes: ['authorize'] } });
    const denied = await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${mallory.body.secret}`, body: { credential, audience: 'hashbin.org', action: 'hashbin:content:write' } });
    expect(denied.status).toBe(403);
  });
});
