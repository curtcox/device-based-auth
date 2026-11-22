import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';

// DPoP nonces (STATUS L12, D15): the account's object keeps the proofs it has seen in memory, which
// starts empty when the object starts (an eviction after idle, a deploy, a move). For the first
// CLOCK_SKEW seconds it cannot rule out that a proof was used before, so it asks for its own nonce
// (RFC 9449 §8), which no earlier object could have handed out.

const realNow = Date.now; let t;
let env; let device; let credential;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  env = await testEnv();
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
  device = await newDevice();
  credential = (await enroll(env, 'alice', device)).approve.body.credential;
});
afterEach(() => { Date.now = realNow; });

const whoami = async (headers) => call(env, 'GET', '/api/v1/whoami', { headers });

describe('DPoP nonces after the account object starts', () => {
  it('asks a just-started object\'s callers for its nonce, then accepts the proof that carries it', async () => {
    env.ACCOUNTS.restart('alice');
    const challenged = await whoami(await device.headers('GET', '/api/v1/whoami', credential));
    expect(challenged.status).toBe(401);
    expect(challenged.body.code).toBe('use_dpop_nonce');
    expect(challenged.body.dpop_nonce).toMatch(/^dpn_\w+$/);
    expect(challenged.headers.get('DPoP-Nonce')).toBe(challenged.body.dpop_nonce);
    expect(challenged.headers.get('WWW-Authenticate')).toBe('DPoP error="use_dpop_nonce"');
    expect(challenged.headers.get('Access-Control-Expose-Headers')).toMatch(/DPoP-Nonce/);
    const ok = await whoami(await device.headers('GET', '/api/v1/whoami', credential, challenged.body.dpop_nonce));
    expect(ok.status).toBe(200);
    expect(ok.body.account).toBe('alice');
    // A wrong nonce is asked again.
    expect((await whoami(await device.headers('GET', '/api/v1/whoami', credential, 'dpn_wrong'))).body.code).toBe('use_dpop_nonce');
  });

  it('refuses a proof used before the object restarted (the replay it closes)', async () => {
    const headers = await device.headers('POST', '/api/v1/token', credential);
    const body = { audience: 'hashbin.org' };
    expect((await call(env, 'POST', '/api/v1/token', { headers, body })).status).toBe(200);
    expect((await call(env, 'POST', '/api/v1/token', { headers, body })).body.code).toBe('replayed_proof');
    // The object forgets the proofs it saw: the same headers must not work again.
    env.ACCOUNTS.restart('alice');
    t += 30_000;
    expect((await call(env, 'POST', '/api/v1/token', { headers, body })).body.code).toBe('use_dpop_nonce');
  });

  it('needs no nonce once the object has run for a minute, and a nonce ends with its object', async () => {
    env.ACCOUNTS.restart('alice');
    const nonce = (await whoami(await device.headers('GET', '/api/v1/whoami', credential))).body.dpop_nonce;
    t += 61_000;
    expect((await whoami(await device.headers('GET', '/api/v1/whoami', credential))).status).toBe(200);
    env.ACCOUNTS.restart('alice');
    const again = await whoami(await device.headers('GET', '/api/v1/whoami', credential, nonce));
    expect(again.body.code).toBe('use_dpop_nonce');
    expect(again.body.dpop_nonce).not.toBe(nonce);
  });

  it('hands out the nonce for free to clients that cannot send twice', async () => {
    const ask = async nonce => call(env, 'POST', '/api/v1/dpop-nonce', { headers: await device.headers('POST', '/api/v1/dpop-nonce', credential, nonce) });
    const running = await ask();
    expect(running.status).toBe(200);
    expect(running.body).toMatchObject({ dpop_nonce: expect.stringMatching(/^dpn_\w+$/), cost_microdollars: 0 });
    expect(running.headers.get('DPoP-Nonce')).toBe(running.body.dpop_nonce);
    env.ACCOUNTS.restart('alice');
    const fresh = await ask();
    expect(fresh.body.code).toBe('use_dpop_nonce');
    expect((await ask(fresh.body.dpop_nonce)).body.dpop_nonce).toBe(fresh.body.dpop_nonce);
    expect((await call(env, 'POST', '/api/v1/dpop-nonce', { auth: 'alice' })).status).toBe(403);
  });

  it('lets local development start a new nonce epoch on purpose', async () => {
    expect((await call(env, 'POST', '/api/v1/dev/fresh-object', { auth: 'alice' })).body).toMatchObject({ fresh: true });
    expect((await whoami(await device.headers('GET', '/api/v1/whoami', credential))).body.code).toBe('use_dpop_nonce');
    const production = await testEnv({ ENVIRONMENT: 'production' });
    expect((await call(production, 'POST', '/api/v1/dev/fresh-object', { auth: 'alice' })).status).not.toBe(200);
  });
});
