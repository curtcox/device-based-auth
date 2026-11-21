import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { newDevice, call, ORIGIN } from '../test-utils/env.js';
import { clerkFreeEnv, signUp, asDevice, paidEvent, sendWebhook } from '../test-utils/signup.js';
import { softAuthenticator } from '../test-utils/authenticator.js';
import { inspectCredential } from '../packages/verify/src/index.js';
import { answerChallenge } from './services/webauthn.js';
import { API_ROUTES } from './index.js';
import { canAccess, SESSION } from './auth/scopes.js';

// The claim in the docs (done/clerk_free_accounts.md, STATUS B9): a paid account can be created,
// funded, used, administered and recovered with only a device and a card, never Clerk. This test
// is the whole life of one such account, run as production with every CLERK_* variable unset,
// through an env that records any read of a CLERK_* variable: if any step comes to depend on
// Clerk, it fails here.

const MINUTE = 60000;
let env; let stripe; let clerkReads; const realNow = Date.now; let t;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  let raw;
  ({ env: raw, stripe } = await clerkFreeEnv());
  clerkReads = new Set();
  env = new Proxy(raw, { get(target, name, receiver) { if (typeof name === 'string' && name.startsWith('CLERK_')) clerkReads.add(name); return Reflect.get(target, name, receiver); } });
});
afterEach(() => { Date.now = realNow; });

/** Every route the journey calls, so the guard below can check each one. */
const used = new Set();
const track = (method, path) => { used.add(`${method} ${path.split('?')[0]}`); };

describe('a paid account without Clerk, from sign-up to recovery (B9)', () => {
  it('lives its whole life with a device and a card', async () => {
    // 1. Sign up: pay the first deposit with a new browser key.
    const laptop = await newDevice();
    const { account, credential } = await signUp(env, stripe, laptop);
    ['POST /api/v1/signup', 'POST /webhooks/stripe', 'POST /api/v1/signup/complete'].forEach(r => used.add(r));
    expect(account).toMatch(/^acct_/);
    const as = (device, cred) => { const call_ = asDevice(env, device, cred); return (method, path, options) => { track(method, path); return call_(method, path, options); }; };
    const laptopCall = as(laptop, credential);
    expect((await laptopCall('GET', '/api/v1/whoami')).body).toMatchObject({ account });

    // 2. In the ten minutes the payment counts as a sign-in: recovery codes and a passkey.
    const sheet = (await laptopCall('POST', '/api/v1/settings/recovery-codes')).body;
    expect(sheet).toMatchObject({ account, codes: expect.any(Array) });
    const passkey = await softAuthenticator();
    const created = (await laptopCall('POST', '/api/v1/gates', { body: { kind: 'webauthn', label: 'Passkey' } })).body;
    const registration = await passkey.register(created.setup.public_key, ORIGIN);
    expect((await laptopCall('POST', `/api/v1/gates/${created.id}/activate`, { body: { registration } })).body.state).toBe('active');
    expect((await laptopCall('GET', '/api/v1/account/recovery')).body).toMatchObject({ recovery_codes_left: 10, at_risk: false });

    // 3. Use it: a credential for another site, and a second deposit.
    const server = await newDevice();
    const issued = (await laptopCall('POST', '/api/v1/credentials', { body: { public_jwk: server.publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], device: { name: 'Build server' } } })).body;
    expect(inspectCredential(issued.credential).payload.acct).toBe(account);
    expect((await laptopCall('POST', '/api/v1/payments/checkout', { body: { credit_cents: 1000 }, headers: { 'Idempotency-Key': 'top-up' } })).status).toBe(200);
    await sendWebhook(env, paidEvent(stripe.sessions.at(-1)));
    expect((await laptopCall('GET', '/api/v1/transactions')).body.items.filter(i => i.kind === 'deposit')).toHaveLength(2);

    // 4. Later, account control needs a confirmation: the passkey gives it.
    t += 30 * MINUTE;
    expect((await laptopCall('POST', '/api/v1/keys', { body: { name: 'verifier', scopes: ['authorize'] } })).body.code).toBe('reverification_required');
    const pending = (await laptopCall('POST', '/api/v1/session/reverify', { body: {} })).body;
    const { factors, id } = pending.gate_request;
    const challenge = await answerChallenge({ requestId: id, entry: 0, decision: 'allow', salt: factors.salt });
    const webauthn = await passkey.assert({ challenge, rpId: factors.rp_id }, ORIGIN);
    expect((await laptopCall('POST', '/api/v1/session/reverify', { body: { gate: created.id, webauthn } })).body.status).toBe('reverified');

    // 5. Administer: an API key that reads credentials, and a second dashboard device. The site's
    // credential checks out for the site (offline verifiers check the same signature and status).
    const key = (await laptopCall('POST', '/api/v1/keys', { body: { name: 'reader', scopes: ['credentials:read'] } })).body.secret;
    track('GET', '/api/v1/credentials');
    expect((await call(env, 'GET', '/api/v1/credentials', { auth: `ApiKey ${key}` })).body.items.map(c => c.cid)).toContain(issued.cid);
    track('POST', '/api/v1/inspect');
    const checked = (await call(env, 'POST', '/api/v1/inspect', { body: { credential: issued.credential, audience: 'hashbin.org', check: { action: 'hashbin:content:write' } } })).body;
    expect(checked).toMatchObject({ valid: true, revoked: false, payload: { acct: account }, evaluation: { allow: true } });
    const desktop = await newDevice();
    track('POST', '/api/v1/enrollments');
    const start = await call(env, 'POST', '/api/v1/enrollments', { body: { request: await desktop.enrollRequest({ aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }], device: { name: 'Desktop browser' } }) } });
    const approved = await laptopCall('POST', '/api/v1/enrollments/approve', { body: { request: start.body.request } });
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);

    // 6. Both browsers are lost. A recovery code puts a new phone on the account.
    t += 30 * MINUTE;
    const phone = await newDevice();
    track('POST', '/api/v1/recover');
    const recovered = await call(env, 'POST', '/api/v1/recover', { body: { account, code: sheet.codes[0], request: await phone.enrollRequest({ device: { name: 'New phone' } }) } });
    expect(recovered.body.status).toBe('recovered');
    const phoneCall = as(phone, recovered.body.credential);
    const devices = (await phoneCall('GET', '/api/v1/devices')).body.items;
    for (const name of ['Laptop browser', 'Desktop browser']) expect((await phoneCall('POST', `/api/v1/devices/${devices.find(d => d.name === name).id}/revoke`)).status).toBe(200);
    expect((await laptopCall('GET', '/api/v1/whoami')).body.code).toBe('revoked');
    expect((await phoneCall('POST', '/api/v1/settings/recovery-codes')).body.codes).toHaveLength(10);
    expect((await phoneCall('GET', '/api/v1/account')).body.balance_microdollars).toBeGreaterThan(0);

    // Nothing on the way asked for Clerk.
    expect([...clerkReads]).toEqual([]);

    // And every route the journey used is public, or open to a dashboard device (dba:session) or
    // an API key; none is reserved to a browser session.
    const device = { kind: 'device', session: false, device: { dba: true, payload: { grants: [{ actions: ['dba:session'] }] }, location: {} } };
    const declared = path => API_ROUTES.find(r => `${r.method} ${r.path}` === path || new RegExp(`^${r.method} ${r.path.replace(/:[a-z_]+/g, '[^/]+')}$`).test(path));
    expect(used.size).toBeGreaterThan(15);
    const key_ = { kind: 'key', session: false, scopes: ['credentials:read'] };
    for (const path of used) {
      const route = declared(path);
      expect(route, path).toBeTruthy();
      if (route.access === 'public') continue;
      expect(canAccess(device, route.access) || canAccess(key_, route.access), `${path} (${JSON.stringify(route.access)})`).toBe(true);
    }
    expect(canAccess(device, SESSION)).toBe(true);
  });
});
