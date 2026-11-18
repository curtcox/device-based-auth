import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { testEnv, call, newDevice, enroll, settle } from '../test-utils/env.js';
import { pushBrowser, pushService } from '../test-utils/push.js';
import { inspectCredential, signJws, createProof } from '../packages/verify/src/index.js';
import { NOTICE_INTERVAL_MS, MAX_SUBSCRIPTIONS } from './services/push.js';

// Master plan §10: account takeover means control of every device, so the owner's browsers are
// told (Web Push) when credentials, API keys or enrollment tokens are issued.

let env; let service; let browser; const realNow = Date.now; let t;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  service = pushService(url => url.includes('gone') ? 410 : 201);
  env = await testEnv({ PUSH_FETCH: service.fetch });
  browser = await pushBrowser();
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
});
afterEach(() => { Date.now = realNow; });

async function notices(of = browser) {
  await settle(env);
  const mine = service.sent.filter(s => s.url === of.subscription.endpoint);
  return Promise.all(mine.map(s => of.decrypt(s.init.body)));
}
const subscribe = (b = browser, name = 'My laptop') => call(env, 'POST', '/api/v1/push-subscriptions', { auth: 'alice', body: { subscription: b.subscription, name } });

describe('security notices', () => {
  it('publishes the VAPID key and lets a signed-in owner subscribe, list and unsubscribe browsers', async () => {
    expect((await call(env, 'GET', '/api/public/config')).body.push_public_key).toMatch(/^B[A-Za-z0-9_-]{86}$/);
    const added = await subscribe();
    expect(added.status).toBe(200);
    expect(added.body).toMatchObject({ name: 'My laptop', push_service: 'fcm.googleapis.com', delivered: true });
    expect((await notices())[0]).toMatchObject({ title: 'Security notices are on', url: 'http://localhost:8787/app.html#account' });
    const list = await call(env, 'GET', '/api/v1/push-subscriptions', { auth: 'alice' });
    expect(list.body.items).toEqual([{ id: added.body.id, name: 'My laptop', push_service: 'fcm.googleapis.com', created_at: t }]);
    expect(JSON.stringify(list.body)).not.toContain(browser.subscription.keys.auth);
    // Subscribing the same browser again refreshes it instead of adding another.
    expect((await subscribe(browser, 'Renamed')).body.id).toBe(added.body.id);
    expect((await call(env, 'GET', '/api/v1/push-subscriptions', { auth: 'alice' })).body.items).toHaveLength(1);
    // Others cannot see or remove it; API keys and devices without dba:session cannot either.
    expect((await call(env, 'GET', '/api/v1/push-subscriptions', { auth: 'bob' })).body.items).toEqual([]);
    expect((await call(env, 'DELETE', `/api/v1/push-subscriptions/${added.body.id}`, { auth: 'bob' })).status).toBe(404);
    const removed = await call(env, 'DELETE', `/api/v1/push-subscriptions/${added.body.id}`, { auth: 'alice' });
    expect(removed.body).toMatchObject({ removed: true });
    // The removed browser itself hears that it was turned off.
    expect((await notices()).at(-1)).toMatchObject({ title: 'Security notices turned off' });
    expect((await call(env, 'GET', '/api/v1/push-subscriptions', { auth: 'alice' })).body.items).toEqual([]);
    const audit = (await call(env, 'GET', '/api/v1/audit', { auth: 'alice' })).body.items.map(e => e.type);
    expect(audit).toEqual(expect.arrayContaining(['push.subscribed', 'push.unsubscribed']));
  });

  it('refuses endpoints that are not browser push services, and more than the cap', async () => {
    const evil = await pushBrowser('https://evil.example/collect');
    expect((await subscribe(evil)).body.code).toBe('invalid_subscription');
    for (let i = 0; i < MAX_SUBSCRIPTIONS; i++) expect((await subscribe(await pushBrowser(`https://fcm.googleapis.com/fcm/send/${i}`))).status).toBe(200);
    const extra = await subscribe(await pushBrowser('https://fcm.googleapis.com/fcm/send/extra'));
    expect(extra.status).toBe(409);
    expect(extra.body.code).toBe('too_many_subscriptions');
  });

  it('announces issuance once an hour, counting the issuances held back in between', async () => {
    await subscribe();
    const device = await newDevice();
    const { approve } = await enroll(env, 'alice', device, { name: 'Build‮ server' });
    const cid = inspectCredential(approve.body.credential).payload.cid;
    let got = await notices();
    expect(got).toHaveLength(2);
    expect(got[1]).toEqual({ title: 'Credential issued', body: 'Build server for hashbin.org.', url: `http://localhost:8787/app.html#credential/${cid}`, tag: 'issued' });
    await enroll(env, 'alice', await newDevice());
    await enroll(env, 'alice', await newDevice());
    expect(await notices()).toHaveLength(2);
    t += NOTICE_INTERVAL_MS;
    await enroll(env, 'alice', await newDevice(), { name: 'Phone' });
    got = await notices();
    expect(got).toHaveLength(3);
    expect(got[2].body).toBe('Phone for hashbin.org (and 2 more since the last notice).');
    // Holding notices back writes nothing extra: the state rides on the balance row.
    const account = [...env.ACCOUNTS.objects.values()].find(o => o.storage.rows.has('push:subs'));
    expect(account.storage.rows.get('balance').notice).toEqual({ at: t, pending: 0 });
  });

  it('announces every credential with account access, API key and enrollment token at once', async () => {
    await subscribe();
    await enroll(env, 'alice', await newDevice());
    await enroll(env, 'alice', await newDevice(), { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }], name: 'Laptop' });
    await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'CI', scopes: ['credentials:read'] } });
    await call(env, 'POST', '/api/v1/enrollment-tokens', { auth: 'alice', body: { name: 'Fleet', aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], max_uses: 10 } });
    const got = await notices();
    expect(got.map(n => n.title)).toEqual(['Security notices are on', 'Credential issued', 'Credential with account access issued', 'API key created', 'Enrollment token created']);
    expect(got[2].body).toBe('Laptop for devicebasedauth.org can now act on your devicebasedauth.org account.');
    expect(got[3].body).toContain('“CI”');
    expect(got[4].body).toBe('“Fleet” lets up to 10 devices enroll for hashbin.org without approval.');
  });

  it('announces a key rotation like an issuance', async () => {
    await subscribe();
    const device = await newDevice(); const next = await newDevice();
    const credential = (await enroll(env, 'alice', device, { name: 'Agent' })).approve.body.credential;
    const { cid } = inspectCredential(credential).payload;
    t += NOTICE_INTERVAL_MS;
    const path = `/api/v1/credentials/${cid}/renew`;
    const keyProof = await signJws({ typ: 'dba-rotate+jwt', jwk: next.publicJwk }, { cid, iat: Math.floor(t / 1000) }, next.privateKey);
    expect((await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: { new_key_proof: keyProof } })).body.rotated).toBe(true);
    expect((await notices()).at(-1)).toMatchObject({ title: 'Credential moved to a new key', body: 'Agent rotated its credential for hashbin.org to a new key.' });
    // A plain renewal is not announced.
    const before = service.sent.length;
    const renewed = (await call(env, 'GET', `/api/v1/credentials/${cid}`, { auth: 'alice' })).body.jws;
    expect((await call(env, 'POST', path, { headers: await next.headers('POST', path, renewed), body: {} })).status).toBe(200);
    await settle(env);
    expect(service.sent.length).toBe(before);
  });

  it('tells the owner at once when a device asks for a step-up approval, once per request', async () => {
    await subscribe();
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'operator', body: { amount_microdollars: 1_000_000 } });
    const key = await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'verifier', scopes: ['authorize'] } });
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { name: 'Deploy bot', grants: [{ actions: ['hashbin:content:delete'], require: { step_up: true } }] })).approve.body.credential;
    const url = 'https://hashbin.org/api/content';
    const ask = async () => call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key.body.secret}`, body: { credential, proof: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential }), request: { method: 'POST', url }, audience: 'hashbin.org', action: 'hashbin:content:delete', resource: 'abc' } });
    const first = await ask();
    await ask();
    const asks = (await notices()).filter(n => n.title === 'Approval needed');
    expect(asks).toEqual([{ title: 'Approval needed', body: 'Deploy bot asks to hashbin:content:delete on abc at hashbin.org. Approve or deny within 10 minutes.', url: 'http://localhost:8787/app.html#approvals', tag: `stepup-${first.body.step_up.id}` }]);
  });

  it('drops a browser whose push service says it is gone', async () => {
    const gone = await pushBrowser('https://fcm.googleapis.com/fcm/send/gone');
    await subscribe();
    const added = await subscribe(gone, 'Old phone');
    expect(added.body.delivered).toBe(false);
    await settle(env);
    expect((await call(env, 'GET', '/api/v1/push-subscriptions', { auth: 'alice' })).body.items.map(s => s.name)).toEqual(['My laptop']);
  });

  it('costs an account without subscriptions nothing extra', async () => {
    const spy = vi.fn(service.fetch); env.PUSH_FETCH = spy;
    await enroll(env, 'alice', await newDevice());
    await settle(env);
    expect(spy).not.toHaveBeenCalled();
    const account = [...env.ACCOUNTS.objects.values()].find(o => o.storage.rows.has('balance'));
    expect(account.storage.rows.get('balance').notice).toBeUndefined();
  });

  it('is unavailable without a VAPID key outside local development', async () => {
    const prod = await testEnv({ ENVIRONMENT: 'production', PUSH_FETCH: service.fetch });
    expect((await call(prod, 'GET', '/api/public/config')).body.push_public_key).toBeNull();
  });
});
