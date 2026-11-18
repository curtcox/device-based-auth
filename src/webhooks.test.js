import { describe, it, expect, beforeEach } from 'vitest';
import { testEnv, call, newDevice, enroll, runAlarms, worker, ORIGIN } from '../test-utils/env.js';
import { createVerifier, createProof, inspectCredential, verifyEvent, decodeJws } from '../packages/verify/src/index.js';
import { cleanWebhookUrl } from './services/webhooks.js';

const fund = (env, account, dollars = 1) => call(env, 'POST', '/api/v1/dev/deposit', { auth: account, body: { amount_microdollars: dollars * 1_000_000 } });
const HOOK = 'https://hashbin.org/hooks/dba';

let env; let sent; let answer;
beforeEach(async () => {
  sent = []; answer = () => new Response('ok');
  env = await testEnv({ WEBHOOK_FETCH: async (url, init) => { sent.push({ url, body: init.body, headers: init.headers, redirect: init.redirect }); return answer(url); } });
  await fund(env, 'alice'); await fund(env, 'operator');
});

const setHook = (url = HOOK) => call(env, 'PATCH', '/api/v1/audiences/hashbin.org', { auth: 'operator', body: { revocation_webhook: url } });
const jwks = async () => (await call(env, 'GET', '/.well-known/jwks.json')).body;
const verifierFor = (audience = 'hashbin.org') => createVerifier({ issuer: ORIGIN, audience, statusTtl: 3600, fetch: (url, init) => worker.fetch(new Request(url, init), env) });
const requestWith = async (device, credential, url = 'https://hashbin.org/api/content') => new Request(url, { method: 'POST', headers: { Authorization: `DBA ${credential}`, DPoP: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential }) } });

describe('revocation webhooks (B1)', () => {
  it('only accepts https URLs on the audience domain, and hides the URL from the public record', () => {
    const prod = { ENVIRONMENT: 'production' };
    expect(cleanWebhookUrl('https://hashbin.org/hooks', 'hashbin.org', prod)).toBe('https://hashbin.org/hooks');
    expect(cleanWebhookUrl('https://api.hashbin.org/x', 'hashbin.org', prod)).toBe('https://api.hashbin.org/x');
    expect(cleanWebhookUrl(null, 'hashbin.org', prod)).toBeNull();
    for (const bad of ['http://hashbin.org/x', 'https://evil.example/x', 'https://nothashbin.org/x', 'https://hashbin.org:8443/x', 'https://u:p@hashbin.org/x', 'not a url', 'https://169.254.169.254/']) {
      expect(() => cleanWebhookUrl(bad, 'hashbin.org', prod), bad).toThrow();
    }
    expect(cleanWebhookUrl('http://localhost:9000/hook', 'localhost:8787', { ENVIRONMENT: 'local' })).toBe('http://localhost:9000/hook');
  });

  it('is set by the owner only, and is not in the public audience record', async () => {
    expect((await call(env, 'PATCH', '/api/v1/audiences/hashbin.org', { auth: 'alice', body: { revocation_webhook: HOOK } })).status).toBe(403);
    expect((await setHook('https://evil.example/hook')).body.code).toBe('invalid_webhook');
    expect((await setHook()).body.revocation_webhook).toBe(HOOK);
    expect((await call(env, 'GET', '/api/v1/audiences/hashbin.org')).body.revocation_webhook).toBeUndefined();
    const mine = await call(env, 'GET', '/api/v1/audiences?mine=1', { auth: 'operator' });
    expect(mine.body.items.find(a => a.name === 'hashbin.org').revocation_webhook).toBe(HOOK);
  });

  it('sends a signed test event on request and reports the endpoint answer', async () => {
    expect((await call(env, 'POST', '/api/v1/audiences/hashbin.org/webhook-test', { auth: 'operator' })).body.code).toBe('no_webhook');
    await setHook();
    const ok = await call(env, 'POST', '/api/v1/audiences/hashbin.org/webhook-test', { auth: 'operator' });
    expect(ok.body).toMatchObject({ url: HOOK, delivered: true, status: 200 });
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ url: HOOK, redirect: 'manual' });
    expect(sent[0].headers['Content-Type']).toBe('application/jwt');
    const { payload } = await verifyEvent(sent[0].body, { jwks: await jwks(), issuer: ORIGIN, audience: 'hashbin.org' });
    expect(payload).toMatchObject({ type: 'webhook.test', aud: 'hashbin.org', jti: ok.body.event_id });
    answer = () => new Response('nope', { status: 500 });
    expect((await call(env, 'POST', '/api/v1/audiences/hashbin.org/webhook-test', { auth: 'operator' })).body).toMatchObject({ delivered: false, status: 500 });
    expect((await call(env, 'POST', '/api/v1/audiences/hashbin.org/webhook-test', { auth: 'alice' })).status).toBe(403);
  });

  it('pushes a signed revocation that an offline verifier applies before its status-list cache expires', async () => {
    await setHook();
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device)).approve.body.credential;
    const { cid, jti, status } = inspectCredential(credential).payload;
    const verifier = verifierFor();
    expect((await verifier.verifyRequest(await requestWith(device, credential), { action: 'hashbin:content:write' })).allow).toBe(true);

    await call(env, 'DELETE', `/api/v1/credentials/${cid}`, { auth: 'alice' });
    expect(sent).toHaveLength(0); // the revoke itself never waits on the audience's endpoint
    await runAlarms(env);
    expect(sent).toHaveLength(1);
    const { payload } = decodeJws(sent[0].body);
    expect(payload).toMatchObject({ type: 'credentials.revoked', aud: 'hashbin.org', credentials: [{ cid, jti, status: status.status_list }] });

    // The verifier's status list is cached for an hour; the pushed event revokes at once.
    expect((await verifier.verifyRequest(await requestWith(device, credential), { action: 'hashbin:content:write' })).allow).toBe(true);
    const handled = await verifier.handleEvent(sent[0].body);
    expect(handled).toMatchObject({ ok: true, type: 'credentials.revoked', duplicate: false });
    expect(await verifier.verifyRequest(await requestWith(device, credential), { action: 'hashbin:content:write' })).toMatchObject({ allow: false, code: 'revoked' });
    expect((await verifier.handleEvent(sent[0].body)).duplicate).toBe(true);

    // Another audience's verifier refuses the event, and a tampered body fails.
    expect(await verifierFor('cronly.org').handleEvent(sent[0].body)).toMatchObject({ ok: false, code: 'wrong_audience', status: 400 });
    const [h, p, sig] = sent[0].body.split('.');
    expect((await verifier.handleEvent(`${h}.${p}x.${sig}`)).ok).toBe(false);
    expect(await call(env, 'GET', '/api/v1/credentials/' + cid, { auth: 'alice' })).toMatchObject({ body: { state: 'revoked' } });
  });

  it('retries a failing endpoint with backoff, then gives up; status lists are unaffected', async () => {
    await setHook();
    const device = await newDevice();
    const { cid } = inspectCredential((await enroll(env, 'alice', device)).approve.body.credential).payload;
    answer = () => new Response('down', { status: 503 });
    await call(env, 'DELETE', `/api/v1/credentials/${cid}`, { auth: 'alice' });
    const account = [...env.ACCOUNTS.objects.values()].find(o => o.storage.rows.has(`cred:${cid}`));
    const realNow = Date.now;
    try {
      let t = realNow();
      for (let round = 1; round <= 4; round++) {
        Date.now = () => t;
        account.storage.alarm = null; await account.alarm();
        expect(sent).toHaveLength(round);
        const entry = account.storage.rows.get(`outbox:${cid}`);
        if (round < 4) { expect(entry).toMatchObject({ status_done: true, hook_attempts: round }); t = entry.hook_next; }
        else expect(entry).toBeUndefined();
      }
    } finally { Date.now = realNow; }
    await runAlarms(env);
    expect(sent).toHaveLength(4);
    const shard = await call(env, 'GET', '/api/v1/credentials/' + cid, { auth: 'alice' });
    expect(shard.body.state).toBe('revoked');
  });

  it('writes nothing extra for audiences without a webhook', async () => {
    const device = await newDevice();
    const { cid } = inspectCredential((await enroll(env, 'alice', device)).approve.body.credential).payload;
    await call(env, 'DELETE', `/api/v1/credentials/${cid}`, { auth: 'alice' });
    const account = [...env.ACCOUNTS.objects.values()].find(o => o.storage.rows.has(`cred:${cid}`));
    expect(account.storage.rows.has(`outbox:${cid}`)).toBe(false);
    await runAlarms(env);
    expect(sent).toHaveLength(0);
  });

  it('batches a bulk revocation into one event per audience', async () => {
    await setHook();
    for (let i = 0; i < 3; i++) await enroll(env, 'alice', await newDevice(), { aud: ['hashbin.org', 'cronly.org'], grants: [{ actions: ['hashbin:content:write'] }] });
    const all = await call(env, 'POST', '/api/v1/revoke-all', { auth: 'alice', body: { confirm: 'revoke-all' } });
    expect(all.body.count).toBe(3);
    await runAlarms(env);
    expect(sent).toHaveLength(1);
    expect(decodeJws(sent[0].body).payload.credentials).toHaveLength(3);
  });
});
