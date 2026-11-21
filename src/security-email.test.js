import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv, call, newDevice, enroll, runAlarms } from '../test-utils/env.js';
import { inspectCredential, signJws } from '../packages/verify/src/index.js';
import { rpc } from './utils/rpc.js';
import { price } from './utils/pricing.js';
import { NOTICE_INTERVAL_MS } from './services/push.js';
import { signAwsV4, cleanEmailAddress, emailLine } from './services/email.js';
import { EMAIL_RETRY_MS } from './durable-objects/account/email.js';

// STATUS S8, D9: takeover-sensitive events are emailed at once, other issuances at most hourly
// in a digest; each email is charged the notice price when queued.

const SES = { EMAIL_PROVIDER: 'ses', SES_REGION: 'us-east-1', SES_ACCESS_KEY_ID: 'AKIDTEST', SES_SECRET_ACCESS_KEY: 'secret', EMAIL_FROM: 'devicebasedauth.org <security@devicebasedauth.org>' };
const session = (sub, fva) => `Bearer ${btoa(JSON.stringify({ sub, sid: 'sess_1', ...(fva ? { fva } : {}) }))}`;

let env; let sent; let answer; const realNow = Date.now; let t;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  sent = []; answer = () => new Response(JSON.stringify({ MessageId: 'm' }), { status: 200 });
  const fetcher = async (url, init) => { sent.push({ url, init, body: JSON.parse(init.body) }); return answer(url, init); };
  env = await testEnv({ ...SES, EMAIL_FETCH: fetcher, CLERK_SECRET_KEY: 'sk_test', CLERK_VERIFY_TOKEN: async token => JSON.parse(atob(token)) });
  await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
  await rpc(env.ACCOUNTS, 'alice', 'init', { account: 'alice', email: 'alice@example.com' });
});
afterEach(() => { Date.now = realNow; });

const balance = async () => (await call(env, 'GET', '/api/v1/account', { auth: 'alice' })).body.balance_microdollars;
async function emails() { await runAlarms(env); return sent.map(s => ({ to: s.body.Destination.ToAddresses[0], subject: s.body.Content.Simple.Subject.Data, text: s.body.Content.Simple.Body.Text.Data })); }
const audit = async () => (await call(env, 'GET', '/api/v1/audit', { auth: 'alice' })).body.items;

describe('AWS Signature Version 4', () => {
  it('matches the AWS test suite', async () => {
    const base = { region: 'us-east-1', service: 'service', accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', now: Date.parse('2015-08-30T12:36:00Z') };
    const sig = async (method, url) => (await signAwsV4({ ...base, method, url })).authorization.split('Signature=')[1];
    expect(await sig('GET', 'https://example.amazonaws.com/')).toBe('5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
    expect(await sig('POST', 'https://example.amazonaws.com/')).toBe('5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b');
    expect(await sig('GET', 'https://example.amazonaws.com/?Param2=value2&Param1=value1')).toBe('b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500');
  });

  it('accepts one plain mailbox and keeps subjects on one line', () => {
    expect(cleanEmailAddress(' a.b+c@example.co.uk ')).toBe('a.b+c@example.co.uk');
    for (const bad of ['a@b', 'a b@example.com', 'a@example.com, b@example.com', 'A <a@example.com>', 'a@example.com\r\nBcc: x@y.z', 42, null]) expect(cleanEmailAddress(bad)).toBeNull();
    expect(emailLine('API key\r\nBcc: x@y.z ‮')).toBe('API key Bcc: x@y.z');
  });
});

describe('security email', () => {
  it('emails a credential with account access at once, signed for SES, and charges the notice price', async () => {
    const before = await balance();
    await enroll(env, 'alice', await newDevice(), { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }], name: 'Laptop' });
    expect(before - await balance()).toBe(price('issue') + price('notice'));
    const [mail] = await emails();
    expect(mail).toMatchObject({ to: 'alice@example.com', subject: 'Credential with account access issued' });
    expect(mail.text).toContain('Laptop for devicebasedauth.org can now act on your devicebasedauth.org account.');
    expect(mail.text).toContain('Review: http://localhost:8787/app.html#credential/');
    expect(sent[0].url).toBe('https://email.us-east-1.amazonaws.com/v2/email/outbound-emails');
    expect(sent[0].body.FromEmailAddress).toBe(SES.EMAIL_FROM);
    expect(sent[0].init.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIDTEST\/\d{8}\/us-east-1\/ses\/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=[0-9a-f]{64}$/);
    const ledger = (await call(env, 'GET', '/api/v1/transactions', { auth: 'alice' })).body.items;
    expect(ledger.find(e => e.kind === 'notice')).toMatchObject({ amount_microdollars: -price('notice'), detail: { email: 'event' } });
    expect((await audit()).find(e => e.type === 'email.sent')).toMatchObject({ subject: 'Credential with account access issued' });
    expect(JSON.stringify(await audit())).not.toContain('alice@example.com');
  });

  it('emails API keys, enrollment tokens, gates, recovery codes and raised limits at once', async () => {
    // A millisecond apart, so the queue (ordered by time) keeps their order.
    await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'CI', scopes: ['credentials:read'] } }); t += 1;
    await call(env, 'POST', '/api/v1/enrollment-tokens', { auth: 'alice', body: { name: 'Fleet', aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], max_uses: 10 } }); t += 1;
    await call(env, 'POST', '/api/v1/settings/recovery-codes', { auth: 'alice' }); t += 1;
    await call(env, 'PATCH', '/api/v1/account/settings', { auth: 'alice', body: { max_issues_per_day: 1000 } }); t += 1;
    await call(env, 'PATCH', '/api/v1/account/settings', { auth: 'alice', body: { max_issues_per_day: 10 } });
    const got = await emails();
    expect(got.map(m => m.subject)).toEqual(['API key created', 'Enrollment token created', 'New recovery codes', 'Budget limit raised']);
    expect(got[3].text).toContain('max issues per day 500 → 1000');
  });

  it('sends other issuances in one digest an hour, read from the audit trail', async () => {
    const before = await balance();
    await enroll(env, 'alice', await newDevice(), { name: 'Build server' });
    let got = await emails();
    expect(got).toHaveLength(1);
    expect(got[0].subject).toBe('1 credential issued or rotated');
    expect(got[0].text).toMatch(/issued {2}Build server for hashbin\.org {2}\(crd_/);
    // Two more within the hour: queued once, paid once, sent when the hour is up.
    t += 1;
    await enroll(env, 'alice', await newDevice(), { name: 'Phone' });
    await enroll(env, 'alice', await newDevice(), { name: 'Tablet' });
    expect(await emails()).toHaveLength(1);
    expect(before - await balance()).toBe(3 * price('issue') + 2 * price('notice'));
    t += NOTICE_INTERVAL_MS;
    got = await emails();
    expect(got).toHaveLength(2);
    expect(got[1].subject).toBe('2 credentials issued or rotated');
    expect(got[1].text).toContain('Phone for hashbin.org');
    expect(got[1].text).toContain('Tablet for hashbin.org');
    expect(got[1].text).not.toContain('Build server');
  });

  it('puts an ordinary rotation in the digest', async () => {
    const device = await newDevice(); const next = await newDevice();
    const credential = (await enroll(env, 'alice', device, { name: 'Agent' })).approve.body.credential;
    await emails();
    const { cid } = inspectCredential(credential).payload;
    t += NOTICE_INTERVAL_MS;
    const path = `/api/v1/credentials/${cid}/renew`;
    const keyProof = await signJws({ typ: 'dba-rotate+jwt', jwk: next.publicJwk }, { cid, iat: Math.floor(t / 1000) }, next.privateKey);
    expect((await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: { new_key_proof: keyProof } })).body.rotated).toBe(true);
    expect((await emails()).at(-1).text).toMatch(/rotated {2}Agent for hashbin\.org/);
  });

  it('sends nothing, and charges nothing, without an address, a provider, the setting or the money', async () => {
    const quiet = async () => { const before = await balance(); await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'k', scopes: ['credentials:read'] } }); expect(await balance()).toBe(before); expect(await emails()).toEqual([]); };
    await rpc(env.ACCOUNTS, 'alice', 'init', { account: 'alice', email: null });
    await quiet();
    await rpc(env.ACCOUNTS, 'alice', 'init', { account: 'alice', email: 'alice@example.com' });
    await call(env, 'PATCH', '/api/v1/account/settings', { auth: 'alice', body: { security_email: 'off' } });
    expect((await emails()).map(m => m.subject)).toEqual(['Security emails turned off']);
    sent.length = 0;
    await quiet();
    await call(env, 'PATCH', '/api/v1/account/settings', { auth: 'alice', body: { security_email: 'sensitive' } });
    // "sensitive" skips the digest but still emails keys.
    await enroll(env, 'alice', await newDevice());
    expect(await emails()).toEqual([]);
    await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'k2', scopes: ['credentials:read'] } });
    expect((await emails()).map(m => m.subject)).toEqual(['API key created']);
    // Not configured on this server: the same request costs nothing.
    sent.length = 0; delete env.SES_SECRET_ACCESS_KEY;
    await quiet();
    expect((await call(env, 'GET', '/api/public/config')).body.security_email).toBe(false);
    // Too little left for an email: the event still happens, without one.
    env.SES_SECRET_ACCESS_KEY = 'secret';
    const poor = await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'bob', body: { amount_microdollars: price('issue') } });
    expect(poor.status).toBe(200);
    await rpc(env.ACCOUNTS, 'bob', 'init', { account: 'bob', email: 'bob@example.com' });
    expect((await enroll(env, 'bob', await newDevice())).approve.status).toBe(200);
    expect(await emails()).toEqual([]);
  });

  it('needs a recent sign-in to turn emails down, and sends a last one when it does', async () => {
    const stale = session('alice', [45, -1]); const fresh = session('alice', [2, -1]);
    expect((await call(env, 'PATCH', '/api/v1/account/settings', { auth: stale, body: { security_email: 'off' } })).body.code).toBe('reverification_required');
    expect((await call(env, 'PATCH', '/api/v1/account/settings', { auth: stale, body: { security_email: 'bogus' } })).body.code).toBe('invalid_setting');
    const off = await call(env, 'PATCH', '/api/v1/account/settings', { auth: fresh, body: { security_email: 'off' } });
    expect(off.body.security_email).toBe('off');
    expect((await emails()).map(m => m.subject)).toEqual(['Security emails turned off']);
    // Turning them back up needs nothing special.
    expect((await call(env, 'PATCH', '/api/v1/account/settings', { auth: stale, body: { security_email: 'all' } })).body.security_email).toBe('all');
  });

  it('retries when SES did not take the message, at most three times, and not after a network error', async () => {
    let calls = 0; answer = () => { calls++; return new Response('throttled', { status: 429 }); };
    await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'k', scopes: ['credentials:read'] } });
    await runAlarms(env);
    expect(calls).toBe(1);
    t += EMAIL_RETRY_MS[0]; await runAlarms(env);
    t += EMAIL_RETRY_MS[1]; await runAlarms(env);
    expect(calls).toBe(3);
    t += 86400000; await runAlarms(env);
    expect(calls).toBe(3);
    expect((await audit()).find(e => e.type === 'email.failed')).toMatchObject({ subject: 'API key created', status: 429 });
    calls = 0; answer = () => { calls++; throw new Error('connection reset'); };
    await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'k2', scopes: ['credentials:read'] } });
    await runAlarms(env); t += 86400000; await runAlarms(env);
    expect(calls).toBe(1);
  });

  it('takes the address from the account profile and shows it to the owner', async () => {
    expect((await call(env, 'GET', '/api/v1/account', { auth: 'alice' })).body.security_email_address).toBe('alice@example.com');
    expect((await call(env, 'GET', '/api/public/config')).body.security_email).toBe(true);
    t += 1;
    await rpc(env.ACCOUNTS, 'alice', 'init', { account: 'alice', email: 'not an address' });
    expect((await call(env, 'GET', '/api/v1/account', { auth: 'alice' })).body.security_email_address).toBeNull();
    expect((await audit()).filter(e => e.type === 'account.email_changed').map(e => e.has_address)).toEqual([false, true]);
  });
});
