import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv, call, newDevice, runAlarms, worker, ORIGIN } from '../test-utils/env.js';
import { createVerifier, createProof, decodeJws, verifyAddressList, ADDRESS_LIST_TYP } from '../packages/verify/src/index.js';
import { price } from './utils/pricing.js';

// STATUS B10 N3 (todo/network_constraints.md §4): named address lists, their publishing on R2,
// issuance and online decisions that use them, and an offline verifier following a change.

const DAY = 86400000;
let env; const realNow = Date.now; let t;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  env = await testEnv();
  for (const who of ['alice', 'bob', 'operator']) await call(env, 'POST', '/api/v1/dev/deposit', { auth: who, body: { amount_microdollars: 1_000_000 } });
});
afterEach(() => { Date.now = realNow; });

const create = (body, auth = 'alice') => call(env, 'POST', '/api/v1/address-lists', { auth, body });
const published = id => env.STATUS_BUCKET.objects.get(`v1/addresses/${id}`)?.value;
const balance = async who => (await call(env, 'GET', '/api/v1/account', { auth: who })).body.balance_microdollars;
const keys = async () => (await call(env, 'GET', '/.well-known/jwks.json')).body;
const listGrant = list => [{ actions: ['hashbin:content:write'], net: { client: { addresses: { lists: [{ id: list.id, uri: list.uri }] } } } }];
const fetcher = (url, init) => worker.fetch(new Request(url, init), env);

async function issueTo(device, grants, auth = 'alice') {
  return call(env, 'POST', '/api/v1/credentials', { auth, body: { public_jwk: device.publicJwk, aud: ['hashbin.org'], grants } });
}

describe('address lists', () => {
  it('creates, publishes a signed list, reads, replaces and deletes', async () => {
    const before = await balance('alice');
    const made = await create({ name: 'Office', cidrs: ['203.0.113.0/24', '2001:DB8:42::/48', '203.0.113.0/24', '198.51.100.7/32'] });
    expect(made.status).toBe(200);
    expect(made.body).toMatchObject({ name: 'Office', count: 3, ver: 1, uri: `${ORIGIN}/status/v1/addresses/${made.body.id}` });
    expect(made.body.id).toMatch(/^adl_[A-Z0-9]{26}$/);
    // One unit (≤ 1,000 ranges) and 395 days of published life.
    expect(made.body.cost_microdollars).toBe(price('address_list') + 395 * price('address_list_day'));
    expect(before - await balance('alice')).toBe(made.body.cost_microdollars);

    const jwt = published(made.body.id);
    expect(decodeJws(jwt).header.typ).toBe(ADDRESS_LIST_TYP);
    const payload = await verifyAddressList(jwt, { id: made.body.id, uri: made.body.uri, issuer: ORIGIN, keys: await keys(), now: Math.floor(t / 1000) });
    expect(payload).toMatchObject({ ver: 1, cidrs: ['198.51.100.7/32', '2001:db8:42::/48', '203.0.113.0/24'] });
    expect(payload.exp - payload.iat).toBe(86400);
    // Served through the Worker as well (local mode; production verifiers use the CDN).
    const served = await call(env, 'GET', `/status/v1/addresses/${made.body.id}`);
    expect(served.status).toBe(200);
    expect(served.headers.get('Cache-Control')).toBe('public, max-age=60');

    expect((await call(env, 'GET', `/api/v1/address-lists/${made.body.id}`, { auth: 'alice' })).body.cidrs).toEqual(payload.cidrs);
    expect((await call(env, 'GET', '/api/v1/address-lists', { auth: 'alice' })).body.items.map(l => l.id)).toEqual([made.body.id]);
    expect((await call(env, 'GET', `/api/v1/address-lists/${made.body.id}`, { auth: 'bob' })).status).toBe(404);

    // A replace a day later pays one more day of published life; published at once (last publish
    // was long ago).
    t += DAY;
    const replaced = await call(env, 'PUT', `/api/v1/address-lists/${made.body.id}`, { auth: 'alice', body: { cidrs: ['192.0.2.0/24'] } });
    expect(replaced.body).toMatchObject({ ver: 2, count: 1, name: 'Office', cost_microdollars: price('address_list') + price('address_list_day') });
    expect(decodeJws(published(made.body.id)).payload).toMatchObject({ ver: 2, cidrs: ['192.0.2.0/24'] });

    expect((await call(env, 'DELETE', `/api/v1/address-lists/${made.body.id}`, { auth: 'alice' })).body.deleted).toBe(true);
    // Deleted within a minute of the last publish: the tombstone waits for the account's alarm.
    expect(decodeJws(published(made.body.id)).payload.ver).toBe(2);
    t += 61000; await runAlarms(env);
    expect(decodeJws(published(made.body.id)).payload).toMatchObject({ ver: 3, deleted: true, cidrs: [] });
    expect((await call(env, 'GET', '/api/v1/address-lists', { auth: 'alice' })).body.items).toEqual([]);
    // Two days later the tombstone has outlived every copy and is removed.
    t += 3 * DAY; await runAlarms(env);
    expect(published(made.body.id)).toBeUndefined();
    const audit = (await call(env, 'GET', '/api/v1/audit', { auth: 'alice' })).body.items.map(e => e.type);
    expect(audit).toEqual(expect.arrayContaining(['address_list.created', 'address_list.replaced', 'address_list.deleted']));
  });

  it('refuses bad ranges, too many ranges, and an empty balance', async () => {
    expect((await create({ name: 'x', cidrs: ['203.0.113.7/24'] })).body.code).toBe('invalid_address_list');
    expect((await create({ name: 'x', cidrs: ['not an address'] })).body.code).toBe('invalid_address_list');
    expect((await create({ cidrs: [] })).body.code).toBe('invalid_address_list');
    expect((await create({ name: 'x', cidrs: [], extra: 1 })).body.code).toBe('invalid_address_list');
    const many = Array.from({ length: 10_001 }, (_, i) => `10.${i >> 8 & 255}.${i & 255}.0/24`);
    expect((await create({ name: 'x', cidrs: many })).body.code).toBe('invalid_address_list');
    expect((await create({ name: 'broke', cidrs: [] }, 'carol')).status).toBe(402);
  });

  it('charges one unit per started 1,000 ranges and keeps big lists in chunks', async () => {
    const cidrs = Array.from({ length: 2500 }, (_, i) => `10.${i >> 8 & 255}.${i & 255}.0/24`);
    const made = await create({ name: 'Big', cidrs });
    expect(made.body).toMatchObject({ count: 2500, cost_microdollars: 3 * price('address_list') + 395 * price('address_list_day') });
    const read = await call(env, 'GET', `/api/v1/address-lists/${made.body.id}`, { auth: 'alice' });
    expect(read.body.cidrs).toHaveLength(2500);
    // Shrinking drops the chunks no longer needed.
    t += 120000;
    await call(env, 'PUT', `/api/v1/address-lists/${made.body.id}`, { auth: 'alice', body: { cidrs: cidrs.slice(0, 10) } });
    const object = [...env.ACCOUNTS.objects.values()].find(o => o.storage.rows.has(`adl:${made.body.id}`));
    expect([...object.storage.rows.keys()].filter(k => k.startsWith(`adlc:${made.body.id}:`))).toHaveLength(1);
    expect((await call(env, 'GET', `/api/v1/address-lists/${made.body.id}`, { auth: 'alice' })).body.cidrs).toHaveLength(10);
  });

  it('re-signs published lists before their copies expire, while their prepaid life lasts', async () => {
    const made = await create({ name: 'Office', cidrs: ['203.0.113.0/24'] });
    const first = decodeJws(published(made.body.id)).payload.iat;
    t += 21 * 3600000; await runAlarms(env);
    expect(decodeJws(published(made.body.id)).payload.iat).toBeGreaterThan(first);
    expect(decodeJws(published(made.body.id)).payload.ver).toBe(1);
    // After 13 months without a change it is no longer re-signed and expires.
    t += 400 * DAY; await runAlarms(env);
    const last = decodeJws(published(made.body.id)).payload;
    t += 2 * DAY; await runAlarms(env);
    expect(decodeJws(published(made.body.id)).payload.iat).toBe(last.iat);
  });

  it('caps lists per account', async () => {
    for (let i = 0; i < 50; i++) expect((await create({ name: `l${i}`, cidrs: [] })).status).toBe(200);
    expect((await create({ name: 'one more', cidrs: [] })).body.code).toBe('too_many_address_lists');
  });

  it('needs networks scopes for API keys', async () => {
    const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'k', scopes: ['networks:read'] } })).body.secret;
    expect((await call(env, 'GET', '/api/v1/address-lists', { auth: `ApiKey ${key}` })).status).toBe(200);
    expect((await call(env, 'POST', '/api/v1/address-lists', { auth: `ApiKey ${key}`, body: { name: 'x', cidrs: [] } })).status).toBe(403);
  });
});

describe('grants naming address lists', () => {
  it('issues only for the account\'s own live lists at their canonical URI', async () => {
    const device = await newDevice();
    const mine = (await create({ name: 'Office', cidrs: ['203.0.113.0/24'] })).body;
    const bobs = (await create({ name: 'Bob', cidrs: ['198.51.100.0/24'] }, 'bob')).body;
    expect((await issueTo(device, listGrant(mine))).status).toBe(200);
    expect((await issueTo(device, listGrant(bobs))).body.code).toBe('unknown_address_list');
    expect((await issueTo(device, listGrant({ id: mine.id, uri: 'https://evil.example/list' }))).body.code).toBe('invalid_grants');
    await call(env, 'DELETE', `/api/v1/address-lists/${mine.id}`, { auth: 'alice' });
    expect((await issueTo(device, listGrant(mine))).body.code).toBe('unknown_address_list');
  });

  it('online decisions allow only addresses in the list', async () => {
    const device = await newDevice();
    const list = (await create({ name: 'Office', cidrs: ['203.0.113.0/24'] })).body;
    const { credential } = (await issueTo(device, listGrant(list))).body;
    const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'v', scopes: ['authorize'] } })).body.secret;
    const url = 'https://hashbin.org/api/content';
    const ask = async ip => call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key}`, body: { credential, proof: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential }), request: { method: 'POST', url }, audience: 'hashbin.org', action: 'hashbin:content:write', context: { network: { ip } } } });
    expect((await ask('203.0.113.9')).body.allow).toBe(true);
    const denied = (await ask('192.0.2.1')).body;
    expect(denied.allow).toBe(false);
    expect(denied.per_grant_reasons[0]).toContain('address_not_allowed');
  });

  it('an offline verifier follows a change within a minute of its cache', async () => {
    const device = await newDevice();
    const list = (await create({ name: 'Office', cidrs: ['203.0.113.0/24'] })).body;
    const { credential } = (await issueTo(device, listGrant(list))).body;
    let now = Math.floor(t / 1000);
    const verifier = createVerifier({ issuer: ORIGIN, audience: 'hashbin.org', fetch: fetcher, now: () => now });
    const url = 'https://hashbin.org/api/content';
    const attempt = async ip => verifier.verifyRequest(new Request(url, { method: 'POST', headers: { Authorization: `DBA ${credential}`, DPoP: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential }) } }), { action: 'hashbin:content:write', location: { network: { ip } } });
    expect((await attempt('203.0.113.9')).allow).toBe(true);
    expect((await attempt('192.0.2.1')).reasons[0]).toContain('address_not_allowed');

    t += 120000; now = Math.floor(t / 1000);
    await call(env, 'PUT', `/api/v1/address-lists/${list.id}`, { auth: 'alice', body: { cidrs: ['192.0.2.0/24'] } });
    // The verifier's copy was fetched more than 60 s ago, so it fetches the new one.
    expect((await attempt('192.0.2.1')).allow).toBe(true);
    expect((await attempt('203.0.113.9')).allow).toBe(false);

    // Deleted: the tombstone matches nothing.
    t += 120000; now = Math.floor(t / 1000);
    await call(env, 'DELETE', `/api/v1/address-lists/${list.id}`, { auth: 'alice' });
    const after = await attempt('192.0.2.1');
    expect(after.allow).toBe(false);
    expect(after.reasons[0]).toEqual(expect.arrayContaining(['address_not_allowed', `address_list_unavailable:${list.id}`]));
  });
});
