import { it, expect, beforeEach } from 'vitest';
import { testEnv, call, newDevice, enroll, worker, ORIGIN } from '../test-utils/env.js';
import { createSiteAuth, createOidcClient, createProof } from '../packages/verify/src/index.js';

let env;
const fetcher = () => (url, init) => worker.fetch(new Request(url, init), env);
beforeEach(async () => { env = await testEnv(); await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } }); await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'operator', body: { amount_microdollars: 1_000_000 } }); });

it('turns a DBA device credential into a site user with that site\'s scopes', async () => {
  const device = await newDevice();
  const credential = (await enroll(env, 'alice', device, { grants: [{ actions: ['hashbin:content:write', 'hashbin:uploads:read'], limits: { spend_usd_per_month: 2 } }, { actions: ['hashbin:session'] }] })).approve.body.credential;
  const links = new Map([['alice', 'hashbin-user-7']]);
  const site = createSiteAuth({ issuer: ORIGIN, audience: 'hashbin.org', namespace: 'hashbin', scopes: ['content:write', 'content:delete', 'uploads:read'], linkedUser: async acct => links.get(acct) || null, fetch: fetcher() });
  const url = 'https://hashbin.org/api/upload';
  const request = async () => new Request(url, { method: 'POST', headers: { Authorization: `DBA ${credential}`, DPoP: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential }) } });
  const result = await site.authenticate(await request());
  expect(result).toMatchObject({ ok: true, userId: 'hashbin-user-7', dbaAccount: 'alice', session: true, scopes: ['content:write', 'uploads:read'], caveats: { spend_usd_per_month: 2 } });
  expect(site.allows(result, 'content:write')).toBe(true);
  expect(site.allows(result, 'content:delete')).toBe(false);
  links.clear();
  expect(await site.authenticate(await request())).toMatchObject({ ok: false, status: 403, code: 'account_not_linked' });
  expect(await site.authenticate(new Request(url))).toBe(null);
});

it('links an account with the OIDC client', async () => {
  const oidc = createOidcClient({ issuer: ORIGIN, clientId: 'hashbin.org', redirectUri: 'https://hashbin.org/auth/dba/callback', fetch: fetcher() });
  const { url, state } = await oidc.begin();
  const query = Object.fromEntries(new URL(url).searchParams);
  expect(query).toMatchObject({ client_id: 'hashbin.org', code_challenge_method: 'S256' });
  const consent = await call(env, 'POST', '/oauth/authorize', { auth: 'alice', body: { ...query, approve: true } });
  const claims = await oidc.finish(new URL(consent.body.redirect).searchParams, state);
  expect(claims).toMatchObject({ sub: 'alice', acct: 'alice', aud: 'hashbin.org' });
  await expect(oidc.finish(new URL(consent.body.redirect).searchParams, { ...state, state: 'other' })).rejects.toMatchObject({ code: 'invalid_state' });
});
