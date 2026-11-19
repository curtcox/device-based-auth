import { test, expect } from '@playwright/test';
import { separateVisitors, signIn, fund, uniqueName, enrollViaApi, asLocal } from './helpers.js';
import { createProof } from '../../packages/verify/src/index.js';
import { hotp } from '../../src/services/totp.js';

// STATUS B7, phase G4: TOTP and security-key gates, set up in the dashboard and answered on the
// approval page (/gate.html) with a TOTP code and a virtual authenticator.

separateVisitors();

const unbase32 = text => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0; let value = 0; const out = []; for (const c of text) { value = (value << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } } return new Uint8Array(out); };
const code = (secret, offset = 0) => hotp(secret, Math.floor(Date.now() / 30000) + offset);

/** A device of `owner` whose grant needs `gate`, and a way to ask hashbin.org's online check. */
async function gated(request, owner, gate, action = 'hashbin:content:delete') {
  await fund(request, 'operator');
  const key = await (await request.post('/api/v1/keys', { headers: asLocal('operator'), data: { name: 'hashbin verifier', scopes: ['authorize'] } })).json();
  const issued = await enrollViaApi(request, owner, { name: 'Release bot', grants: [{ actions: ['hashbin:content:delete', 'hashbin:content:write'], require: { gates: [{ any: [gate], timeout_s: 300 }] } }] });
  return async (asked = action) => {
    const url = 'https://hashbin.org/api/content/abc';
    const proof = await createProof({ ...issued.device, method: 'DELETE', url, credential: issued.credential });
    return (await request.post('/api/v1/authorize', { headers: { Authorization: `ApiKey ${key.secret}` }, data: { credential: issued.credential, proof, request: { method: 'DELETE', url }, audience: 'hashbin.org', action: asked, resource: 'abc' } })).json();
  };
}

test('an authenticator app gate: set up in the dashboard, approved with a code, and each code works once', async ({ page, request }) => {
  const owner = uniqueName('totp');
  await fund(request, owner);
  await signIn(page, owner);
  await page.getByRole('link', { name: 'Gates', exact: true }).click();
  await page.locator('#gate-totp-form').getByLabel('Label').fill('Pixel authenticator');
  await page.getByRole('button', { name: 'Add authenticator app' }).click();
  const secret = unbase32(await page.locator('#totp-secret').textContent());
  await page.locator('#gate-totp-confirm').getByLabel('Code from the app').fill(await code(secret));
  await page.getByRole('button', { name: 'Finish' }).click();
  await expect(page.locator('#flash')).toContainText('is set up');
  await expect(page.locator('#gate-list')).toContainText('Pixel authenticator');
  const gate = (await (await request.get('/api/v1/gates', { headers: asLocal(owner) })).json()).items.find(g => g.kind === 'totp').id;

  const ask = await gated(request, owner, gate);
  const pending = await ask();
  expect(pending.code).toBe('gate_pending');
  await page.goto(pending.gate_request.approve_url.replace('http://localhost:8787', ''));
  await expect(page.locator('#gate-summary')).toContainText('Release bot');
  await expect(page.locator('#gate-summary')).toContainText('hashbin:content:delete');
  // The activation spent this step's code; the next step's is accepted (one step of clock drift).
  const fresh = await code(secret, 1);
  await page.getByLabel('Code from Pixel authenticator').fill(fresh);
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.locator('#gate-root')).toContainText('Approved. Thank you.');
  expect((await ask()).allow).toBe(true);

  // The same code on another request is refused.
  const other = await ask('hashbin:content:write');
  await page.goto(other.gate_request.approve_url.replace('http://localhost:8787', ''));
  await page.getByLabel('Code from Pixel authenticator').fill(fresh);
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.locator('#gate-root')).toContainText('not right, or was already used');
});

test('a security key gate: registered and approved with a virtual authenticator', async ({ page, request }) => {
  const owner = uniqueName('webauthn');
  await fund(request, owner);
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true } });
  await signIn(page, owner);
  await page.getByRole('link', { name: 'Gates', exact: true }).click();
  await page.locator('#gate-key-form').getByLabel('Label').fill('YubiKey 5');
  await page.getByRole('button', { name: 'Register security key' }).click();
  await expect(page.locator('#flash')).toContainText('is registered');
  const gate = (await (await request.get('/api/v1/gates', { headers: asLocal(owner) })).json()).items.find(g => g.kind === 'webauthn').id;

  const ask = await gated(request, owner, gate);
  const pending = await ask();
  await page.goto(pending.gate_request.approve_url.replace('http://localhost:8787', ''));
  await expect(page.locator('#gate-summary')).toContainText('Release bot');
  await page.getByRole('button', { name: 'Approve with security key' }).click();
  await expect(page.locator('#gate-root')).toContainText('Approved. Thank you.');
  expect((await ask()).allow).toBe(true);
});

test('a sign-in waits for its gate: inline with an authenticator code, and through the approval link with number matching', async ({ page, browser, request }) => {
  const owner = uniqueName('signin');
  await fund(request, owner);
  // An authenticator app gate, set up through the API (the dashboard flow is tested above).
  const created = await (await request.post('/api/v1/gates', { headers: asLocal(owner), data: { kind: 'totp', label: 'Phone app' } })).json();
  const secret = unbase32(created.setup.secret);
  expect((await request.post(`/api/v1/gates/${created.id}/activate`, { headers: asLocal(owner), data: { code: await code(secret) } })).ok()).toBeTruthy();
  // Deny on timeout: answerable right on the consent page.
  expect((await request.put('/api/v1/settings/sign-in-gates', { headers: asLocal(owner), data: { audiences: { 'cronly.org': [{ any: [created.id], timeout_s: 120 }] } } })).ok()).toBeTruthy();

  await page.route('https://cronly.org/**', route => route.fulfill({ status: 200, contentType: 'text/plain', body: 'back at cronly' }));
  const query = new URLSearchParams({ client_id: 'cronly.org', redirect_uri: 'https://cronly.org/auth/dba/callback', response_type: 'code', scope: 'openid', state: 'st', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256', acr_values: 'urn:devicebasedauth.org:acr:gated' });
  await signIn(page, owner);
  await page.goto(`/authorize.html?${query}`);
  await page.getByRole('button', { name: 'Sign in to cronly.org' }).click();
  await expect(page.locator('#sign-in-gate')).toContainText('Waiting for approval');
  await expect(page.locator('#gate-number')).toHaveText(/^\d\d$/);
  await page.getByLabel('Code from Phone app').fill(await code(secret, 1));
  await page.getByRole('button', { name: 'Approve with code' }).click();
  await page.waitForURL(url => url.hostname === 'cronly.org');
  expect(new URL(page.url()).searchParams.get('code')).toMatch(/^dbac_/);

  // Allow on timeout: never answered inline, only through the link, by someone who types the number.
  // (A second authenticator: the first one's codes up to the next step are spent.)
  const tablet = await (await request.post('/api/v1/gates', { headers: asLocal(owner), data: { kind: 'totp', label: 'Tablet app' } })).json();
  const tabletSecret = unbase32(tablet.setup.secret);
  expect((await request.post(`/api/v1/gates/${tablet.id}/activate`, { headers: asLocal(owner), data: { code: await code(tabletSecret) } })).ok()).toBeTruthy();
  expect((await request.put('/api/v1/settings/sign-in-gates', { headers: asLocal(owner), data: { audiences: { 'cronly.org': [{ any: [tablet.id], timeout_s: 120, on_timeout: 'allow' }] } } })).ok()).toBeTruthy();
  await page.goto(`/authorize.html?${query}`);
  await page.getByRole('button', { name: 'Sign in to cronly.org' }).click();
  await expect(page.locator('#sign-in-gate')).toContainText('allowed if nobody answers within 2 minutes');
  await expect(page.getByRole('button', { name: 'Approve with code' })).toHaveCount(0);
  const number = await page.locator('#gate-number').textContent();
  const link = (await (await request.post('/oauth/authorize', { headers: asLocal(owner), data: { ...Object.fromEntries(query), approve: true } })).json()).gate_request.approve_url;
  const approver = await browser.newPage();
  await approver.goto(link);
  await expect(approver.locator('#gate-summary')).toContainText('sign in to cronly.org');
  await expect(approver.locator('#gate-summary')).not.toContainText(number);
  await approver.getByLabel('Number shown on the sign-in page').fill(number);
  await approver.getByLabel('Code from Tablet app').fill(await code(tabletSecret, 1));
  await approver.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(approver.locator('#gate-root')).toContainText('Approved. Thank you.');
  await page.waitForURL(url => url.hostname === 'cronly.org');
  expect(new URL(page.url()).searchParams.get('code')).toMatch(/^dbac_/);
});
