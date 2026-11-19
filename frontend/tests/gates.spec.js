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
  // Two authenticator app gates, set up through the API (the dashboard flow is tested above).
  const totpGate = async label => {
    const made = await (await request.post('/api/v1/gates', { headers: asLocal(owner), data: { kind: 'totp', label } })).json();
    const key = unbase32(made.setup.secret);
    expect((await request.post(`/api/v1/gates/${made.id}/activate`, { headers: asLocal(owner), data: { code: await code(key) } })).ok()).toBeTruthy();
    return { id: made.id, secret: key };
  };
  const phone = await totpGate('Phone app');
  const tablet = await totpGate('Tablet app');
  const setGates = async entries => {
    const response = await request.put('/api/v1/settings/sign-in-gates', { headers: asLocal(owner), data: { audiences: { 'cronly.org': entries } } });
    expect(response.status()).toBe(200); // never a 202: each change here tightens the last one
  };

  await page.route('https://cronly.org/**', route => route.fulfill({ status: 200, contentType: 'text/plain', body: 'back at cronly' }));
  const query = new URLSearchParams({ client_id: 'cronly.org', redirect_uri: 'https://cronly.org/auth/dba/callback', response_type: 'code', scope: 'openid', state: 'st', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256', acr_values: 'urn:devicebasedauth.org:acr:gated' });
  await signIn(page, owner);

  // Allow on timeout: never answered inline, only through the link, by someone who types the number.
  await setGates([{ any: [tablet.id, phone.id], timeout_s: 120, on_timeout: 'allow' }]);
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
  await approver.getByLabel('Code from Tablet app').fill(await code(tablet.secret, 1));
  await approver.locator('form.gate-totp', { has: approver.getByLabel('Code from Tablet app') }).getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(approver.locator('#gate-root')).toContainText('Approved. Thank you.');
  await page.waitForURL(url => url.hostname === 'cronly.org');
  expect(new URL(page.url()).searchParams.get('code')).toMatch(/^dbac_/);

  // Deny on timeout, only the phone (a tightening, so saved at once): answerable right on the consent page.
  await setGates([{ any: [phone.id], timeout_s: 120 }]);
  await page.goto(`/authorize.html?${query}`);
  await page.getByRole('button', { name: 'Sign in to cronly.org' }).click();
  await expect(page.locator('#sign-in-gate')).toContainText('Waiting for approval');
  await expect(page.locator('#gate-number')).toHaveText(/^\d\d$/);
  await page.getByLabel('Code from Phone app').fill(await code(phone.secret, 1));
  await page.getByRole('button', { name: 'Approve with code' }).click();
  await page.waitForURL(url => url.hostname === 'cronly.org');
  expect(new URL(page.url()).searchParams.get('code')).toMatch(/^dbac_/);
});

test('the dashboard waits for its sign-in gate, and a recovery code opens it once', async ({ page, browser, request }) => {
  const owner = uniqueName('dashgate');
  const admin = { Authorization: `LocalDev ${owner} admin` };
  await fund(request, owner);
  const created = await (await request.post('/api/v1/gates', { headers: admin, data: { kind: 'totp', label: 'Phone app' } })).json();
  const secret = unbase32(created.setup.secret);
  expect((await request.post(`/api/v1/gates/${created.id}/activate`, { headers: admin, data: { code: await code(secret) } })).ok()).toBeTruthy();
  const codes = (await (await request.post('/api/v1/settings/recovery-codes', { headers: admin, data: {} })).json()).codes;
  expect((await request.put('/api/v1/settings/sign-in-gates', { headers: admin, data: { dashboard: [{ any: [created.id], timeout_s: 300 }] } })).ok()).toBeTruthy();

  // A new browser session is held until the gate confirms it.
  await page.goto('/app.html');
  await page.getByLabel('Local account name').fill(owner);
  await page.getByRole('button', { name: 'Use local account' }).click();
  await expect(page.getByRole('heading', { name: 'Confirm this sign-in' })).toBeVisible();
  await expect(page.locator('#lock-number')).toHaveText(/^\d\d$/);
  await page.getByLabel('Code from Phone app').fill(await code(secret, 1));
  await page.getByRole('button', { name: 'Confirm with code' }).click();
  await expect(page.getByRole('heading', { name: 'Credentials', exact: true })).toBeVisible();

  // Another browser: a recovery code opens it, once.
  const other = await browser.newPage();
  await other.goto('/app.html');
  await other.getByLabel('Local account name').fill(owner);
  await other.getByRole('button', { name: 'Use local account' }).click();
  await expect(other.getByRole('heading', { name: 'Confirm this sign-in' })).toBeVisible();
  await other.getByLabel('Recovery code').fill(codes[0]);
  await other.getByRole('button', { name: 'Use recovery code' }).click();
  await expect(other.getByRole('heading', { name: 'Credentials', exact: true })).toBeVisible();
  await expect(other.locator('#flash')).toContainText('9 left');
  const third = await browser.newPage();
  await third.goto('/app.html');
  await third.getByLabel('Local account name').fill(owner);
  await third.getByRole('button', { name: 'Use local account' }).click();
  await third.getByLabel('Recovery code').fill(codes[0]);
  await third.getByRole('button', { name: 'Use recovery code' }).click();
  await expect(third.locator('#flash')).toContainText('not valid');
});

test('Duo Push and Okta Verify gates are added from the Gates page, their secrets never shown again (STATUS B7 G9)', async ({ page, request }) => {
  const owner = uniqueName('vendor');
  await fund(request, owner);
  await signIn(page, owner);
  await page.getByRole('link', { name: 'Gates', exact: true }).click();
  const duo = page.locator('#gate-duo-form');
  await duo.getByLabel('Label').fill('Duo for Sam');
  await duo.getByLabel('API hostname').fill('api-1234abcd.duosecurity.com');
  await duo.getByLabel('Integration key').fill('DIWJ8X6AEYOR5OMC6TQ1');
  await duo.getByLabel('Secret key').fill('Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep');
  await duo.getByLabel('Duo username').fill('sam');
  await page.getByRole('button', { name: 'Add Duo Push' }).click();
  await expect(page.locator('#flash')).toContainText('Added gate gate_');
  await expect(page.locator('#gate-list')).toContainText('Duo for Sam');
  await expect(page.locator('#gate-list')).toContainText('Duo Push');
  const okta = page.locator('#gate-okta-form');
  await okta.getByLabel('Label').fill('Okta for Sam');
  await okta.getByLabel('Org URL').fill('https://example.okta.com');
  await okta.getByLabel('API token').fill('00abcdefghijklmnopqrstuvwxyz0123456789ABCD');
  await okta.getByLabel('User id').fill('00u1abcdefGHIJKLM357');
  await okta.getByLabel('Okta Verify push factor id').fill('opf1abcdefGHIJKLM357');
  await page.getByRole('button', { name: 'Add Okta Verify' }).click();
  await expect(page.locator('#gate-list')).toContainText('Okta Verify push');
  const items = (await (await request.get('/api/v1/gates', { headers: asLocal(owner) })).json()).items;
  expect(items.find(g => g.kind === 'duo')).toMatchObject({ api_host: 'api-1234abcd.duosecurity.com', username: 'sam', state: 'active' });
  expect(JSON.stringify(items)).not.toContain('Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep');
  expect(JSON.stringify(items)).not.toContain('00abcdefghijklmnopqrstuvwxyz0123456789ABCD');
  // A bad value is explained, not saved.
  await duo.getByLabel('Label').fill('Broken');
  await duo.getByLabel('API hostname').fill('evil.example.com');
  await duo.getByLabel('Integration key').fill('DIWJ8X6AEYOR5OMC6TQ1');
  await duo.getByLabel('Secret key').fill('Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep');
  await duo.getByLabel('Duo username').fill('sam');
  await page.getByRole('button', { name: 'Add Duo Push' }).click();
  await expect(page.locator('#flash')).toContainText('api_host must be your Duo API hostname');
});

test('a webhook gate can be tested from the Gates page (STATUS B7 G9)', async ({ page, request }) => {
  const owner = uniqueName('hooktest');
  await fund(request, owner);
  const { generateKeyPair, exportPublicJwk } = await import('../../packages/verify/src/index.js');
  const jwk = await exportPublicJwk((await generateKeyPair(true)).publicKey);
  // Nothing listens on port 9, so the test reports that the service did not answer.
  const gate = await (await request.post('/api/v1/gates', { headers: asLocal(owner), data: { kind: 'webhook', label: 'Ops approvals', url: 'http://localhost:9/dba-gate', public_jwk: jwk } })).json();
  await signIn(page, owner);
  await page.getByRole('link', { name: 'Gates', exact: true }).click();
  await page.locator(`[data-test="${gate.id}"]`).click();
  await expect(page.locator('#flash')).toContainText('“Ops approvals” did not answer');
});
