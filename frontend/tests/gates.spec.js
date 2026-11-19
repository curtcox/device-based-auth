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
