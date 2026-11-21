// A dashboard signed in with this browser's own device confirms it is the owner through a gate
// before an operation that needs a recent sign-in (STATUS B9, todo/clerk_free_accounts.md §3.4).
import { test, expect } from '@playwright/test';
import { uniqueName, fund, signIn, asLocal, separateVisitors } from './helpers.js';
import { hotp } from '../../src/services/totp.js';

separateVisitors();

const unbase32 = text => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0; let value = 0; const out = []; for (const c of text) { value = (value << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } } return new Uint8Array(out); };
const code = (secret, offset = 0) => hotp(secret, Math.floor(Date.now() / 30000) + offset);

test('a dashboard device confirms it is you with an authenticator code, then creates an API key', async ({ page, request }) => {
  const owner = uniqueName('reverify');
  await fund(request, owner);
  // An authenticator app gate, set up through the API as the owner.
  const created = await (await request.post('/api/v1/gates', { headers: asLocal(owner), data: { kind: 'totp', label: 'Phone app' } })).json();
  const secret = unbase32(created.setup.secret);
  expect((await request.post(`/api/v1/gates/${created.id}/activate`, { headers: asLocal(owner), data: { code: await code(secret) } })).ok()).toBeTruthy();

  // This browser becomes the dashboard's device, and the local sign-in is forgotten.
  await signIn(page, owner);
  const popupEvent = page.waitForEvent('popup');
  await page.getByRole('button', { name: 'Use this browser as a device for the dashboard' }).click();
  const popup = await popupEvent;
  await popup.getByRole('button', { name: /^Approve for/ }).click();
  await expect(popup.getByText('You can close this window')).toBeVisible();
  await page.evaluate(() => localStorage.removeItem('dba-local-user'));
  await page.goto('/app.html#keys');
  await expect(page.locator('#account-strip')).toContainText('Signed in with this device');

  // Creating a key needs a recent sign-in; the device asks the gate instead.
  await page.getByRole('button', { name: 'Create key' }).click();
  await expect(page.locator('#new-key')).toContainText('Please confirm it is you');
  await page.getByRole('button', { name: 'Confirm it is you' }).click();
  await expect(page.locator('#reverify-number')).toHaveText(/^\d\d$/);
  // The activation spent this step's code; the next step's is accepted (one step of clock drift).
  await page.getByLabel('Code from Phone app').fill(await code(secret, 1));
  await page.getByRole('button', { name: 'Confirm with code' }).click();
  await expect(page.locator('#reverify-panel')).toContainText('Confirmed.');

  await page.getByRole('button', { name: 'Create key' }).click();
  await expect(page.locator('#key-secret')).toHaveText(/^dbak_/);
});
