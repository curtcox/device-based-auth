import { test, expect } from '@playwright/test';
import { separateVisitors, signIn, fund, uniqueName } from './helpers.js';

separateVisitors();

test('a browser enrolls with the SDK, calls the API, and its owner revokes it from the dashboard', async ({ page, request }) => {
  const owner = uniqueName('owner');
  await fund(request, owner);
  await signIn(page, owner);

  // A same-origin page using the SDK exactly as a site would: enroll from a click (popup).
  await page.goto('/tools/');
  await page.evaluate(() => {
    const button = document.createElement('button');
    button.id = 'enroll-test'; button.textContent = 'Enroll this browser';
    button.addEventListener('click', async () => {
      const { DBA } = await import('/sdk/dba.js');
      const dba = new DBA({ origin: location.origin });
      window.enrolled = dba.enroll({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'], limits: { spend_usd_per_month: 5 } }], device: { name: 'Playwright browser' } })
        .then(async () => { const response = await dba.fetch('/api/v1/whoami'); return { status: response.status, body: await response.json(), allows: dba.allows('hashbin:content:write') }; });
    });
    document.body.append(button);
  });
  const popupEvent = page.waitForEvent('popup');
  await page.click('#enroll-test');
  const popup = await popupEvent;

  // The approval page shows what is asked, in plain English, and the price.
  await expect(popup.getByRole('heading', { name: /Playwright browser/ })).toBeVisible();
  await expect(popup.locator('#grant-descriptions')).toContainText('spending at most $5.00 per month');
  await expect(popup.locator('#request-summary')).toContainText('hashbin.org');
  await expect(popup.locator('#price')).toContainText('µ$');
  await popup.getByRole('button', { name: /^Approve for/ }).click();
  await expect(popup.getByText('You can close this window')).toBeVisible();

  const result = await page.evaluate(() => window.enrolled);
  expect(result.status).toBe(200);
  expect(result.body).toMatchObject({ account: owner, kind: 'device', aud: ['hashbin.org'] });
  expect(result.allows).toBe(true);

  // The owner sees it in the dashboard with its grant in plain English, and revokes it.
  await page.goto('/app.html#credentials');
  await page.getByRole('link', { name: 'Playwright browser' }).click();
  await expect(page.locator('#grant-descriptions')).toContainText('May "hashbin:content:write", on any resource, spending at most $5.00 per month.');
  await expect(page.locator('#raw-jws')).toContainText(result.body.cid ? '.' : '');
  await expect(page.locator('#decoded-payload')).toContainText(result.body.cid);
  await page.getByRole('button', { name: 'Revoke', exact: true }).click();
  await page.getByRole('button', { name: 'Yes, revoke it' }).click();
  await expect(page.locator('#flash')).toContainText(`Revoked 1 credential: ${result.body.cid}`);
  await expect(page.getByRole('heading', { level: 1 })).toContainText('revoked');

  // The device is refused at once (this API checks revocation online).
  const after = await page.evaluate(async () => {
    const { DBA } = await import('/sdk/dba.js');
    const dba = new DBA({ origin: location.origin });
    await dba.ready();
    const response = await dba.fetch('/api/v1/whoami');
    return { status: response.status, body: await response.json() };
  });
  expect(after.status).toBe(401);
  expect(after.body.code).toBe('revoked');
});

test('the dashboard can sign in with this browser as its own device (dba:session)', async ({ page, request }) => {
  const owner = uniqueName('stageb');
  await fund(request, owner);
  await signIn(page, owner);
  const popupEvent = page.waitForEvent('popup');
  await page.getByRole('button', { name: 'Use this browser as a device for the dashboard' }).click();
  const popup = await popupEvent;
  await expect(popup.locator('#grant-descriptions')).toContainText('dba:session');
  await expect(popup.locator('#request-summary')).toContainText('first party');
  await popup.getByLabel('Device name').fill('My dashboard browser');
  await popup.getByRole('button', { name: /^Approve for/ }).click();
  await expect(popup.getByText('You can close this window')).toBeVisible();
  await expect(page.locator('#account-strip')).toContainText('Signed in with this device');
  await expect(page.locator('#signed-in-as')).toContainText('My dashboard browser');

  // Forget the local sign-in: the device credential alone keeps the dashboard working.
  await page.evaluate(() => localStorage.removeItem('dba-local-user'));
  await page.goto('/app.html#credentials');
  await expect(page.getByRole('link', { name: 'My dashboard browser' })).toBeVisible();
  await expect(page.locator('#account-strip')).toContainText('Signed in with this device');

  // Signing out revokes the dashboard credential, so the next visit asks for a sign-in.
  await page.getByRole('button', { name: /Sign out/ }).click();
  await expect(page.getByLabel('Local account name')).toBeVisible();
  const list = await (await request.get('/api/v1/credentials', { headers: { Authorization: `LocalDev ${owner}` } })).json();
  expect(list.items.map(c => c.state)).toEqual(['revoked']);
});
