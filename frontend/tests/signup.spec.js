// Creating an account with only this browser and a card, then getting back in with a recovery
// code after losing the browser (STATUS B9, done/clerk_free_accounts.md §3.2, §3.5). The local
// server has no Stripe, so the page pays through the local-only development route.
import { test, expect } from '@playwright/test';
import { separateVisitors } from './helpers.js';

separateVisitors();

test('signs up with this browser, makes a recovery sheet, and recovers in another browser', async ({ page, browser }) => {
  await page.goto('/');
  await page.getByRole('link', { name: 'Create an account' }).first().click();
  await expect(page.getByRole('heading', { name: 'Create an account' })).toBeVisible();
  await page.getByLabel('First deposit').selectOption({ label: '$5.00' });
  await expect(page.locator('#signup-quote')).toContainText('of credit plus');
  await page.getByLabel('Name for this browser').fill('My laptop');
  await page.getByRole('button', { name: 'Continue to payment' }).click();
  // Without accepting the terms the browser refuses to submit.
  await expect(page.locator('#signup-form')).toBeVisible();
  await page.getByLabel(/I accept the/).check();
  await page.getByRole('button', { name: 'Continue to payment' }).click();
  await page.getByRole('button', { name: 'Pay (local development: no card)' }).click();
  await expect(page.locator('#signup-account')).toHaveText(/^acct_[0-9A-Z]{26}$/);
  const account = await page.locator('#signup-account').textContent();

  await page.getByRole('button', { name: 'Make recovery codes' }).click();
  const sheet = await page.locator('#recovery-sheet').textContent();
  expect(sheet).toContain(`Account: ${account}`);
  const code = sheet.split('\n').find(line => /^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(line));
  await page.getByRole('link', { name: 'Open the dashboard' }).click();
  await expect(page.locator('#account-strip')).toContainText('Signed in with this device');
  await page.goto('/app.html#account');
  await expect(page.locator('#account-id')).toHaveText(account);
  await expect(page.locator('#recovery-ways')).toContainText('10 recovery codes');

  // The laptop is lost: a new browser recovers with the code.
  const other = await browser.newContext();
  const phone = await other.newPage();
  await phone.goto('/app.html');
  await phone.getByRole('link', { name: 'Recover your account' }).click();
  const byCode = phone.locator('#recover-code');
  await byCode.getByLabel('Account id').fill(account);
  await byCode.getByLabel('Recovery code').fill(code);
  await byCode.getByRole('button', { name: 'Recover' }).click();
  await expect(phone.locator('#recovered-account')).toHaveText(account);
  await phone.getByRole('link', { name: 'Account page' }).click();
  await expect(phone.locator('#account-id')).toHaveText(account);
  await expect(phone.locator('#recovery-ways')).toContainText('9 recovery codes');
  await other.close();
});
