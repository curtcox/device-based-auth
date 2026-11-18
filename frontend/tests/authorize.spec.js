import { test, expect } from '@playwright/test';
import { separateVisitors, signIn, uniqueName } from './helpers.js';

separateVisitors();

const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const query = new URLSearchParams({ client_id: 'cronly.org', redirect_uri: 'https://cronly.org/auth/dba/callback', response_type: 'code', scope: 'openid profile', state: 'st-123', nonce: 'n-1', code_challenge: challenge, code_challenge_method: 'S256' });

test('the consent page names the site and returns a code or an error', async ({ page }) => {
  const owner = uniqueName('oidc');
  await page.route('https://cronly.org/**', route => route.fulfill({ status: 200, contentType: 'text/plain', body: 'back at cronly' }));
  await page.goto(`/oauth/authorize?${query}`);
  await expect(page).toHaveURL(/\/authorize(\.html)?\?client_id=cronly\.org/);
  await page.getByLabel('Local account name').fill(owner);
  await page.getByRole('button', { name: 'Use local account' }).click();
  await expect(page.locator('#client-name')).toContainText('cronly.org');
  await expect(page.locator('#client-description')).toContainText('cronly');
  await expect(page.locator('#shared-account')).toHaveText(owner);
  await page.getByRole('button', { name: 'Cancel' }).click();
  await page.waitForURL(url => url.hostname === 'cronly.org');
  expect(new URL(page.url()).searchParams.get('error')).toBe('access_denied');
  expect(new URL(page.url()).searchParams.get('state')).toBe('st-123');

  await page.goto(`/authorize.html?${query}`);
  await page.getByRole('button', { name: 'Sign in to cronly.org' }).click();
  await page.waitForURL(url => url.hostname === 'cronly.org');
  const back = new URL(page.url());
  expect(back.searchParams.get('code')).toMatch(/^dbac_/);
  expect(back.searchParams.get('state')).toBe('st-123');
});

test('the consent page refuses an unregistered redirect', async ({ page }) => {
  await signIn(page, uniqueName('oidc-bad'));
  const bad = new URLSearchParams(query); bad.set('redirect_uri', 'https://evil.example/cb');
  await page.goto(`/authorize.html?${bad}`);
  await expect(page.locator('#authorize-root')).toContainText('is not registered for cronly.org');
  await expect(page.getByRole('button', { name: /Sign in to/ })).toHaveCount(0);
});
