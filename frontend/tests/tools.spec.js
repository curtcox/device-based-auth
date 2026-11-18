import { test, expect } from '@playwright/test';
import { separateVisitors, fund, uniqueName, enrollViaApi } from './helpers.js';

separateVisitors();

test('the inspector decodes a credential locally and checks it with the server', async ({ page, request }) => {
  const owner = uniqueName('inspect');
  await fund(request, owner);
  const issued = await enrollViaApi(request, owner, { name: 'Office printer', grants: [{ actions: ['hashbin:uploads:read'], when: { tz: 'America/Chicago', windows: [{ days: ['mon', 'tue', 'wed', 'thu', 'fri'], from: '08:00', to: '18:00' }] } }] });
  await page.goto('/tools/inspector.html');
  await page.getByLabel('Credential or access token').fill(issued.credential);
  await expect(page.locator('#decoded-payload')).toContainText(issued.cid);
  await expect(page.locator('#decoded-header')).toContainText('dba-device+jwt');
  await expect(page.locator('#grant-descriptions')).toContainText('weekdays 08:00–18:00 (America/Chicago time)');
  await expect(page.locator('#validity')).toContainText('within its validity window');
  await expect(page.locator('#server-check')).toContainText('verifies with the issuer\'s key');
  await expect(page.locator('#server-check')).toContainText('not revoked');

  // Tampering breaks the signature; garbage is reported, not rendered.
  const [h, p, s] = issued.credential.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  payload.grants[0].actions = ['hashbin:<img src=x onerror=alert(1)>'];
  await page.getByLabel('Credential or access token').fill(`${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`);
  await expect(page.locator('#server-check')).toContainText('does not verify');
  await expect(page.locator('#grant-descriptions')).toContainText('<img src=x onerror=alert(1)>');
  expect(await page.locator('#grant-descriptions img').count()).toBe(0);
  await page.getByLabel('Credential or access token').fill('not a credential');
  await expect(page.locator('#local-result')).toContainText('not a compact JWS');
});

test('the playground allows inside a time window and denies outside it', async ({ page }) => {
  await page.goto('/tools/playground.html');
  await page.getByRole('button', { name: 'Office hours in Chicago' }).click();
  await expect(page.locator('#verdict')).toHaveText('Allow');
  await expect(page.locator('#time-note')).toContainText('Wednesday');
  // Saturday 10:00 in Chicago: outside the weekday window.
  await page.getByLabel('Date and time').fill('2026-11-21T10:00');
  await expect(page.locator('#verdict')).toHaveText('Deny');
  await expect(page.locator('#grant-results')).toContainText('outside_time_window');
  // Wednesday 19:30 is after hours.
  await page.getByLabel('Date and time').fill('2026-11-18T19:30');
  await expect(page.locator('#verdict')).toHaveText('Deny');
  // An action the grant does not name.
  await page.getByLabel('Date and time').fill('2026-11-18T09:00');
  await page.getByLabel('Action').fill('hashbin:content:delete');
  await expect(page.locator('#grant-results')).toContainText('action_not_granted');
});

test('the playground explains online-only grants and network rules', async ({ page }) => {
  await page.goto('/tools/playground.html');
  await page.getByRole('button', { name: /^Agent/ }).click();
  await expect(page.locator('#verdict')).toHaveText('Deny');
  await expect(page.locator('#verdict-panel')).toContainText('ask online');
  await page.getByLabel(/Evaluate online/).check();
  await expect(page.locator('#verdict')).toHaveText('Allow');
  await page.getByRole('button', { name: 'US only, from the office network' }).click();
  await expect(page.locator('#verdict')).toHaveText('Allow');
  await page.getByLabel('IP', { exact: true }).fill('198.51.100.1');
  await expect(page.locator('#grant-results')).toContainText('network_not_allowed');
});

test('the grant builder produces valid JSON, a CLI command and an SDK snippet', async ({ page }) => {
  await page.goto('/tools/builder.html');
  await page.getByLabel(/hashbin:content:write/).check();
  await expect(page.locator('#validation')).toContainText('Valid grant');
  await page.getByLabel('Location source').selectOption('network');
  await page.getByLabel(/Countries/).fill('US, CA');
  await page.getByLabel('Spend cap (USD / month)').fill('3');
  await page.getByLabel(/owner approves each use/).check();
  const grant = JSON.parse(await page.locator('#grant-json').textContent());
  expect(grant).toEqual({ actions: ['hashbin:content:write'], where: { source: 'network', countries: ['US', 'CA'] }, limits: { spend_usd_per_month: 3 }, require: { step_up: true } });
  await expect(page.locator('#english')).toContainText('only from US or CA');
  await expect(page.locator('#cli-command')).toContainText('dba enroll --aud hashbin.org --grant');
  await expect(page.locator('#sdk-snippet')).toContainText("aud: [\"hashbin.org\"]");
  await page.getByLabel(/Countries/).fill('usa');
  await expect(page.locator('#problems')).toContainText('ISO 3166-1');
});

test('the request signer shows the DPoP headers for a request', async ({ page }) => {
  await page.goto('/tools/signer.html');
  await expect(page.locator('#jkt')).not.toBeEmpty();
  await page.getByLabel('URL').fill('https://example.com/api/things?x=1');
  await page.getByLabel('Method').selectOption('DELETE');
  await page.getByRole('button', { name: 'Sign request' }).click();
  await expect(page.locator('#headers')).toContainText('DPoP: ey');
  await expect(page.locator('#proof-payload')).toContainText('"htm": "DELETE"');
  await expect(page.locator('#proof-payload')).toContainText('"htu": "https://example.com/api/things"');
  await expect(page.locator('#curl')).toContainText("curl -X DELETE -H 'DPoP: ");
});
