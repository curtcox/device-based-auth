import { test, expect } from '@playwright/test';
import { separateVisitors, signIn, fund, uniqueName, startEnrollment } from './helpers.js';

separateVisitors();

test('the approval page refuses an unfunded account with a way to add credit (402)', async ({ page, request }) => {
  const owner = uniqueName('broke');
  const start = await startEnrollment(request, { name: 'Build server', grants: [{ actions: ['cronly:run'], where: { source: 'network', countries: ['US'] } }], aud: ['cronly.org'] });
  await signIn(page, owner);
  await page.goto(`/approve.html#${start.request}`);
  await expect(page.getByRole('heading', { name: /Build server/ })).toBeVisible();
  await expect(page.locator('#grant-descriptions')).toContainText('only from US');
  await page.getByRole('button', { name: /^Approve for/ }).click();
  await expect(page.locator('#approve-result')).toContainText('Insufficient balance');
  await expect(page.locator('#add-credit')).toHaveAttribute('href', '/app.html#account');
  // Funding the account and retrying works: the request stayed open.
  await fund(request, owner);
  await page.getByRole('button', { name: /^Approve for/ }).click();
  await expect(page.getByText('Approved — the device will pick up its credential')).toBeVisible();
});

test('the approval page asks for sign-in first, keeps the request, and handles a decided request (409)', async ({ page, context, request }) => {
  const owner = uniqueName('approver');
  await fund(request, owner);
  const start = await startEnrollment(request, { name: 'CI runner' });
  await page.goto(`/approve.html#${start.request}`);
  await expect(page.getByRole('heading', { name: /CI runner/ })).toBeVisible();
  await page.getByLabel('Local account name').fill(owner);
  await page.getByRole('button', { name: 'Use local account' }).click();
  // Narrow the grants and rename the device before approving.
  await page.getByLabel('Device name').fill('CI runner (narrowed)');
  await page.getByText('Edit the grants').click();
  await page.locator('textarea[name="grants"]').fill(JSON.stringify([{ actions: ['hashbin:content:write'], resources: ['ci/*'] }]));
  await expect(page.locator('#edited-descriptions')).toContainText('resources starting with "ci/"');
  // A second tab with the same link, still showing the open request.
  const other = await context.newPage();
  await other.goto(`/approve.html#${start.request}`);
  await expect(other.getByRole('button', { name: /^Approve for/ })).toBeVisible();
  await page.getByRole('button', { name: /^Approve for/ }).click();
  await expect(page.getByText('Approved — the device will pick up its credential')).toBeVisible();
  await other.getByRole('button', { name: /^Approve for/ }).click();
  await expect(other.locator('#approve-result')).toContainText('Already decided');
  const poll = await (await request.get(start.poll_url.replace(/^https?:\/\/[^/]+/, ''))).json();
  expect(poll.status).toBe('approved');
  // Opening the same link again shows it is already decided.
  await page.goto('/app.html');
  await page.goto(`/approve.html#${start.request}`);
  await expect(page.locator('#approve-root')).toContainText('already approved');
  const credentials = await (await request.get('/api/v1/credentials', { headers: { Authorization: `LocalDev ${owner}` } })).json();
  expect(credentials.items[0]).toMatchObject({ device: { name: 'CI runner (narrowed)' }, grants: [{ actions: ['hashbin:content:write'], resources: ['ci/*'] }] });
});

test('denying tells the device', async ({ page, request }) => {
  const owner = uniqueName('denier');
  const start = await startEnrollment(request, { name: 'Unknown laptop' });
  await signIn(page, owner);
  await page.goto(`/approve.html#${start.request}`);
  await page.getByRole('button', { name: 'Deny' }).click();
  await expect(page.locator('#approve-root')).toContainText('Denied');
  const poll = await (await request.get(start.poll_url.replace(/^https?:\/\/[^/]+/, ''))).json();
  expect(poll.status).toBe('denied');
});

test('the approval page warns about a grant that pinpoints a place and offers a coarse area', async ({ page, request }) => {
  const owner = uniqueName('placer');
  await fund(request, owner);
  const start = await startEnrollment(request, { name: 'Home tablet', grants: [{ actions: ['hashbin:content:write'], where: { source: 'device', areas: [{ lat: 38.627123, lon: -90.199456, radius_m: 150 }] } }] });
  await signIn(page, owner);
  await page.goto(`/approve.html#${start.request}`);
  await expect(page.locator('#area-privacy')).toContainText('pinpoints a place');
  await page.getByRole('button', { name: /Use coarse areas/ }).click();
  await expect(page.locator('#area-privacy')).toBeEmpty();
  await expect(page.locator('#edited-descriptions')).toContainText('within 1 km of 38.63,-90.2');
  await page.getByRole('button', { name: /^Approve for/ }).click();
  await expect(page.getByText('Approved — the device will pick up its credential')).toBeVisible();
  const credentials = await (await request.get('/api/v1/credentials', { headers: { Authorization: `LocalDev ${owner}` } })).json();
  expect(credentials.items[0].grants[0].where.areas).toEqual([{ lat: 38.63, lon: -90.2, radius_m: 1000 }]);
});
