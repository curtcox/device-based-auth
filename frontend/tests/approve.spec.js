import { test, expect } from '@playwright/test';
import { createProof } from '../../packages/verify/src/index.js';
import { separateVisitors, signIn, fund, uniqueName, startEnrollment, enrollViaApi, asLocal } from './helpers.js';

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

test('the owner can require periodic confirmation by one of their gates when approving (STATUS B7 G9)', async ({ page, request }) => {
  const owner = uniqueName('confirmer');
  await fund(request, owner);
  const phone = await enrollViaApi(request, owner, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:approvals:answer'] }], name: 'Phone' });
  const gate = await (await request.post('/api/v1/gates', { headers: asLocal(owner), data: { kind: 'dba-device', label: 'My phone', device_id: phone.device_id } })).json();
  const start = await startEnrollment(request, { name: 'Shared laptop' });
  await signIn(page, owner);
  await page.goto(`/approve.html#${start.request}`);
  await page.getByText('Require periodic confirmation').click();
  await expect(page.locator('#confirm-gate')).toContainText('My phone (dba-device)');
  await page.locator('#confirm-gate').selectOption(gate.id);
  await page.getByLabel('Require confirmation').check();
  await page.getByLabel('Every (hours)').fill('8');
  await page.getByRole('button', { name: /^Approve for/ }).click();
  await expect(page.getByText('Approved — the device will pick up its credential')).toBeVisible();
  const { credential } = await (await request.get(start.poll_url.replace(/^https?:\/\/[^/]+/, ''))).json();
  const payload = JSON.parse(Buffer.from(credential.split('.')[1], 'base64url'));
  expect(payload.confirm).toEqual({ gates: [{ any: [gate.id], timeout_s: 300, on_timeout: 'deny' }], every_s: 28800 });

  // The laptop asks, the phone allows; the dashboard shows it confirmed and can stop trusting it.
  const signed = async (device, cred, method, path, data) => request.fetch(path, { method, data, headers: { Authorization: `DBA ${cred}`, DPoP: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method, url: new URL(path, page.url()).href, credential: cred }) } });
  const path = `/api/v1/credentials/${payload.cid}/confirm`;
  expect((await (await signed(start.device, credential, 'POST', path, {})).json()).status).toBe('pending');
  const [waiting] = (await (await signed(phone.device, phone.credential, 'GET', '/api/v1/gate-requests')).json()).items;
  expect((await signed(phone.device, phone.credential, 'POST', `/api/v1/gate-requests/${waiting.id}/answer`, { ...waiting.answer_as[0], decision: 'allow' })).ok()).toBeTruthy();
  expect((await (await signed(start.device, credential, 'POST', path, {})).json()).status).toBe('confirmed');
  await page.goto(`/app.html#credential/${payload.cid}`);
  await expect(page.locator('#confirmation-area')).toContainText('every 8 hours');
  await expect(page.locator('#confirmation-area')).toContainText('Confirmed until');
  await page.getByRole('button', { name: 'Stop trusting now' }).click();
  await page.getByRole('button', { name: 'Yes, stop trusting it' }).click();
  await expect(page.locator('#confirmation-area')).toContainText('Not confirmed now');
});
