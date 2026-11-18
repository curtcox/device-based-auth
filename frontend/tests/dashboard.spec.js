import { test, expect } from '@playwright/test';
import { separateVisitors, signIn, fund, uniqueName, enrollViaApi, asLocal } from './helpers.js';
import { createProof } from '../../packages/verify/src/index.js';

separateVisitors();

test('local sign-in, development deposit, and the account page', async ({ page }) => {
  const owner = uniqueName('local');
  await signIn(page, owner);
  await expect(page.locator('#balance')).toHaveText('Balance $0.00');
  await page.getByRole('link', { name: 'Account', exact: true }).click();
  await expect(page.locator('#account-id')).toHaveText(owner);
  await page.getByLabel('Development credit (USD)').fill('2.5');
  await page.getByRole('button', { name: 'Add development credit' }).click();
  await expect(page.locator('#balance')).toHaveText('Balance $2.50');
  // Signed in survives a reload (localStorage).
  await page.reload();
  await expect(page.locator('#account-balance')).toContainText('2,500,000 µ$');
  await page.getByRole('link', { name: 'Transactions', exact: true }).click();
  await expect(page.locator('#view table')).toContainText('development credit');
});

test('devices, API keys, audiences and the panic button', async ({ page, request }) => {
  const owner = uniqueName('panel');
  await fund(request, owner);
  const first = await enrollViaApi(request, owner, { name: 'Laptop <b>bold</b>' });
  await enrollViaApi(request, owner, { name: 'Phone' });
  await signIn(page, owner);
  // Device names are text, never markup.
  await expect(page.getByRole('link', { name: 'Laptop <b>bold</b>' })).toBeVisible();
  await page.getByRole('link', { name: 'Devices', exact: true }).click();
  await expect(page.locator('#view table')).toContainText(first.device_id);

  await page.getByRole('link', { name: 'API keys', exact: true }).click();
  await page.getByLabel('Name', { exact: true }).fill('ci reader');
  await page.getByRole('button', { name: 'Create key' }).click();
  await expect(page.locator('#key-secret')).toContainText('dbak_');
  const secret = await page.locator('#key-secret').textContent();
  const read = await request.get('/api/v1/credentials', { headers: { Authorization: `ApiKey ${secret}` } });
  expect(read.status()).toBe(200);

  await page.getByRole('link', { name: 'Audiences', exact: true }).click();
  await expect(page.locator('#view')).toContainText('cronly.org');
  await expect(page.locator('#view')).toContainText('You have not registered an audience.');
  await page.getByLabel('Domain name').fill(`${owner}.localhost`);
  await page.getByLabel('Action namespace').fill(owner.replace(/[^a-z0-9-]/g, ''));
  await page.getByLabel(/Action catalog/).fill(`${owner}:notes:read Read notes`);
  await page.getByRole('button', { name: /^Register for/ }).click();
  await expect(page.locator('#flash')).toContainText(`Registered ${owner}.localhost`);
  await expect(page.locator('#view')).toContainText('Read notes');
  await expect(page.locator('.audience-usage')).toContainText('Online decisions');
  await expect(page.locator('.audience-usage tbody tr')).toHaveCount(1);

  await page.getByRole('link', { name: 'Revoke everything' }).click();
  const button = page.locator('#panic-button');
  await expect(button).toBeDisabled();
  await page.getByLabel('Type revoke-all to confirm').fill('revoke-all');
  await expect(button).toBeEnabled();
  await button.click();
  await expect(page.locator('#view')).toContainText('Revoked 2 credentials');
  const list = await (await request.get('/api/v1/credentials', { headers: asLocal(owner) })).json();
  expect(list.items.every(c => c.state === 'revoked')).toBe(true);
});

test('step-up approvals appear in the dashboard and approving lets the next use through', async ({ page, request }) => {
  const owner = uniqueName('stepper');
  await fund(request, owner);
  // hashbin.org belongs to the local "operator" account, which asks for online decisions.
  await fund(request, 'operator');
  const key = await (await request.post('/api/v1/keys', { headers: asLocal('operator'), data: { name: 'hashbin verifier', scopes: ['authorize'] } })).json();
  const issued = await enrollViaApi(request, owner, { name: 'Release bot', grants: [{ actions: ['hashbin:content:delete'], require: { step_up: true } }] });
  const ask = async () => {
    const url = 'https://hashbin.org/api/content/abc';
    const proof = await createProof({ ...issued.device, method: 'DELETE', url, credential: issued.credential });
    return (await request.post('/api/v1/authorize', { headers: { Authorization: `ApiKey ${key.secret}` }, data: { credential: issued.credential, proof, request: { method: 'DELETE', url }, audience: 'hashbin.org', action: 'hashbin:content:delete', resource: 'abc' } })).json();
  };
  expect((await ask()).code).toBe('step_up_required');
  await signIn(page, owner);
  await page.getByRole('link', { name: 'Approvals', exact: true }).click();
  await expect(page.locator('#approval-list')).toContainText('Release bot');
  await expect(page.locator('#approval-list')).toContainText('hashbin:content:delete');
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.locator('#flash')).toContainText('Approved for the next use');
  expect((await ask()).allow).toBe(true);
  // The decision log shows on the credential page.
  await page.goto(`/app.html#credential/${issued.cid}`);
  await expect(page.locator('#view')).toContainText('step_up_required');
});
