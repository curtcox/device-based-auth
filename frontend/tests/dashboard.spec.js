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
  // Budget guards: saved through the API, refused when out of range.
  await expect(page.getByLabel('Credentials issued per day (UTC)')).toHaveValue('500');
  await page.getByLabel('Credentials issued per day (UTC)').fill('20');
  await page.getByLabel(/Renewals per credential per month/).fill('40');
  await page.getByRole('button', { name: 'Save limits' }).click();
  await expect(page.locator('#view')).toContainText('Saved.');
  const settings = await (await page.request.get('/api/v1/account/settings', { headers: { Authorization: `LocalDev ${owner}` } })).json();
  expect(settings).toMatchObject({ max_issues_per_day: 20, max_renewals_per_credential_per_month: 40 });
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

  // Export: every credential, as CSV and as JSON, with names kept as data.
  await page.getByRole('link', { name: 'Credentials', exact: true }).click();
  const [csvDownload] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export CSV' }).click()]);
  expect(csvDownload.suggestedFilename()).toMatch(/^credentials-\d{4}-\d{2}-\d{2}\.csv$/);
  const csv = await new Response(await csvDownload.createReadStream()).text();
  expect(csv.split('\r\n')).toHaveLength(4);
  expect(csv).toContain(first.cid);
  expect(csv).toContain('Laptop <b>bold</b>');
  const [jsonDownload] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export JSON' }).click()]);
  const exported = JSON.parse(await new Response(await jsonDownload.createReadStream()).text());
  expect(exported).toMatchObject({ account: owner, count: 2 });
  expect(exported.items.some(c => 'jws' in c)).toBe(false);

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
  // Revocation webhook (B1): nothing listens on port 9, so the test event is reported undelivered.
  await page.getByLabel(/Revocation webhook/).fill('http://localhost:9/hook');
  await page.getByRole('button', { name: /^Save for/ }).click();
  await expect(page.locator('#flash')).toContainText(`Revocation webhook for ${owner}.localhost saved.`);
  await expect(page.getByLabel(/Revocation webhook/)).toHaveValue('http://localhost:9/hook');
  await page.getByRole('button', { name: /^Send test event/ }).click();
  await expect(page.locator('.webhook-form')).toContainText('Not delivered');
  // Gate policies (B7): require security-key or TOTP gates for an action, and no allow by timeout on sign-in.
  await page.getByText('Gate policies').click();
  await page.getByLabel(`Require gates for ${owner}:notes:read`).check();
  await page.getByLabel(`Gate kinds for ${owner}:notes:read`).fill('totp, webauthn');
  await page.getByLabel('Refuse allow by timeout for Signing in (OpenID Connect)').check();
  await page.locator('.gate-policies').getByRole('button', { name: /^Save for/ }).click();
  await expect(page.locator('#flash')).toContainText(`Gate policies for ${owner}.localhost saved.`);
  await expect(page.locator('#view')).toContainText('gates required (totp, webauthn)');
  await expect(page.locator('#view')).toContainText('Signing in: no allow by timeout');
  const audience = await (await request.get(`/api/v1/audiences/${owner}.localhost`)).json();
  expect(audience.catalog[0].gates).toEqual({ require: true, kinds: ['totp', 'webauthn'] });
  expect(audience.sign_in_gates).toEqual({ fail_open: false });

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
