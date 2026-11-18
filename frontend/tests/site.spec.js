import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { separateVisitors, signIn, uniqueName, usd } from './helpers.js';

separateVisitors();

const PAGES = ['/', '/app.html', '/approve.html', '/authorize.html', '/pricing.html', '/docs/', '/tools/', '/tools/inspector.html', '/tools/playground.html', '/tools/builder.html', '/tools/signer.html', '/tools/explorer.html', '/terms.html', '/privacy.html', '/sitemap.html'];

test('serves every page with security headers', async ({ request }) => {
  for (const path of PAGES) {
    // The asset server may canonicalize /page.html to /page (same origin); the page must load.
    const first = await request.get(path, { maxRedirects: 0 });
    if (first.status() === 307) expect(new URL(first.headers().location, 'http://localhost:8787').origin, path).toBe('http://localhost:8787');
    const response = await request.get(path);
    expect(response.status(), path).toBe(200);
    const headers = response.headers();
    expect(headers['content-type'], path).toContain('text/html');
    expect(headers['content-security-policy'], path).toContain("frame-ancestors 'none'");
    expect(headers['content-security-policy'], path).toContain("script-src 'self' https://cdn.jsdelivr.net");
    expect(headers['x-content-type-options'], path).toBe('nosniff');
    expect(headers['referrer-policy'], path).toBeTruthy();
  }
  expect((await request.get('/favicon.svg')).headers()['content-type']).toContain('image/svg');
  expect((await request.get('/tests/site.spec.js')).status()).toBe(404);
});

test('landing page explains the service and shows live prices', async ({ page, request }) => {
  const config = await (await request.get('/api/public/config')).json();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Revocable, device-bound credentials');
  await expect(page.locator('#live-prices [data-op="issue"]')).toContainText(usd(config.prices.issue));
  await expect(page.locator('#live-prices [data-op="decision"]')).toContainText(`${config.prices.decision} µ$`);
  await expect(page.locator('#live-prices')).toContainText('Offline verification: free');
  for (const name of ['Docs', 'Tools', 'Pricing', 'Dashboard']) await expect(page.getByRole('navigation', { name: 'Site' }).getByRole('link', { name })).toBeVisible();
  expect(errors).toEqual([]);
});

test('pricing page lists live prices and the calculator follows the inputs', async ({ page, request }) => {
  const config = await (await request.get('/api/public/config')).json();
  await page.goto('/pricing.html');
  await expect(page.locator('#prices [data-op="issue"]')).toContainText(`${config.prices.issue} µ$`);
  await expect(page.locator('#prices')).toContainText('Online authorization decision');
  await page.getByLabel('Devices').fill('0');
  await page.getByLabel('New enrollments this month').fill('2');
  await page.getByLabel('Online decisions / month').fill('1000');
  const expected = 2 * config.prices.issue + 1000 * config.prices.decision;
  await expect(page.locator('#calculator-total')).toContainText(`${expected.toLocaleString('en-US')} µ$`);
});

test('pages fit a phone screen without horizontal scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  for (const path of ['/', '/pricing.html', '/docs/', '/tools/', '/tools/inspector.html', '/tools/playground.html', '/tools/builder.html', '/tools/signer.html', '/terms.html']) {
    await page.goto(path);
    await page.waitForLoadState('networkidle');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), path).toBe(true);
  }
  await signIn(page, uniqueName('phone'));
  for (const hash of ['#credentials', '#devices', '#issue', '#tokens', '#account', '#transactions', '#keys', '#audiences', '#panic']) {
    await page.goto(`/app.html${hash}`);
    await page.waitForLoadState('networkidle');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), hash).toBe(true);
  }
});

test('docs code taken from docs/samples matches the tested samples', async ({ page }) => {
  await page.goto('/docs/');
  const blocks = await page.locator('pre[data-sample]').evaluateAll(pres => pres.map(pre => ({ sample: pre.dataset.sample, text: pre.textContent })));
  expect(blocks.length).toBeGreaterThan(0);
  for (const { sample, text } of blocks) {
    const source = await readFile(new URL(`../../docs/samples/${sample}`, import.meta.url), 'utf8');
    const lines = source.split('\n').map(line => line.trimEnd());
    for (const line of text.split('\n').map(l => l.trimEnd()).filter(Boolean)) expect(lines, `${sample}: ${line}`).toContain(line);
  }
  for (const id of ['concepts', 'format', 'browser', 'cli', 'verify', 'workers', 'authorize', 'oidc', 'mcp', 'revocation', 'api']) await expect(page.locator(`section#${id} h2`)).toBeVisible();
});
