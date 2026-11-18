import { test, expect } from '@playwright/test';
import { createServer } from 'node:http';
import { separateVisitors, signIn, fund, uniqueName, enrollViaApi } from './helpers.js';
import { pushBrowser } from '../../test-utils/push.js';

separateVisitors();

// Security notices end to end: the dashboard subscribes this browser (its push service stubbed by
// a local HTTP server, since headless Chromium has none), and the local Worker really encrypts
// and sends each notice, which the test decrypts with the browser's keys.
test('security notices: subscribe, get notices on issuance, turn off', async ({ page, context, request }) => {
  const received = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => { received.push({ headers: req.headers, body: Buffer.concat(chunks) }); res.writeHead(201).end(); });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const browser = await pushBrowser(`http://127.0.0.1:${server.address().port}/push/test`);
    await context.grantPermissions(['notifications']);
    await page.addInitScript(json => {
      let current = null;
      const make = () => ({ endpoint: json.endpoint, toJSON: () => json, unsubscribe: async () => { current = null; return true; } });
      PushManager.prototype.subscribe = async function subscribe(options) { if (!options?.applicationServerKey) throw new Error('no key'); current = make(); return current; };
      PushManager.prototype.getSubscription = async function getSubscription() { return current; };
    }, browser.subscription);
    const decrypted = async n => { await expect.poll(() => received.length).toBeGreaterThanOrEqual(n); return browser.decrypt(received[n - 1].body); };

    const owner = uniqueName('push');
    await fund(request, owner);
    await signIn(page, owner);
    await page.getByRole('link', { name: 'Account', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Security notices' })).toBeVisible();
    await page.getByLabel('Name for this browser').fill('Test laptop');
    await page.getByRole('button', { name: 'Notify this browser' }).click();
    await expect(page.locator('#flash')).toContainText('Security notices are on for Test laptop');
    await expect(page.locator('#view table')).toContainText('this browser');
    expect(received[0].headers['content-encoding']).toBe('aes128gcm');
    expect(received[0].headers.authorization).toMatch(/^vapid t=.+, k=B/);
    expect(await decrypted(1)).toMatchObject({ title: 'Security notices are on' });

    await enrollViaApi(request, owner, { name: 'Build server' });
    expect(await decrypted(2)).toMatchObject({ title: 'Credential issued', body: 'Build server for hashbin.org.' });

    await page.getByRole('button', { name: 'Turn off' }).click();
    await page.getByRole('button', { name: 'Yes, turn off' }).click();
    await expect(page.locator('#flash')).toContainText('Security notices to Test laptop are off');
    expect(await decrypted(3)).toMatchObject({ title: 'Security notices turned off' });
    await expect(page.locator('#view')).toContainText('No browser gets security notices yet.');
  } finally { server.close(); }
});
