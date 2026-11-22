// Shared helpers for the browser tests. Devices made here (Node side) use the same verify library
// as everything else, so a test can create real credentials without a browser when it only needs one.
import { test, expect } from '@playwright/test';
import { generateKeyPair, exportPublicJwk, signJws, createProof } from '../../packages/verify/src/index.js';

/** A fresh local account name per test, so tests never share balances or credentials. */
export const uniqueName = (prefix = 'user') => `${prefix}-${crypto.randomUUID().slice(0, 8)}`;

/**
 * Give each test its own client IP, as separate visitors have in production; the local per-IP
 * limiter would otherwise count the whole suite as one visitor.
 */
export function separateVisitors() {
  test.beforeEach(async ({ context }, testInfo) => {
    await context.setExtraHTTPHeaders({ 'CF-Connecting-IP': ipFor(testInfo) });
  });
}
const ipFor = testInfo => `2001:db8::${(testInfo.workerIndex + 1).toString(16)}:${(testInfo.line + 1).toString(16)}:${(testInfo.retry + 1).toString(16)}`;

/** Headers for an API call as a local account. */
export const asLocal = name => ({ Authorization: `LocalDev ${name}` });

/** Add development credit to a local account. */
export async function fund(request, name, amount = 1_000_000) {
  const response = await request.post('/api/v1/dev/deposit', { headers: asLocal(name), data: { amount_microdollars: amount } });
  expect(response.ok()).toBeTruthy();
  return response.json();
}

/** Sign in to the dashboard as a local account (stored in localStorage, so popups share it). */
export async function signIn(page, name) {
  await page.goto('/app.html');
  await page.getByLabel('Local account name').fill(name);
  await page.getByRole('button', { name: 'Use local account' }).click();
  await expect(page.getByRole('heading', { name: 'Credentials', exact: true })).toBeVisible();
}

/** Start an enrollment for a new (Node-side) device. Returns the start response body. */
export async function startEnrollment(request, { aud = ['hashbin.org'], grants = [{ actions: ['hashbin:content:write'] }], name = 'Test device', kind = 'server' } = {}) {
  const pair = await generateKeyPair(false);
  const jwk = await exportPublicJwk(pair.publicKey);
  const signed = await signJws({ typ: 'dba-enroll+jwt', jwk }, { iat: Math.floor(Date.now() / 1000), aud, grants, device: { name, kind } }, pair.privateKey);
  const response = await request.post('/api/v1/enrollments', { data: { request: signed } });
  expect(response.ok()).toBeTruthy();
  return { ...await response.json(), device: { privateKey: pair.privateKey, publicJwk: jwk } };
}

/** Enroll and approve through the API; returns { credential, cid, device_id, device: { privateKey, publicJwk } }. */
export async function enrollViaApi(request, owner, options) {
  const start = await startEnrollment(request, options);
  const response = await request.post('/api/v1/enrollments/approve', { headers: asLocal(owner), data: { request: start.request } });
  expect(response.ok()).toBeTruthy();
  return { ...await response.json(), device: start.device };
}

/** Dollars from micro-dollars, formatted as the site does. */
export const usd = micro => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 6 }).format(micro / 1_000_000);

/**
 * Send a request signed by a device, like the SDK and CLI do: once more with the nonce when a
 * just-started account object answers 401 use_dpop_nonce (STATUS D15).
 */
export async function sendSigned(request, { privateKey, publicJwk, credential, method, url, data }) {
  const send = async nonce => request.fetch(url, { method, data, headers: { Authorization: `DBA ${credential}`, DPoP: await createProof({ privateKey, publicJwk, method, url, credential, nonce }) } });
  const first = await send();
  if (first.status() !== 401) return first;
  const body = await first.json().catch(() => ({}));
  return body.code === 'use_dpop_nonce' && body.dpop_nonce ? send(body.dpop_nonce) : first;
}
