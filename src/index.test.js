import { it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { API_ROUTES, matchRoute } from './index.js';
import { PUBLIC, SESSION, DEVICE, AUTHENTICATED, USER_SCOPES } from './auth/scopes.js';

it('declares valid access for every route', () => {
  for (const route of API_ROUTES) {
    const ok = [PUBLIC, SESSION, DEVICE, AUTHENTICATED].includes(route.access) || USER_SCOPES.includes(route.access);
    expect(ok, `${route.method} ${route.path}`).toBe(true);
  }
});
it('has no duplicate routes and matches parameters', () => {
  const keys = API_ROUTES.map(r => `${r.method} ${r.path}`);
  expect(new Set(keys).size).toBe(keys.length);
  expect(matchRoute('GET', '/api/v1/credentials/crd_1').params).toEqual({ cid: 'crd_1' });
  expect(matchRoute('GET', '/api/v1/credentials/a/b')).toBe(null);
  expect(matchRoute('GET', '/api/v1/credentials/%E0%A4%A')).toBe(null);
});
it('binds every exported Durable Object in both wrangler configs', async () => {
  const exported = Object.keys(await import('./index.js')).filter(name => name.endsWith('DO'));
  for (const file of ['wrangler.toml', 'wrangler.local.toml']) {
    const config = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
    for (const name of exported) expect(config, `${file} ${name}`).toContain(`class_name = "${name}"`);
  }
});
it('keeps the local issuer key out of production config', () => {
  expect(readFileSync(new URL('../wrangler.toml', import.meta.url), 'utf8')).not.toMatch(/ISSUER_KEYS\s*=/);
});
