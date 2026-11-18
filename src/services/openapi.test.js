import { it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { API_ROUTES } from '../index.js';
import { openapi } from './openapi.js';
it('matches the checked-in frontend/openapi.json (npm run docs:generate)', () => {
  expect(JSON.parse(readFileSync('frontend/openapi.json', 'utf8'))).toEqual(openapi(API_ROUTES));
});
it('documents every non-webhook route with a summary', () => {
  const spec = openapi(API_ROUTES);
  for (const route of API_ROUTES.filter(r => !r.path.startsWith('/webhooks/'))) {
    const op = spec.paths[route.path.replace(/:([a-z_]+)/g, '{$1}')][route.method.toLowerCase()];
    expect(op.summary, `${route.method} ${route.path}`).not.toBe(route.handler);
  }
});
