import { it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { buildLlmsFull } from './llms-full.mjs';
import { API_ROUTES } from '../src/index.js';

it('matches the checked-in frontend/llms-full.txt (npm run docs:generate)', () => {
  expect(readFileSync('frontend/llms-full.txt', 'utf8')).toBe(buildLlmsFull());
});

it('lists every public route and inlines the spec and prices with absolute links', () => {
  const text = buildLlmsFull();
  for (const route of API_ROUTES.filter(r => !r.path.startsWith('/webhooks/'))) {
    expect(text, `${route.method} ${route.path}`).toContain(`\`${route.method} ${route.path.replace(/:([a-z_]+)/g, '{$1}')}\``);
  }
  expect(text).toContain('<!-- Credential format: from spec/credential.md -->');
  expect(text).toContain('<!-- Prices and why: from docs/business/pricing.md -->');
  expect(text).not.toMatch(/\]\((?!https?:|#|mailto:)/);
});
