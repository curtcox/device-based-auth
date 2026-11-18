import { it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
it('serves an up-to-date copy of the verify library to browsers (npm run docs:generate)', () => {
  const files = readdirSync('packages/verify/src').filter(f => f.endsWith('.js') && !f.endsWith('.test.js'));
  expect(readdirSync('frontend/lib/verify').sort()).toEqual(files.sort());
  for (const file of files) expect(readFileSync(`frontend/lib/verify/${file}`, 'utf8')).toBe(`// Generated from packages/verify/src/${file} by scripts/sync-browser-lib.mjs. Do not edit.\n${readFileSync(`packages/verify/src/${file}`, 'utf8')}`);
});
