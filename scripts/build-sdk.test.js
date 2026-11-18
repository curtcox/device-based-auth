import { it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { build } from 'esbuild';

it('keeps frontend/sdk/dba.js in sync with its sources (node scripts/build-sdk.mjs)', async () => {
  const VERSION = readFileSync('packages/browser-sdk/dba.js', 'utf8').match(/export const VERSION = '([\d.]+)'/)[1];
  const result = await build({ entryPoints: ['packages/browser-sdk/dba.js'], bundle: true, format: 'esm', target: 'es2022', write: false, legalComments: 'none', banner: { js: `// devicebasedauth.org browser SDK v${VERSION}. Built by scripts/build-sdk.mjs from packages/browser-sdk and packages/verify. MIT.` } });
  expect(readFileSync('frontend/sdk/dba.js', 'utf8')).toBe(result.outputFiles[0].text);
});
it('pins every released SDK version with its integrity hash', () => {
  if (!existsSync('frontend/sdk/integrity.json')) return;
  const integrity = JSON.parse(readFileSync('frontend/sdk/integrity.json', 'utf8'));
  const releases = readdirSync('frontend/sdk').filter(d => /^v\d/.test(d));
  expect(Object.keys(integrity).sort()).toEqual(releases.sort());
  for (const version of releases) expect(integrity[version]).toBe(`sha384-${createHash('sha384').update(readFileSync(`frontend/sdk/${version}/dba.js`)).digest('base64')}`);
});
