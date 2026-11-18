// Bundles packages/browser-sdk/dba.js (with the verify library) into one ES module, so sites can
// pin it with Subresource Integrity. `--release` also writes the immutable versioned copy.
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';

const VERSION = readFileSync('packages/browser-sdk/dba.js', 'utf8').match(/export const VERSION = '([\d.]+)'/)[1];
const result = await build({ entryPoints: ['packages/browser-sdk/dba.js'], bundle: true, format: 'esm', target: 'es2022', write: false, legalComments: 'none', banner: { js: `// devicebasedauth.org browser SDK v${VERSION}. Built by scripts/build-sdk.mjs from packages/browser-sdk and packages/verify. MIT.` } });
const code = result.outputFiles[0].text;
mkdirSync('frontend/sdk', { recursive: true });
writeFileSync('frontend/sdk/dba.js', code);
const integrity = existsSync('frontend/sdk/integrity.json') ? JSON.parse(readFileSync('frontend/sdk/integrity.json', 'utf8')) : {};
if (process.argv.includes('--release')) {
  const dir = `frontend/sdk/v${VERSION}`;
  if (existsSync(`${dir}/dba.js`) && readFileSync(`${dir}/dba.js`, 'utf8') !== code) throw new Error(`${dir} is immutable; bump VERSION in packages/browser-sdk/dba.js`);
  mkdirSync(dir, { recursive: true }); writeFileSync(`${dir}/dba.js`, code);
  integrity[`v${VERSION}`] = `sha384-${createHash('sha384').update(code).digest('base64')}`;
  writeFileSync('frontend/sdk/integrity.json', JSON.stringify(integrity, null, 2) + '\n');
}
console.log(`built frontend/sdk/dba.js (v${VERSION}, ${code.length} bytes)`);
