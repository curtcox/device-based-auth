// Copies the zero-dependency verify library to frontend/lib/verify/ so pages and the browser SDK
// import exactly the code relying parties use. src/browser-lib.test.js fails on drift.
import { readdirSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
const from = 'packages/verify/src'; const to = 'frontend/lib/verify';
rmSync(to, { recursive: true, force: true }); mkdirSync(to, { recursive: true });
for (const file of readdirSync(from).filter(f => f.endsWith('.js') && !f.endsWith('.test.js'))) {
  writeFileSync(`${to}/${file}`, `// Generated from packages/verify/src/${file} by scripts/sync-browser-lib.mjs. Do not edit.\n${readFileSync(`${from}/${file}`, 'utf8')}`);
}
console.log(`synced ${to}`);
