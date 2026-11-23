// frontend/_headers: Cloudflare static assets apply every rule whose path matches and join repeated
// header names into one comma-separated value. For Access-Control-Allow-Origin that yields "*, *",
// which browsers refuse, so other sites could not load a versioned SDK as a module script.
import { readFileSync } from 'node:fs';
import { it, expect } from 'vitest';

/** Rules as [pattern, [[name, value], ...]] in file order (Cloudflare's _headers format). */
function rules(text) {
  const out = [];
  for (const line of text.split('\n')) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    if (!/^\s/.test(line)) { out.push([line.trim(), []]); continue; }
    const at = line.indexOf(':'); out.at(-1)[1].push([line.slice(0, at).trim().toLowerCase(), line.slice(at + 1).trim()]);
  }
  return out;
}
/** A path pattern as a regular expression: `*` is a splat, `:name` one segment. */
const matcher = pattern => new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/:[A-Za-z]\w*/g, '[^/]+')}$`);

const parsed = rules(readFileSync(new URL('../frontend/_headers', import.meta.url), 'utf8'));
const PATHS = ['/', '/index.html', '/sdk/dba.js', '/sdk/integrity.json', '/sdk/v1.4.0/dba.js', '/lib/verify.js', '/docs/index.html'];

it('sends each header at most once on every path, so CORS answers a single "*"', () => {
  for (const path of PATHS) {
    const names = parsed.filter(([pattern]) => matcher(pattern).test(path)).flatMap(([, headers]) => headers.map(([name]) => name));
    expect(names.filter((name, i) => names.indexOf(name) !== i), path).toEqual([]);
  }
});

it('lets any site load the SDK, versioned or not, and caches released versions forever', () => {
  const headersFor = path => Object.fromEntries(parsed.filter(([pattern]) => matcher(pattern).test(path)).flatMap(([, headers]) => headers));
  expect(headersFor('/sdk/dba.js')['access-control-allow-origin']).toBe('*');
  expect(headersFor('/sdk/v1.4.0/dba.js')).toMatchObject({ 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=31536000, immutable' });
});
