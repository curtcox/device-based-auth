// Builds frontend/llms-full.txt: llms.txt plus every API route, the credential format, the
// evaluation rules and the pricing sheet, in one plain-text file an agent can read in one fetch.
// Everything comes from files that are already the source of truth, so it cannot say anything
// they do not. scripts/llms-full.test.js fails on drift; `npm run docs:generate` rewrites it.
import { readFileSync } from 'node:fs';
import { API_ROUTES } from '../src/index.js';
import { openapi } from '../src/services/openapi.js';

const SOURCES = [
  ['spec/credential.md', 'Credential format'],
  ['spec/evaluation.md', 'Grant evaluation'],
  ['docs/business/pricing.md', 'Prices and why']
];

/** Every route as "METHOD /path — access — summary", grouped in route-table order. */
function routeList() {
  const spec = openapi(API_ROUTES);
  const lines = [];
  for (const [path, operations] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(operations)) lines.push(`- \`${method.toUpperCase()} ${path}\` (${op['x-access']}): ${op.summary}`);
  }
  return lines.join('\n');
}

/** Relative links in the included files would point nowhere once inlined; point them at GitHub. */
function absoluteLinks(text, file) {
  const dir = file.split('/').slice(0, -1).join('/');
  return text.replace(/\]\((?!https?:|#|mailto:)([^)]+)\)/g, (_, target) => {
    const parts = `${dir}/${target}`.split('/'); const out = [];
    for (const part of parts) { if (part === '..') out.pop(); else if (part !== '.' && part !== '') out.push(part); }
    return `](https://github.com/curtcox/device-based-auth/blob/main/${out.join('/')})`;
  });
}

/** The whole file as a string. `read` is injectable for tests. */
export function buildLlmsFull(read = path => readFileSync(path, 'utf8')) {
  const parts = [
    read('frontend/llms.txt').trimEnd(),
    '',
    '---',
    '',
    '# Every API route',
    '',
    'Access: PUBLIC needs nothing; SESSION is the dashboard (Clerk session or a DBA browser credential); DEVICE is a device credential + DPoP proof; a scope means an API key with it (or a session, or a device credential holding dba:<scope>). Full schemas: https://devicebasedauth.org/openapi.json',
    '',
    routeList()
  ];
  for (const [file, title] of SOURCES) {
    parts.push('', '---', '', `<!-- ${title}: from ${file} -->`, '', absoluteLinks(read(file).trimEnd(), file));
  }
  return `${parts.join('\n')}\n`;
}
