// Writes frontend/openapi.json from API_ROUTES. src/services/openapi.test.js fails on drift.
import { writeFileSync } from 'node:fs';
import { API_ROUTES } from '../src/index.js';
import { openapi } from '../src/services/openapi.js';
writeFileSync('frontend/openapi.json', JSON.stringify(openapi(API_ROUTES), null, 2) + '\n');
console.log('wrote frontend/openapi.json');
