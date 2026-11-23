// Writes frontend/openapi.json from API_ROUTES (tab-indented: smaller than spaces, under its size limit). src/services/openapi.test.js fails on drift.
import { writeFileSync } from 'node:fs';
import { API_ROUTES } from '../src/index.js';
import { openapi } from '../src/services/openapi.js';
writeFileSync('frontend/openapi.json', JSON.stringify(openapi(API_ROUTES), null, '\t') + '\n');
console.log('wrote frontend/openapi.json');
