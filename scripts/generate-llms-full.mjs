// Writes frontend/llms-full.txt (see scripts/llms-full.mjs).
import { writeFileSync } from 'node:fs';
import { buildLlmsFull } from './llms-full.mjs';
writeFileSync('frontend/llms-full.txt', buildLlmsFull());
console.log('wrote frontend/llms-full.txt');
