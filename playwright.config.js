// Browser tests for the static site in frontend/, against a real local Worker (wrangler dev,
// local mode, fresh state per run). Set PW_CHROMIUM_PATH to use a preinstalled Chromium when the
// installed @playwright/test version does not match the downloaded browser.
import { defineConfig } from '@playwright/test';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PORT = 8787;
// Workers re-load this file; reuse the directory the main process made (inherited env).
process.env.DBA_E2E_STATE ||= mkdtempSync(join(tmpdir(), 'dba-e2e-'));

export default defineConfig({
  testDir: 'frontend/tests',
  timeout: 60000,
  expect: { timeout: 10000 },
  workers: 2,
  reporter: [['list']],
  use: {
    baseURL: `http://localhost:${PORT}`,
    browserName: 'chromium',
    trace: 'off',
    launchOptions: process.env.PW_CHROMIUM_PATH ? { executablePath: process.env.PW_CHROMIUM_PATH } : {}
  },
  webServer: {
    command: `npx wrangler dev --config wrangler.local.toml --local --port ${PORT} --persist-to ${process.env.DBA_E2E_STATE}`,
    url: `http://localhost:${PORT}/health`,
    reuseExistingServer: false,
    timeout: 120000,
    stdout: 'ignore',
    stderr: 'pipe'
  }
});
