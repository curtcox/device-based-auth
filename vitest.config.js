import { defineConfig } from 'vitest/config';
export default defineConfig({ test: { include: ['src/**/*.test.js', 'packages/**/*.test.js', 'scripts/**/*.test.js', 'spec/**/*.test.js'] } });
