import { it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

// The Go port checks itself against edge cases recorded from this JavaScript evaluator. When the
// evaluator changes, regenerate them (command in the script) and make the Go port agree.
it('packages/verify-go/testdata/crosscheck.json matches the JavaScript evaluator', () => {
  const fresh = execFileSync(process.execPath, ['packages/verify-go/testdata/crosscheck.mjs'], { encoding: 'utf8' });
  expect(JSON.parse(fresh)).toEqual(JSON.parse(readFileSync('packages/verify-go/testdata/crosscheck.json', 'utf8')));
});
