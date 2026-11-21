import { describe, it, expect } from 'vitest';
import { UsageError } from './errors.js';
import { parseArgs, splitCommand, configPaths, resolveOrigin, DEFAULT_ORIGIN } from './args.js';

describe('argument parsing', () => {
  const spec = { values: ['name'], booleans: ['force'], repeatable: ['aud', 'action'] };

  it('reads values, repeated values, booleans and positionals', () => {
    const { options, positionals } = parseArgs(['--aud', 'a.org', '--aud=b.org', '--action', 'x:y', '--name=My laptop', '--force', 'extra'], spec);
    expect(options).toEqual({ aud: ['a.org', 'b.org'], action: ['x:y'], name: 'My laptop', force: true });
    expect(positionals).toEqual(['extra']);
  });

  it('stops at -- and treats - as a positional', () => {
    expect(parseArgs(['-', '--', '--force'], spec).positionals).toEqual(['-', '--force']);
  });

  it('refuses unknown options, missing values and values on booleans', () => {
    expect(() => parseArgs(['--grnat', '{}'], spec)).toThrow(UsageError);
    expect(() => parseArgs(['--name'], spec)).toThrow(/needs a value/);
    expect(() => parseArgs(['--force=yes'], spec)).toThrow(/does not take a value/);
  });

  it('splits global options from the command', () => {
    expect(splitCommand(['--profile', 'work', '--origin=http://localhost:8788', 'curl', '-sS', 'https://x.org/'])).toEqual({ globals: { profile: 'work', origin: 'http://localhost:8788' }, command: 'curl', rest: ['-sS', 'https://x.org/'] });
    expect(splitCommand(['--help'])).toEqual({ globals: { help: true }, command: undefined, rest: [] });
  });
});

describe('configuration', () => {
  it('puts each profile in its own directory', () => {
    expect(configPaths({ env: {}, home: '/home/u' }).dir).toBe('/home/u/.config/dba/default');
    expect(configPaths({ env: { XDG_CONFIG_HOME: '/x' }, home: '/home/u', profile: 'work' }).key).toBe('/x/dba/work/key.json');
    expect(configPaths({ env: { DBA_HOME: '/tmp/dba/' }, home: '/home/u' })).toEqual({ dir: '/tmp/dba/default', key: '/tmp/dba/default/key.json', credential: '/tmp/dba/default/credential.jwt', config: '/tmp/dba/default/config.json', confirmation: '/tmp/dba/default/confirmation.jwt', certificate: '/tmp/dba/default/client.crt', certificateKey: '/tmp/dba/default/client.key', ca: '/tmp/dba/default/ca.crt' });
  });

  it('refuses profile names that could escape the directory', () => {
    for (const profile of ['..', '../x', 'a/b', '', '.hidden']) expect(() => configPaths({ env: {}, home: '/h', profile })).toThrow(UsageError);
  });

  it('prefers --origin, then $DBA_ORIGIN, then the enrolled origin', () => {
    expect(resolveOrigin({})).toBe(DEFAULT_ORIGIN);
    expect(resolveOrigin({ saved: 'http://localhost:8788' })).toBe('http://localhost:8788');
    expect(resolveOrigin({ env: { DBA_ORIGIN: 'http://localhost:9/' }, saved: 'http://localhost:8788' })).toBe('http://localhost:9');
    expect(resolveOrigin({ flag: 'https://example.org/x', env: { DBA_ORIGIN: 'http://localhost:9' } })).toBe('https://example.org');
    expect(() => resolveOrigin({ flag: 'ftp://x' })).toThrow(UsageError);
  });
});
