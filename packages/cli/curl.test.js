import { describe, it, expect } from 'vitest';
import { UsageError } from './errors.js';
import { curlRequest, curlArgs, curlHeaderFile, curlWaitOption } from './curl.js';

describe('curl handling', () => {
  it('finds the method and URL the way curl would', () => {
    expect(curlRequest(['-sS', 'https://hashbin.org/api/content'])).toEqual({ method: 'GET', url: 'https://hashbin.org/api/content' });
    expect(curlRequest(['https://x.org/a', '-d', '{"a":1}'])).toEqual({ method: 'POST', url: 'https://x.org/a' });
    expect(curlRequest(['--data-binary', '@file', 'https://x.org/a'])).toMatchObject({ method: 'POST' });
    expect(curlRequest(['--json', '{}', 'https://x.org/a'])).toMatchObject({ method: 'POST' });
    expect(curlRequest(['-F', 'f=@x', 'https://x.org/a'])).toMatchObject({ method: 'POST' });
    expect(curlRequest(['-G', '-d', 'q=1', 'https://x.org/a'])).toMatchObject({ method: 'GET' });
    expect(curlRequest(['-X', 'delete', 'https://x.org/a'])).toMatchObject({ method: 'DELETE' });
    expect(curlRequest(['-XPUT', '-d', 'x', 'https://x.org/a'])).toMatchObject({ method: 'PUT' });
    expect(curlRequest(['--request=PATCH', 'https://x.org/a'])).toMatchObject({ method: 'PATCH' });
    expect(curlRequest(['-I', 'https://x.org/a'])).toMatchObject({ method: 'HEAD' });
    expect(curlRequest(['-T', 'file.txt', 'https://x.org/a'])).toMatchObject({ method: 'PUT' });
  });

  it('never mistakes an option value for the URL', () => {
    expect(curlRequest(['-H', 'https://not-the-url/', '-d', 'https://data/', 'https://x.org/real']).url).toBe('https://x.org/real');
    expect(curlRequest(['--url', 'https://x.org/u', 'https://x.org/other']).url).toBe('https://x.org/u');
    expect(() => curlRequest(['-sS', 'x.org'])).toThrow(/URL/);
  });

  it('reads the headers from a file, never from the command line, before the caller\'s arguments', () => {
    expect(curlArgs(['-sS', 'https://x.org/'], '/tmp/dba-curl-x/headers')).toEqual(['-H', '@/tmp/dba-curl-x/headers', '-sS', 'https://x.org/']);
    expect(curlHeaderFile({ Authorization: 'DBA c', DPoP: 'p' })).toBe('Authorization: DBA c\nDPoP: p\n');
  });
});

describe('dba curl --dba-wait (STATUS B7 G9)', () => {
  it('takes --dba-wait out of curl\'s arguments and refuses options that hide the response', () => {
    expect(curlWaitOption(['-sS', 'https://x.org/'])).toEqual({ args: ['-sS', 'https://x.org/'], waitSeconds: null });
    expect(curlWaitOption(['--dba-wait', '-X', 'DELETE', 'https://x.org/'])).toEqual({ args: ['-X', 'DELETE', 'https://x.org/'], waitSeconds: 300 });
    expect(curlWaitOption(['https://x.org/', '--dba-wait=45']).waitSeconds).toBe(45);
    expect(() => curlWaitOption(['--dba-wait=soon', 'https://x.org/'])).toThrow(UsageError);
    for (const bad of [['-o', 'out'], ['--output=out'], ['-O'], ['-i'], ['--fail'], ['-sSf'], ['-D', '-'], ['-w', '%{http_code}']]) {
      expect(() => curlWaitOption(['--dba-wait', ...bad, 'https://x.org/'])).toThrow(/drop -/);
    }
    // A value that merely looks like one of them is not an option; nor is -H's header text.
    expect(curlWaitOption(['--dba-wait', '-H', '-o: x', '-d', '-i', 'https://x.org/']).args).toHaveLength(5);
    // In a short cluster, letters after one that takes a value are that value.
    expect(curlWaitOption(['--dba-wait', '-Hfoo: bar', 'https://x.org/']).args).toHaveLength(2);
    expect(() => curlWaitOption(['--dba-wait', '-sHfoo: bar', 'https://x.org/'])).not.toThrow();
  });
});
