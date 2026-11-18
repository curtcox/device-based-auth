import { it, expect } from 'vitest';
import { csvField, credentialsCsv, credentialsJson } from '../frontend/js/export.js';

const item = {
  cid: 'crd_A', version: 2, state: 'revoked', device_id: 'dev_A', device: { name: '=HYPERLINK("x"), "Bob"', kind: 'cli', key_protection: 'software' },
  aud: ['hashbin.org', 'cronly.org'], grants: [{ actions: ['hashbin:content:write'] }, { actions: ['cronly:run', 'hashbin:content:write'] }],
  iat: 1795017600, exp: 1795104000, revoked_at: 1795020000000, revoked_reason: 'lost\nlaptop', jkt: 'abc'
};

it('quotes fields that need it and defuses spreadsheet formulas', () => {
  expect(csvField('plain')).toBe('plain');
  expect(csvField('a,b')).toBe('"a,b"');
  expect(csvField('say "hi"')).toBe('"say ""hi"""');
  expect(csvField('-1+2')).toBe("'-1+2");
  expect(csvField('@SUM(A1)')).toBe("'@SUM(A1)");
  expect(csvField(undefined)).toBe('');
});

it('writes one row per credential with readable times and actions', () => {
  const [header, row, end] = credentialsCsv([item]).split('\r\n');
  expect(header).toBe('cid,version,state,device_id,device_name,device_kind,key_protection,audiences,actions,grants_json,issued_at,expires_at,revoked_at,revoked_reason,parent_cid,key_thumbprint');
  expect(row).toContain(',"\'=HYPERLINK(""x""), ""Bob""",');
  expect(row).toContain(',hashbin.org cronly.org,hashbin:content:write cronly:run,');
  expect(row).toContain(',2026-11-18T16:00:00.000Z,2026-11-19T16:00:00.000Z,2026-11-18T16:40:00.000Z,');
  expect(end).toBe('');
  expect(credentialsCsv([item])).toContain('"lost\nlaptop"');
});

it('wraps JSON exports with their account, filter and count', () => {
  const parsed = JSON.parse(credentialsJson([item], { account: 'alice', filter: { status: 'revoked' }, now: 0 }));
  expect(parsed).toEqual({ exported_at: '1970-01-01T00:00:00.000Z', account: 'alice', filter: { status: 'revoked' }, count: 1, items: [item] });
});
