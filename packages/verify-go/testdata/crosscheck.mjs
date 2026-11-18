// Generates crosscheck.json: grant evaluation and htu results from the JavaScript reference
// for edge cases (key order, coercions, IP parsing, time zones) that spec/vectors does not cover.
import { evaluateGrants, htu } from '../../verify/src/index.js';
const now = 1795014000;
const A = 'hashbin:content:write';
const cases = [];
// Extra edge cases beyond spec/vectors, decided by the JavaScript reference. Regenerate with:
//   node packages/verify-go/testdata/crosscheck.mjs > packages/verify-go/testdata/crosscheck.json
const add = (name, grants, context) => cases.push({ name, grants, context, result: (({allow, grant_index, reasons, online_required, caveats}) => ({allow, grant_index, reasons, online_required, caveats}))(evaluateGrants(grants, context)) });
add('multi unknown order', [JSON.parse('{"zeta":1,"2":1,"actions":["hashbin:*"],"alpha":1,"10":1,"1":0,"when":{"q":1,"tz":"UTC"},"limits":{"x":1}}')], { now, action: A });
add('array from', [{ actions: [A], when: { tz: 'UTC', windows: [{ from: ['08:00'], to: '09:00' }] } }], { now, action: A });
add('array from yesterday', [{ actions: [A], when: { tz: 'UTC', windows: [{ from: ['08:00'], to: '23:00' }] } }], { now, action: A });
add('lowercase tz', [{ actions: [A], when: { tz: 'america/chicago', windows: [{ from: '08:00', to: '18:00' }] } }], { now, action: A });
add('offset tz', [{ actions: [A], when: { tz: '+05:30', windows: [{ from: '08:00', to: '18:00' }] } }], { now, action: A });
add('nested unknown uses', [{ actions: [A], limits: { uses: { count: 1, per: 'day', x: 1 } } }], { now, action: A, online: true });
add('null when', [{ actions: [A], when: null }], { now, action: A });
add('grant not object', [5, 'x', null, [1]], { now, action: A });
add('online required mix', [{ actions: [A], require: { online: true } }, { actions: ['x:y'] }], { now, action: A });
add('online required + other reason', [{ actions: [A], require: { online: true }, resources: ['a'] }], { now, action: A, resource: 'b' });
add('attestation level as a list', [{ actions: [A], require: { attestation: ['hardware'] } }], { now, action: A, attestation: { security_level: 'tee' } });
add('attestation level inherited name', [{ actions: [A], require: { attestation: 'toString' } }], { now, action: A, attestation: { security_level: 'tee' } });
add('attestation as array', [{ actions: [A], require: { attestation: 'hardware' } }], { now, action: A, attestation: ['tee'] });
add('attestation locked as 1', [{ actions: [A], require: { verified_boot: true } }], { now, action: A, attestation: { verified_boot: 'verified', device_locked: 1 } });
add('spend caveat', [{ actions: ['x:y'] }, { actions: [A], limits: { spend_usd_per_month: 2.5 } }], { now, action: A });
add('v4 leading zeros', [{ actions: [A], where: { source: 'network', networks: ['010.0.0.0/8'] } }], { now, action: A, location: { network: { ip: '10.1.2.3' } } });
add('v4 mapped no cross', [{ actions: [A], where: { source: 'network', networks: ['10.0.0.0/8'] } }], { now, action: A, location: { network: { ip: '::ffff:10.1.2.3' } } });
add('mapped range', [{ actions: [A], where: { source: 'network', networks: ['::ffff:10.0.0.0/104'] } }], { now, action: A, location: { network: { ip: '::ffff:10.1.2.3' } } });
add('weird v4 suffix', [{ actions: [A], where: { source: 'network', networks: ['::1ea:0/112'] } }], { now, action: A, location: { network: { ip: '::1234.1.2.3' } } });
add('ipv6 zone', [{ actions: [A], where: { source: 'network', networks: ['fe80::/10'] } }], { now, action: A, location: { network: { ip: 'fe80::1%eth0' } } });
add('prefix 0', [{ actions: [A], where: { source: 'network', networks: ['0.0.0.0/0'] } }], { now, action: A, location: { network: { ip: '1.2.3.4' } } });
add('bad prefix 33', [{ actions: [A], where: { source: 'network', networks: ['1.2.3.4/33'] } }], { now, action: A, location: { network: { ip: '1.2.3.4' } } });
add('device both stale', [{ actions: [A], where: { source: 'both', countries: ['US'] } }], { now, action: A, location: { network: { country: 'US' }, device: { t: 1 } } });
add('device bad loc string', [{ actions: [A], where: { source: 'device', areas: [{ lat: 1, lon: 1, radius_m: 100 }] } }], { now, action: A, location: { device: 'x' } });
add('window overnight sunday wrap', [{ actions: [A], when: { tz: 'Asia/Tokyo', windows: [{ days: ['sat'], from: '20:00', to: '04:00' }] } }], { now: 1795014000, action: A });
add('days empty invalid', [{ actions: [A], when: { tz: 'UTC', windows: [{ days: [], from: '01:00', to: '02:00' }] } }], { now, action: A });
add('resource long', [{ actions: [A], resources: ['é'.repeat(256)] }], { now, action: A, resource: 'é'.repeat(256) });
add('resource emoji too long', [{ actions: [A], resources: ['😀'.repeat(129)] }], { now, action: A });
add('to 24:00 from 23:00', [{ actions: [A], when: { tz: 'UTC', windows: [{ from: '23:00', to: '24:00' }] } }], { now: 1795042800 - 1, action: A });
add('not_before >= not_after', [{ actions: [A], when: { not_before: 5, not_after: 5 } }], { now, action: A });
add('where device with countries', [{ actions: [A], where: { source: 'device', countries: ['US'] } }], { now, action: A });
add('fractional count', [{ actions: [A], limits: { uses: { count: 1.5, per: 'day' } } }], { now, action: A, online: true });
add('step_up false online true', [{ actions: [A], require: { step_up: false, online: false } }], { now, action: A });
add('invalid grants', 'nope', { now, action: A });
const htus = ['https://Example.COM:443/a/./b/../c?x#y', 'http://h:80', 'http://h:8080/', 'https://[2001:DB8:0::1]/p', 'https://h/a%2fb', 'https://h/a b'].map(u => [u, htu(u)]);
console.log(JSON.stringify({ cases, htus }, null, 1));
