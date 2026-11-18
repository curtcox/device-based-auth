// A relying party (here, a site called hashbin.org) checking requests from devices, offline:
// the verifier fetches and caches devicebasedauth.org's public keys and revocation lists, and
// never calls devicebasedauth.org per request.
//
//   DBA_ORIGIN=http://localhost:8787 node docs/samples/verify-request.mjs
import { createVerifier } from '@devicebasedauth/verify';
import { enrollDevice, signedRequest } from './device.mjs';

const issuer = process.env.DBA_ORIGIN || 'https://devicebasedauth.org';

// Make one verifier per process and reuse it, so its key and status-list caches work.
const dba = createVerifier({ issuer, audience: 'hashbin.org' });

/** What a route handler does: verify, then allow or refuse with the reasons. */
async function check(label, request, action) {
  const result = await dba.verifyRequest(request, { action });
  if (result.allow) console.log(`ALLOW ${label}: ${action} by account ${result.account}, device ${result.device}`);
  else console.log(`DENY  ${label}: ${result.status} ${result.code}${result.reasons.length ? ` ${JSON.stringify(result.reasons)}` : ''}`);
  return result;
}

// A device that may publish content on hashbin.org, and nothing else. In real life it runs
// elsewhere (`dba enroll`, the browser SDK, python_device.py); here we enroll one to have
// something to verify.
const device = await enrollDevice({ origin: issuer, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], name: 'verify-request sample' });

const publish = await signedRequest(device, 'POST', 'https://hashbin.org/api/content');
await check('publish', publish, 'hashbin:content:write');
// The same request again: its proof was single-use.
await check('replayed request', publish, 'hashbin:content:write');
// An action the credential does not grant.
await check('delete', await signedRequest(device, 'DELETE', 'https://hashbin.org/api/content/abc'), 'hashbin:content:delete');
// No credential at all.
await check('anonymous', new Request('https://hashbin.org/api/content', { method: 'POST' }), 'hashbin:content:write');
