// A Cloudflare Worker for a site called hashbin.org that lets enrolled devices publish content.
// Every request to a guarded route must carry a devicebasedauth.org credential and DPoP proof
// whose grants allow the route's action. Configure with vars:
//   DBA_ISSUER   = "https://devicebasedauth.org"  (default)
//   DBA_AUDIENCE = "hashbin.org"                  (default)
import { createVerifier } from '@devicebasedauth/verify';

// Module scope: the verifier, its key and status-list caches, and its proof-replay cache live
// as long as the isolate, so most requests verify without any fetch.
let verifier;

const ROUTES = [
  { method: 'POST', pattern: /^\/api\/content$/, action: 'hashbin:content:write', handle: () => ({ published: true }) },
  { method: 'DELETE', pattern: /^\/api\/content\/([^/]+)$/, action: 'hashbin:content:delete', handle: ([, id]) => ({ deleted: id }) }
];

export default {
  async fetch(request, env = {}) {
    verifier ??= createVerifier({ issuer: env.DBA_ISSUER || 'https://devicebasedauth.org', audience: env.DBA_AUDIENCE || 'hashbin.org' });
    const { pathname } = new URL(request.url);
    for (const route of ROUTES) {
      const match = request.method === route.method && pathname.match(route.pattern);
      if (!match) continue;
      // The resource lets grants limit a device to some paths ("resources": ["/api/content/abc*"]).
      const result = await verifier.verifyRequest(request, { action: route.action, resource: pathname });
      if (!result.allow) {
        const headers = result.status === 401 ? { 'WWW-Authenticate': 'DPoP algs="ES256"' } : {};
        return Response.json({ error: 'Not allowed', code: result.code, reasons: result.reasons }, { status: result.status, headers });
      }
      // result.account is the devicebasedauth.org account: map it to your own user.
      // result.caveats lists limits you enforce yourself, such as a monthly spending cap.
      return Response.json({ ...route.handle(match), account: result.account, device: result.device, caveats: result.caveats });
    }
    return Response.json({ error: 'Not found', code: 'not_found' }, { status: 404 });
  }
};
