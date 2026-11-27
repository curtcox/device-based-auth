# @devicebasedauth/verify

Read and verify [devicebasedauth.org](https://devicebasedauth.org) device credentials, DPoP proofs,
status lists and confirmations, and evaluate their grants. Zero dependencies; ES modules on
WebCrypto, so it runs in Cloudflare Workers, Node 22+, Deno, Bun and browsers. It is the reference
implementation of the [credential format](https://github.com/curtcox/device-based-auth/blob/main/spec/credential.md)
and the [evaluation rules](https://github.com/curtcox/device-based-auth/blob/main/spec/evaluation.md),
and passes every conformance vector in `spec/vectors/`.

```sh
npm install @devicebasedauth/verify
```

## Verify a request

```js
import { createVerifier } from '@devicebasedauth/verify';

// One verifier per process or isolate: it caches the issuer's keys and status lists and keeps
// the DPoP replay cache.
const dba = createVerifier({ audience: 'hashbin.org' });

const result = await dba.verifyRequest(request, { action: 'hashbin:content:write', resource: '/api/content' });
if (!result.allow) return Response.json({ code: result.code, reasons: result.reasons }, { status: result.status });
// result.account is the devicebasedauth.org account; result.caveats holds limits you enforce
// yourself, such as spend_usd_per_month.
```

`verifyRequest` checks the credential (`Authorization: DBA …` with a `DPoP` proof, or a
`Bearer` access token), revocation, any `DBA-Confirmation`, and then the grants for the action.
It fails closed: `401` for a missing or invalid credential or proof, `403` (`forbidden`, or
`online_required` for grants only devicebasedauth.org can decide), `503` when the issuer cannot
be reached. Runnable versions: [`docs/samples/verify-request.mjs`](https://github.com/curtcox/device-based-auth/blob/main/docs/samples/verify-request.mjs)
(Node) and [`docs/samples/worker-middleware.mjs`](https://github.com/curtcox/device-based-auth/blob/main/docs/samples/worker-middleware.mjs)
(a Worker that also receives revocation webhooks).

`createVerifier` options include `issuer`, `fetch`, `now`, `replay` (a shared cache such as
`durableReplayCache` over the exported `ReplayCacheDO`), `acceptAccessTokens`,
`online: { apiKey }` (enables `verifyOnline`, metered), `catalog` (your audience's gate policies),
and for `net` grants `rtt: { secret }` (round-trip timing), `dns` and `addressLists`. The JSDoc
on `createVerifier` in `src/verifier.js` describes each.

Where a request came from (for `where` and `net` grants) is read by default from Cloudflare's
`request.cf` and the `CF-Connecting-IP` header, which a client can set itself when you are not
behind Cloudflare. Elsewhere, pass `{ location: { network: { ip } } }` with the socket's peer
address in the check given to `verifyRequest`.

## Other exports

- `handleEvent(body)` on a verifier, and `verifyEvent`: signed revocation webhooks
  ([spec/events.md](https://github.com/curtcox/device-based-auth/blob/main/spec/events.md)).
- `createSiteAuth` (credentials as API keys beside a site's own auth, mapped to local users) and
  `createOidcClient` ("Sign in with devicebasedauth.org" and account linking).
- `evaluateGrants`, `validateGrants`, `describeGrant`: grants on their own.
- `verifyCredential`, `verifyProof`, `verifyConfirmation`, `createProof`, `decodeStatusList`,
  `getBit`, JOSE helpers, and issuer helpers (`signCredential`, `signStatusList`) for tests.

Ports with the same decisions and reason codes: Python (`packages/verify-python`) and Go
(`packages/verify-go`) in the [repository](https://github.com/curtcox/device-based-auth).
