# Code samples

Every file here runs in CI against a local devicebasedauth.org server (`npm run test:samples`,
see [`scripts/run-samples.mjs`](../../scripts/run-samples.mjs)), so the docs can include them
without them drifting from the API. The harness approves each enrollment as a local account owner
by reading the approval link the sample prints, exactly as a person would open it; the samples
contain no test hooks.

| Sample | Side | Shows |
|--------|------|-------|
| [`enroll-and-call.sh`](enroll-and-call.sh) | device (shell) | `dba enroll` for hashbin.org, `dba status`, `dba headers`, `dba curl`, and `dba token` for curl-only scripts. |
| [`device.mjs`](device.mjs) | device (JavaScript) | Make a non-extractable WebCrypto key, send a signed enrollment request, poll for approval, sign requests with a DPoP proof. Used by the two samples below. |
| [`verify-request.mjs`](verify-request.mjs) | relying party (Node) | `createVerifier({ issuer, audience: 'hashbin.org' })` allowing a granted action and denying a replayed proof, an action that was not granted, and a request with no credential. |
| [`worker-middleware.mjs`](worker-middleware.mjs) | relying party (Cloudflare Worker) | An `export default { fetch }` Worker that guards routes by action, returning 401/403 with reasons, and the account, device and caveats on success, and applies revocation webhooks. The harness imports it, calls `fetch` with `Request`s, and points hashbin.org's webhook at it to check a revocation arrives. |
| [`python_device.py`](python_device.py) | device (Python) | ES256 JWS by hand with `cryptography` (DER → raw `r‖s`), enrollment and polling with `requests`, then a DPoP proof with `ath` to call `GET /api/v1/whoami`. |
| [`go_verify/`](go_verify/main.go) | relying party (Go, standard library) | Verify a credential's ES256 signature against the JWKS, check issuer and expiry, print its grants. (Signature and claims only: proofs and revocation are left to the spec.) |

## Running them

All samples read `DBA_ORIGIN` (default `https://devicebasedauth.org`).

```sh
npm run test:samples                      # all of them, against a fresh local server on :8788
DBA_SAMPLES_VERBOSE=1 npm run test:samples   # also print each sample's output
DBA_SAMPLES_STRICT=1 npm run test:samples    # fail, rather than skip, when python3 or go is missing
```

To run one by hand, start the local server (`npm run dev:local`, port 8787), then for example
`DBA_ORIGIN=http://localhost:8787 node docs/samples/verify-request.mjs`, and approve the printed
link while signed in to the local site.

The Python sample needs `pip install cryptography requests`; the Go sample needs Go 1.24+.
