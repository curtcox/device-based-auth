# dbaverify — devicebasedauth.org credentials in Go

Verify [devicebasedauth.org](https://devicebasedauth.org) device credentials, DPoP proofs and
revocation, and evaluate their grants, with **only the Go standard library** (Go 1.24+).

This is a port of the JavaScript reference library
[`@devicebasedauth/verify`](../verify/src) and follows [`spec/credential.md`](../../spec/credential.md)
and [`spec/evaluation.md`](../../spec/evaluation.md). Its tests run every conformance vector in
[`spec/vectors`](../../spec/vectors), plus extra edge cases recorded from the JavaScript
implementation (`testdata/crosscheck.json`), so both libraries make the same decisions with the
same reason codes.

```sh
go get github.com/curtcox/device-based-auth/packages/verify-go
```

## Protect an HTTP handler

`Verifier` fetches and caches the issuer's JWKS (1 hour) and status lists (at most their `ttl`,
5 minutes by default), verifies the credential, its DPoP proof (with a replay cache) and
revocation, and then evaluates the grants for the action the route performs. If the issuer cannot
be reached it fails closed with `503`.

```go
verifier, err := dbaverify.NewVerifier(dbaverify.Options{
	Audience:     "hashbin.org",         // your audience name
	PublicOrigin: "https://hashbin.org", // the URL clients sign DPoP proofs for
})
if err != nil {
	log.Fatal(err)
}
// Each route names the action it performs; the credential's grants decide.
requireWrite := verifier.Middleware(func(r *http.Request) dbaverify.Check {
	return dbaverify.Check{Action: "hashbin:content:write", Resource: r.PathValue("id")}
})
mux := http.NewServeMux()
mux.Handle("PUT /api/content/{id}", requireWrite(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	decision := dbaverify.DecisionFromContext(r.Context())
	fmt.Fprintf(w, "saved by device %s of account %s\n", decision.Device, decision.Account)
})))

// A request without a credential never reaches the handler (and costs no fetch).
w := httptest.NewRecorder()
mux.ServeHTTP(w, httptest.NewRequest("PUT", "/api/content/doc-1", nil))
fmt.Println(w.Code, strings.TrimSpace(w.Body.String()))
```

The JSON error has the shape `{"error", "code", "reasons"}` with the HTTP status of the
decision: `401` (no or invalid credential or proof, revoked), `403` (`forbidden`, or
`online_required` for grants with usage limits, step-up or `require.online`, which only
`VerifyOnline` can allow) and `503` (issuer unreachable).

Without middleware, `verifier.VerifyRequest(r, check)` returns the same `*Decision`.
Sites that accept credentials as API keys alongside their own auth can use `NewSiteAuth`
(the counterpart of `createSiteAuth`): it lets requests without a DBA credential through, maps
the DBA account to a local user, and reports the scopes the credential allows right now.

Options worth knowing:

- `PublicOrigin` / `RequestURL`: DPoP proofs sign the absolute URL the client used. Behind a
  TLS-terminating proxy, tell the verifier what that URL is.
- `NetworkLocation`: where a request came from, for grants with `where`. The default is
  *unknown*, so network-restricted grants deny. Use `dbaverify.CloudflareLocation` only behind
  Cloudflare and `dbaverify.RemoteAddrLocation` only without a proxy; otherwise clients could
  choose their own location.
- `HTTPClient`: any `Do(*http.Request)`; tests inject a fake.
- `Replay`: share a replay cache between instances if a proof must never be accepted twice
  across your fleet.

## Evaluate grants directly

```go
grants, err := dbaverify.ParseJSON([]byte(`[{
	"actions": ["hashbin:content:write"],
	"when": { "tz": "America/Chicago", "windows": [{ "days": ["mon","tue","wed","thu","fri"], "from": "08:00", "to": "18:00" }] }
}]`))
if err != nil {
	log.Fatal(err)
}
// Wednesday 2026-11-18 at 10:00 and at 19:00 in Chicago.
wednesday10am := int64(1795017600)
for _, now := range []int64{wednesday10am, wednesday10am + 9*3600} {
	result := dbaverify.EvaluateGrants(grants, dbaverify.Context{Now: now, Action: "hashbin:content:write"})
	fmt.Println(result.Allow, result.Reasons)
}
```

Lower-level functions mirror the JavaScript exports: `VerifyCredential`, `VerifyProof`,
`DecodeStatusList`, `GetBit`, `EvaluateGrants`, `JWKThumbprint`, `VerifyJWS`, and, for tests and
Go clients, `CreateProof`, `SignCredential` and `SignStatusList`. Failures are
`*dbaverify.VerificationError` values with the same `Code` strings as the JavaScript library.

## Why it parses JSON its own way

Grants are untrusted JSON. A grant with an unknown member must deny with
`unknown_constraint:<path>`, `when: null` is invalid while a missing `when` is not, and reasons are
reported in JavaScript object-key order. `ParseJSON` therefore returns `*dbaverify.Object` values
that keep member order and tell absent from null, and numbers are `float64` as in JavaScript.

## Tests

```sh
cd packages/verify-go
go test ./...   # vectors, JavaScript crosscheck, verifier, README examples
go vet ./...
node testdata/crosscheck.mjs > testdata/crosscheck.json   # from packages/verify-go, after changing the JS evaluator
```
