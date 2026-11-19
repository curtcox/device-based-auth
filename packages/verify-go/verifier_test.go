package dbaverify

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// Verifier tests mint fresh credentials, proofs and status lists with the TEST-ONLY keys
// published in spec/vectors/credentials.json and serve them from an injected fetcher, so
// nothing touches the network.

const (
	testNow       = 1795017610
	testStatusURI = DefaultIssuer + "/status/v1/lists/0"
	testURL       = "https://hashbin.org/api/content"
)

type fakeDoc struct {
	status int
	body   string
}

type fakeFetcher struct {
	mu       sync.Mutex
	docs     map[string]fakeDoc
	calls    map[string]int
	lastBody string
}

func (f *fakeFetcher) set(url string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.docs[url] = fakeDoc{status, body}
}

func (f *fakeFetcher) count(url string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[url]
}

func (f *fakeFetcher) Do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	url := req.URL.String()
	f.calls[url]++
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		f.lastBody = string(b)
	}
	doc, ok := f.docs[url]
	if !ok {
		doc = fakeDoc{404, `{"error":"not found"}`}
	}
	return &http.Response{StatusCode: doc.status, Body: io.NopCloser(strings.NewReader(doc.body)), Header: http.Header{}, Request: req}, nil
}

type testEnv struct {
	t       *testing.T
	signer  IssuerSigner
	device  *ecdsa.PrivateKey
	jkt     string
	fetcher *fakeFetcher
	now     int64
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	vectors := loadVectors(t, "credentials.json")
	issuerJWK, _ := vectors.Get("test_only_issuer_private_jwk")
	deviceJWK, _ := vectors.Get("test_only_device_private_jwk")
	issuerKey, err := PrivateKeyFromJWK(issuerJWK)
	if err != nil {
		t.Fatal(err)
	}
	device, err := PrivateKeyFromJWK(deviceJWK)
	if err != nil {
		t.Fatal(err)
	}
	jkt, _ := vectors.Get("device_jkt")
	env := &testEnv{t: t, signer: IssuerSigner{Kid: "test-vectors-1", Key: issuerKey}, device: device, jkt: jkt.(string),
		fetcher: &fakeFetcher{docs: map[string]fakeDoc{}, calls: map[string]int{}}, now: testNow}
	env.serveJWKS(env.signer)
	env.serveStatusList(testStatusURI, 3) // index 3 is revoked
	return env
}

func (e *testEnv) serveJWKS(signers ...IssuerSigner) {
	e.fetcher.set(DefaultIssuer+"/.well-known/jwks.json", 200, jsonStringify(NewObject("keys", JWKSFor(signers...).Keys)))
}

func (e *testEnv) serveStatusList(uri string, revoked ...int64) {
	var bits []byte
	for _, i := range revoked {
		bits = SetBit(bits, i, 1)
	}
	jwt, err := SignStatusList(StatusListParams{URI: uri, Bytes: bits, Issuer: DefaultIssuer, Now: e.now}, e.signer)
	if err != nil {
		e.t.Fatal(err)
	}
	e.fetcher.set(uri, 200, jwt)
}

// credential mints a credential (typ CredentialTyp) or access token (AccessTyp).
func (e *testEnv) credential(grants string, idx int64, typ string) string {
	e.t.Helper()
	parsed, err := ParseJSON([]byte(grants))
	if err != nil {
		e.t.Fatal(err)
	}
	payload := NewObject("iss", DefaultIssuer, "sub", "dev_GOTEST0001", "acct", "acct_go", "aud", []string{"hashbin.org"},
		"cid", "crd_GOTEST0001", "jti", "crd_GOTEST0001.1", "iat", e.now-10, "nbf", e.now-10, "exp", e.now+86400,
		"grants", parsed, "status", NewObject("status_list", NewObject("idx", idx, "uri", testStatusURI)), "ver", 1)
	if typ == CredentialTyp {
		payload.Set("cnf", NewObject("jkt", e.jkt))
	}
	jws, err := SignCredential(payload, e.signer, typ)
	if err != nil {
		e.t.Fatal(err)
	}
	return jws
}

func (e *testEnv) proof(method, url, credential string, loc *DeviceLocation) string {
	e.t.Helper()
	p, err := CreateProof(ProofParams{Key: e.device, Method: method, URL: url, Credential: credential, Now: e.now, Location: loc})
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *testEnv) verifier(mutate func(*Options)) *Verifier {
	e.t.Helper()
	opts := Options{Audience: "hashbin.org", HTTPClient: e.fetcher, Now: func() int64 { return e.now }}
	if mutate != nil {
		mutate(&opts)
	}
	v, err := NewVerifier(opts)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func deviceRequest(credential, proof string) *http.Request {
	r := httptest.NewRequest("POST", testURL+"?draft=1", nil)
	r.Header.Set("Authorization", "DBA "+credential)
	if proof != "" {
		r.Header.Set("DPoP", proof)
	}
	return r
}

const writeGrant = `[{"actions":["hashbin:content:write"]}]`

func mustDecide(t *testing.T, v *Verifier, r *http.Request, check Check) *Decision {
	t.Helper()
	d, err := v.VerifyRequest(r, check)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestVerifyRequestAllows(t *testing.T) {
	env := newTestEnv(t)
	cred := env.credential(writeGrant, 4, CredentialTyp)
	d := mustDecide(t, env.verifier(nil), deviceRequest(cred, env.proof("POST", testURL, cred, nil)), Check{Action: "hashbin:content:write"})
	if !d.Allow || d.Status != 200 || d.Code != "ok" || d.GrantIndex == nil || *d.GrantIndex != 0 {
		t.Fatalf("decision = %+v", d)
	}
	if d.Device != "dev_GOTEST0001" || d.Account != "acct_go" || d.CredentialID != "crd_GOTEST0001" || d.Kind != "device" {
		t.Errorf("identity = %s %s %s %s", d.Device, d.Account, d.CredentialID, d.Kind)
	}
}

func TestVerifyRequestDenials(t *testing.T) {
	env := newTestEnv(t)
	good := env.credential(writeGrant, 4, CredentialTyp)
	revoked := env.credential(writeGrant, 3, CredentialTyp)
	limited := env.credential(`[{"actions":["hashbin:content:write"],"limits":{"uses":{"count":3,"per":"day"}}}]`, 4, CredentialTyp)
	cases := []struct {
		name    string
		request *http.Request
		action  string
		status  int
		code    string
		reasons [][]string
	}{
		{"no credential", httptest.NewRequest("POST", testURL, nil), "hashbin:content:write", 401, "credential_required", [][]string{}},
		{"no proof", deviceRequest(good, ""), "hashbin:content:write", 401, "proof_required", [][]string{}},
		{"garbage", deviceRequest("not-a-jws", "x"), "hashbin:content:write", 401, "invalid_format", [][]string{}},
		{"revoked", deviceRequest(revoked, env.proof("POST", testURL, revoked, nil)), "hashbin:content:write", 401, "revoked", [][]string{}},
		{"proof for another URL", deviceRequest(good, env.proof("POST", "https://hashbin.org/api/other", good, nil)), "hashbin:content:write", 401, "invalid_proof", [][]string{}},
		{"forbidden", deviceRequest(good, env.proof("POST", testURL, good, nil)), "hashbin:uploads:read", 403, "forbidden", [][]string{{"action_not_granted"}}},
		{"online only", deviceRequest(limited, env.proof("POST", testURL, limited, nil)), "hashbin:content:write", 403, "online_required", [][]string{{"online_required"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := mustDecide(t, env.verifier(nil), c.request, Check{Action: c.action})
			if d.Allow || d.Status != c.status || d.Code != c.code || !reflect.DeepEqual(d.Reasons, c.reasons) {
				t.Errorf("decision = allow %v status %d code %q reasons %q message %q", d.Allow, d.Status, d.Code, d.Reasons, d.Message)
			}
		})
	}
}

func TestProofReplayIsRejected(t *testing.T) {
	env := newTestEnv(t)
	v := env.verifier(nil)
	cred := env.credential(writeGrant, 4, CredentialTyp)
	proof := env.proof("POST", testURL, cred, nil)
	if d := mustDecide(t, v, deviceRequest(cred, proof), Check{Action: "hashbin:content:write"}); !d.Allow {
		t.Fatalf("first use: %+v", d)
	}
	if d := mustDecide(t, v, deviceRequest(cred, proof), Check{Action: "hashbin:content:write"}); d.Code != "replayed_proof" || d.Status != 401 {
		t.Fatalf("replay: %+v", d)
	}
}

func TestCachingAndBackoff(t *testing.T) {
	env := newTestEnv(t)
	v := env.verifier(nil)
	cred := env.credential(writeGrant, 4, CredentialTyp)
	jwksURL := DefaultIssuer + "/.well-known/jwks.json"
	decide := func() *Decision {
		return mustDecide(t, v, deviceRequest(cred, env.proof("POST", testURL, cred, nil)), Check{Action: "hashbin:content:write"})
	}
	decide()
	decide()
	if env.fetcher.count(jwksURL) != 1 || env.fetcher.count(testStatusURI) != 1 {
		t.Fatalf("fetches: jwks %d status %d, want 1 and 1", env.fetcher.count(jwksURL), env.fetcher.count(testStatusURI))
	}
	// The status list says ttl 60: refetch after that, but keep the JWKS (1 h).
	env.now += 61
	decide()
	if env.fetcher.count(jwksURL) != 1 || env.fetcher.count(testStatusURI) != 2 {
		t.Fatalf("after ttl: jwks %d status %d, want 1 and 2", env.fetcher.count(jwksURL), env.fetcher.count(testStatusURI))
	}
	// Status list unreachable: fail closed with 503, then back off for 30 s.
	env.now += 61
	env.fetcher.set(testStatusURI, 500, "down")
	if d := decide(); d.Code != "status_unavailable" || d.Status != 503 {
		t.Fatalf("status down: %+v", d)
	}
	decide()
	if env.fetcher.count(testStatusURI) != 3 {
		t.Fatalf("status fetched %d times during backoff, want 3", env.fetcher.count(testStatusURI))
	}
	env.serveStatusList(testStatusURI, 3)
	env.now += 31
	if d := decide(); !d.Allow {
		t.Fatalf("after recovery: %+v", d)
	}
}

func TestJWKSUnavailable(t *testing.T) {
	env := newTestEnv(t)
	env.fetcher.set(DefaultIssuer+"/.well-known/jwks.json", 502, "bad gateway")
	v := env.verifier(nil)
	cred := env.credential(writeGrant, 4, CredentialTyp)
	d := mustDecide(t, v, deviceRequest(cred, env.proof("POST", testURL, cred, nil)), Check{Action: "hashbin:content:write"})
	if d.Code != "jwks_unavailable" || d.Status != 503 || d.Message != "JWKS fetch failed (502)" {
		t.Fatalf("decision = %+v", d)
	}
}

func TestKeyRotationRefetchesJWKS(t *testing.T) {
	env := newTestEnv(t)
	v := env.verifier(nil)
	old := env.credential(writeGrant, 4, CredentialTyp)
	if d := mustDecide(t, v, deviceRequest(old, env.proof("POST", testURL, old, nil)), Check{Action: "hashbin:content:write"}); !d.Allow {
		t.Fatalf("old key: %+v", d)
	}
	newKey, _ := GenerateKey()
	previous := env.signer
	env.signer = IssuerSigner{Kid: "test-vectors-2", Key: newKey}
	env.serveJWKS(previous, env.signer)
	env.serveStatusList(testStatusURI, 3)
	cred := env.credential(writeGrant, 4, CredentialTyp)
	// Within the cooldown an unknown kid costs no fetch (anyone can send a made-up kid).
	if d := mustDecide(t, v, deviceRequest(cred, env.proof("POST", testURL, cred, nil)), Check{Action: "hashbin:content:write"}); d.Code != "unknown_kid" {
		t.Fatalf("inside cooldown: %+v", d)
	}
	if n := env.fetcher.count(DefaultIssuer + "/.well-known/jwks.json"); n != 1 {
		t.Errorf("jwks fetched %d times inside the cooldown, want 1", n)
	}
	env.now += 30
	if d := mustDecide(t, v, deviceRequest(cred, env.proof("POST", testURL, cred, nil)), Check{Action: "hashbin:content:write"}); !d.Allow {
		t.Fatalf("new key: %+v", d)
	}
	if n := env.fetcher.count(DefaultIssuer + "/.well-known/jwks.json"); n != 2 {
		t.Errorf("jwks fetched %d times, want 2", n)
	}
}

func TestStatusListMustMatchURI(t *testing.T) {
	env := newTestEnv(t)
	jwt, _ := SignStatusList(StatusListParams{URI: DefaultIssuer + "/status/v1/lists/9", Issuer: DefaultIssuer, Now: env.now}, env.signer)
	env.fetcher.set(testStatusURI, 200, jwt) // a valid list, but for another URI
	cred := env.credential(writeGrant, 4, CredentialTyp)
	d := mustDecide(t, env.verifier(nil), deviceRequest(cred, env.proof("POST", testURL, cred, nil)), Check{Action: "hashbin:content:write"})
	if d.Code != "status_unavailable" {
		t.Fatalf("decision = %+v", d)
	}
}

func TestStaleStatusListCannotUndoRevocation(t *testing.T) {
	env := newTestEnv(t)
	v := env.verifier(nil)
	cred := env.credential(writeGrant, 3, CredentialTyp) // index 3 is revoked in the served list
	decide := func() *Decision {
		return mustDecide(t, v, deviceRequest(cred, env.proof("POST", testURL, cred, nil)), Check{Action: "hashbin:content:write"})
	}
	if d := decide(); d.Code != "revoked" {
		t.Fatalf("first: %+v", d)
	}
	// A CDN edge still serving the list from before the revocation cannot undo it.
	env.serveStatusList(testStatusURI)
	env.now += 61
	if d := decide(); d.Code != "revoked" || env.fetcher.count(testStatusURI) != 2 {
		t.Fatalf("stale list: %+v (fetches %d)", d, env.fetcher.count(testStatusURI))
	}
}

func TestStatusListWithoutExpIsRefused(t *testing.T) {
	env := newTestEnv(t)
	payload := NewObject("iss", DefaultIssuer, "sub", testStatusURI, "iat", float64(env.now), "ttl", float64(60), "status_list", EncodeStatusList(nil))
	jwt, err := SignJWS(NewObject("typ", StatusListTyp, "kid", env.signer.Kid), payload, env.signer.Key)
	if err != nil {
		t.Fatal(err)
	}
	env.fetcher.set(testStatusURI, 200, jwt)
	cred := env.credential(writeGrant, 4, CredentialTyp)
	if d := mustDecide(t, env.verifier(nil), deviceRequest(cred, env.proof("POST", testURL, cred, nil)), Check{Action: "hashbin:content:write"}); d.Code != "status_unavailable" {
		t.Fatalf("decision = %+v", d)
	}
}

func TestAccessTokens(t *testing.T) {
	env := newTestEnv(t)
	token := env.credential(writeGrant, 4, AccessTyp)
	request := func() *http.Request {
		r := httptest.NewRequest("GET", testURL, nil)
		r.Header.Set("Authorization", "bearer "+token)
		return r
	}
	if d := mustDecide(t, env.verifier(nil), request(), Check{Action: "hashbin:content:write"}); !d.Allow || d.Kind != "access" {
		t.Fatalf("access token: %+v", d)
	}
	d := mustDecide(t, env.verifier(func(o *Options) { o.RejectAccessTokens = true }), request(), Check{Action: "hashbin:content:write"})
	if d.Code != "access_tokens_not_accepted" {
		t.Fatalf("refused: %+v", d)
	}
	// Other bearer tokens belong to the site.
	r := httptest.NewRequest("GET", testURL, nil)
	r.Header.Set("Authorization", "Bearer sk_live_123")
	if CredentialFromRequest(r) != nil {
		t.Error("claimed a foreign bearer token")
	}
}

func TestPublicOriginBehindProxy(t *testing.T) {
	env := newTestEnv(t)
	cred := env.credential(writeGrant, 4, CredentialTyp)
	r := httptest.NewRequest("POST", "/api/content", nil) // as seen behind a TLS-terminating proxy
	r.Host = "internal:8080"
	r.Header.Set("Authorization", "DBA "+cred)
	r.Header.Set("DPoP", env.proof("POST", testURL, cred, nil))
	d := mustDecide(t, env.verifier(func(o *Options) { o.PublicOrigin = "https://hashbin.org" }), r, Check{Action: "hashbin:content:write"})
	if !d.Allow {
		t.Fatalf("decision = %+v", d)
	}
}

func TestLocationGrants(t *testing.T) {
	env := newTestEnv(t)
	area := env.credential(`[{"actions":["hashbin:content:write"],"where":{"source":"device","areas":[{"lat":38.627,"lon":-90.199,"radius_m":50000}]}}]`, 4, CredentialTyp)
	lat, lon, acc, ts := 38.63, -90.2, 100.0, float64(env.now)
	inside := &DeviceLocation{Lat: &lat, Lon: &lon, AccM: &acc, T: &ts}
	v := env.verifier(nil)
	if d := mustDecide(t, v, deviceRequest(area, env.proof("POST", testURL, area, inside)), Check{Action: "hashbin:content:write"}); !d.Allow {
		t.Fatalf("device location inside: %+v", d)
	}
	if d := mustDecide(t, v, deviceRequest(area, env.proof("POST", testURL, area, nil)), Check{Action: "hashbin:content:write"}); d.Allow || d.Reasons[0][0] != "location_unavailable:device" {
		t.Fatalf("no device location: %+v", d)
	}

	network := env.credential(`[{"actions":["hashbin:content:write"],"where":{"source":"network","countries":["US"],"networks":["203.0.113.0/24"]}}]`, 4, CredentialTyp)
	request := func() *http.Request {
		r := deviceRequest(network, env.proof("POST", testURL, network, nil))
		r.Header.Set("CF-Connecting-IP", "203.0.113.9")
		r.Header.Set("CF-IPCountry", "US")
		return r
	}
	// By default no network location is trusted, so network grants deny.
	if d := mustDecide(t, v, request(), Check{Action: "hashbin:content:write"}); d.Allow || d.Reasons[0][0] != "location_unavailable:network" {
		t.Fatalf("default network location: %+v", d)
	}
	cf := env.verifier(func(o *Options) { o.NetworkLocation = CloudflareLocation })
	if d := mustDecide(t, cf, request(), Check{Action: "hashbin:content:write"}); !d.Allow {
		t.Fatalf("behind Cloudflare: %+v", d)
	}
}

func TestVerifierMiddleware(t *testing.T) {
	env := newTestEnv(t)
	v := env.verifier(nil)
	handler := v.Middleware(func(r *http.Request) Check {
		return Check{Action: "hashbin:content:write", Resource: r.URL.Query().Get("doc")}
	})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "hello "+DecisionFromContext(r.Context()).Device)
		}))
	cred := env.credential(`[{"actions":["hashbin:content:write"],"resources":["doc-*"]}]`, 4, CredentialTyp)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, deviceRequest(cred, env.proof("POST", testURL, cred, nil)))
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != 403 || body["code"] != "forbidden" || body["error"] != "forbidden" {
		t.Fatalf("no resource: %d %s", w.Code, w.Body)
	}

	w = httptest.NewRecorder()
	r := httptest.NewRequest("POST", testURL+"?doc=doc-1", nil)
	r.Header.Set("Authorization", "DBA "+cred)
	r.Header.Set("DPoP", env.proof("POST", testURL, cred, nil))
	handler.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "hello dev_GOTEST0001" {
		t.Fatalf("allowed: %d %s", w.Code, w.Body)
	}
}

func TestSiteAuth(t *testing.T) {
	env := newTestEnv(t)
	site, err := NewSiteAuth(SiteOptions{
		Options:   Options{Audience: "hashbin.org", HTTPClient: env.fetcher, Now: func() int64 { return env.now }},
		Namespace: "hashbin",
		Scopes:    []string{"content:write", "uploads:read"},
		LinkedUser: func(_ context.Context, account string, _ LinkInfo) (string, error) {
			if account == "acct_go" {
				return "user_42", nil
			}
			return "", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cred := env.credential(`[{"actions":["hashbin:content:write","hashbin:session"],"limits":{"spend_usd_per_month":5}},{"actions":["hashbin:uploads:read"],"resources":["pub/*"],"limits":{"spend_usd_per_month":2}},{"actions":["cronly:*"],"limits":{"spend_usd_per_month":1}}]`, 4, CredentialTyp)

	res, err := site.Authenticate(deviceRequest(cred, env.proof("POST", testURL, cred, nil)))
	if err != nil || res == nil || !res.OK {
		t.Fatalf("authenticate: %+v %v", res, err)
	}
	// uploads:read is resource-scoped, so it is not a blanket scope; the cronly cap is cronly's.
	if res.UserID != "user_42" || !res.Session || !reflect.DeepEqual(res.Scopes, []string{"content:write"}) || *res.Caveats.SpendUSDPerMonth != 2 {
		t.Fatalf("result = %+v (cap %v)", res, *res.Caveats.SpendUSDPerMonth)
	}
	if !site.Allows(res, "uploads:read", "pub/a.png") || site.Allows(res, "uploads:read", "private/a.png") {
		t.Error("Allows did not honour resources")
	}

	if res, err := site.Authenticate(httptest.NewRequest("GET", testURL, nil)); res != nil || err != nil {
		t.Errorf("no credential: %+v %v", res, err)
	}

	passthrough := false
	handler := site.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passthrough = SiteResultFromContext(r.Context()) == nil
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", testURL, nil))
	if !passthrough {
		t.Error("middleware did not pass a request without a credential through")
	}
}

func TestVerifyOnline(t *testing.T) {
	env := newTestEnv(t)
	env.fetcher.set(DefaultIssuer+"/api/v1/authorize", 200, `{"allow":true,"code":"ok","grant_index":0,"reasons":[],"per_grant_reasons":[[]],"caveats":{},"device_id":"dev_GOTEST0001","account":"acct_go","cid":"crd_GOTEST0001","expires_in":30,"cost_microdollars":100}`)
	v := env.verifier(func(o *Options) { o.OnlineAPIKey = "test-key" })
	cred := env.credential(writeGrant, 4, CredentialTyp)
	d, err := v.VerifyOnline(deviceRequest(cred, env.proof("POST", testURL, cred, nil)), Check{Action: "hashbin:content:write"})
	if err != nil || !d.Allow || d.Status != 200 || d.ExpiresIn != 30 || d.CredentialID != "crd_GOTEST0001" {
		t.Fatalf("online: %+v %v", d, err)
	}
	var sent map[string]any
	_ = json.Unmarshal([]byte(env.fetcher.lastBody), &sent)
	if sent["audience"] != "hashbin.org" || sent["action"] != "hashbin:content:write" || sent["request"].(map[string]any)["url"] != testURL+"?draft=1" {
		t.Errorf("sent %s", env.fetcher.lastBody)
	}
	env.fetcher.set(DefaultIssuer+"/api/v1/authorize", 402, `{"error":"Insufficient balance","code":"insufficient_balance"}`)
	d, err = v.VerifyOnline(deviceRequest(cred, env.proof("POST", testURL, cred, nil)), Check{Action: "hashbin:content:write"})
	if err != nil || d.Allow || d.Status != 503 || d.Code != "insufficient_balance" || d.Message != "Insufficient balance" {
		t.Fatalf("402: %+v %v", d, err)
	}
}

func TestReplayCache(t *testing.T) {
	c := NewReplayCache(10, 2)
	if !c.Check("a", 100) || c.Check("a", 105) {
		t.Fatal("a should be new once")
	}
	if !c.Check("a", 110) {
		t.Fatal("a should expire after ttl")
	}
	c.Check("b", 111)
	c.Check("c", 112) // evicts the oldest (a) at max size
	if !c.Check("a", 113) {
		t.Fatal("a should have been evicted")
	}
}

func TestGetBitDoesNotWrap(t *testing.T) {
	bits := SetBit(nil, 3, 1)
	if GetBit(bits, 3) != 1 || GetBit(bits, 4) != 0 || GetBit(bits, 1000) != 0 {
		t.Fatal("basic bits")
	}
	// Credentials may only carry idx <= 2^31-1; past the list end every bit reads 0.
	if GetBit(bits, 1<<32+3) != 0 || GetBit(bits, 1<<31) != 0 || GetBit(bits, -1) != 0 {
		t.Fatal("large or negative indexes must read 0")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("SetBit past MaxStatusIndex must panic")
		}
	}()
	SetBit(nil, MaxStatusIndex+1, 1)
}

func TestVerifyCredentialTypes(t *testing.T) {
	env := newTestEnv(t)
	jwks := JWKSFor(env.signer)
	access := env.credential(writeGrant, 4, AccessTyp)
	if _, err := VerifyCredential(access, CredentialOptions{JWKS: jwks, Now: env.now}); ErrorCode(err) != "wrong_type" {
		t.Errorf("access token as device: %v", err)
	}
	if _, err := VerifyCredential(access, CredentialOptions{JWKS: jwks, Now: env.now, Typ: "any", Audience: "hashbin.org"}); err != nil {
		t.Errorf("access token as any: %v", err)
	}
	if _, err := VerifyCredential(access, CredentialOptions{JWKS: &JWKS{}, Now: env.now, Typ: "access"}); ErrorCode(err) != "unknown_kid" {
		t.Errorf("empty JWKS: %v", err)
	}
	if _, err := VerifyCredential(access, CredentialOptions{JWKS: jwks, Now: env.now, Typ: "access", Issuer: "https://example.com"}); ErrorCode(err) != "wrong_issuer" {
		t.Errorf("other issuer: %v", err)
	}
	var ve *VerificationError
	_, err := VerifyCredential("x.y", CredentialOptions{JWKS: jwks})
	if !errorsAs(err, &ve) || ve.Code != "invalid_format" || ve.HTTPStatus() != 401 {
		t.Errorf("garbage: %v", err)
	}
}

func errorsAs(err error, target **VerificationError) bool {
	v, ok := err.(*VerificationError)
	*target = v
	return ok
}
