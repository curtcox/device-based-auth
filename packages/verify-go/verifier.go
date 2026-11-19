package dbaverify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A caching verifier for relying parties (the Go counterpart of the JavaScript createVerifier).
// It verifies credentials offline with the issuer's JWKS and status lists, both fetched over
// HTTP and cached here, and can also ask devicebasedauth.org online.

// Fetcher performs HTTP requests. *http.Client satisfies it; tests inject a fake so that
// nothing touches the network.
type Fetcher interface {
	Do(*http.Request) (*http.Response, error)
}

// Options configure a Verifier.
type Options struct {
	// Audience is your audience name, e.g. "hashbin.org" (required).
	Audience string
	// Issuer defaults to DefaultIssuer.
	Issuer string
	// HTTPClient fetches the JWKS and status lists; default an *http.Client with a 10 s timeout.
	HTTPClient Fetcher
	// JWKSTTL (default 1 h) and StatusTTL (default 5 min) bound how long fetched documents are
	// cached. A status list is never cached longer than its own ttl claim.
	JWKSTTL, StatusTTL time.Duration
	// FailureBackoff (default 30 s): after a failed fetch, fail fast for this long instead of
	// hitting an unreachable issuer on every request.
	FailureBackoff time.Duration
	// JWKSCooldown (default 30 s) spaces out the JWKS refetches an unknown kid forces: anyone
	// can send a credential with a made-up kid, and each would otherwise cost a fetch.
	JWKSCooldown time.Duration
	// Replay is the DPoP proof replay cache; default a per-Verifier ReplayCache.
	Replay Replay
	// DisableReplay turns replay protection off (only for tests or a shared external check).
	DisableReplay bool
	// RejectAccessTokens refuses "Bearer" access tokens (audiences MAY refuse them).
	RejectAccessTokens bool
	// Now is the clock in Unix seconds; default time.Now.
	Now func() int64
	// PublicOrigin, e.g. "https://hashbin.org", is how clients reach this server. DPoP proofs
	// sign the absolute URL the client used, which a server behind a TLS-terminating proxy
	// cannot see. When empty the URL is rebuilt from the request (r.TLS and r.Host).
	PublicOrigin string
	// RequestURL overrides how the absolute request URL is determined (wins over PublicOrigin).
	RequestURL func(*http.Request) string
	// NetworkLocation says where a request came from, for grants with "where". Default: none,
	// so network-restricted grants deny. Which source is trustworthy depends on your
	// deployment: use CloudflareLocation only behind Cloudflare (anyone can send those headers
	// otherwise) and RemoteAddrLocation only when no proxy sits in front of the server.
	NetworkLocation func(*http.Request) *NetworkLocation
	// OnlineAPIKey enables VerifyOnline (POST {issuer}/api/v1/authorize, metered).
	OnlineAPIKey string
}

// Verifier verifies credentials and requests for one audience. It is safe for concurrent use.
type Verifier struct {
	opts      Options
	issuer    string
	client    Fetcher
	clock     func() int64
	jwksTTL   int64
	statusTTL int64
	backoff   int64
	cooldown  int64
	replay    Replay

	mu             sync.Mutex
	jwksCache      *jwksEntry
	jwksFailure    *fetchFailure
	statusCache    map[string]statusEntry
	statusFailures map[string]fetchFailure
}

type jwksEntry struct {
	value   *JWKS
	expires int64
	fetched int64
}

type statusEntry struct {
	bits    []byte
	expires int64
}

type fetchFailure struct {
	until   int64
	message string
}

func seconds(d, def time.Duration) int64 {
	if d == 0 {
		d = def
	}
	return int64(d / time.Second)
}

// NewVerifier creates a Verifier.
func NewVerifier(opts Options) (*Verifier, error) {
	if opts.Audience == "" {
		return nil, errors.New("dbaverify: NewVerifier needs an audience")
	}
	v := &Verifier{opts: opts, issuer: opts.Issuer, client: opts.HTTPClient, clock: opts.Now,
		jwksTTL: seconds(opts.JWKSTTL, time.Hour), statusTTL: seconds(opts.StatusTTL, 5*time.Minute), backoff: seconds(opts.FailureBackoff, 30*time.Second),
		cooldown:    seconds(opts.JWKSCooldown, 30*time.Second),
		statusCache: map[string]statusEntry{}, statusFailures: map[string]fetchFailure{}}
	if v.issuer == "" {
		v.issuer = DefaultIssuer
	}
	if v.client == nil {
		v.client = &http.Client{Timeout: 10 * time.Second}
	}
	if v.clock == nil {
		v.clock = func() int64 { return time.Now().Unix() }
	}
	if !opts.DisableReplay {
		v.replay = opts.Replay
		if v.replay == nil {
			v.replay = NewReplayCache(0, 0)
		}
	}
	return v, nil
}

// Issuer is the issuer this verifier trusts.
func (v *Verifier) Issuer() string { return v.issuer }

// Audience is the audience this verifier accepts.
func (v *Verifier) Audience() string { return v.opts.Audience }

// maxDocumentBytes bounds fetched JWKS and status list bodies.
const maxDocumentBytes = 16 << 20

func (v *Verifier) get(ctx context.Context, url, accept string) (body []byte, failure string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err.Error(), nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, strconv.Itoa(resp.StatusCode), nil
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
	if err != nil {
		return nil, err.Error(), nil
	}
	return body, "", nil
}

// JWKS returns the issuer's key set, from cache unless force is set; even forced, it refetches
// at most once per JWKSCooldown. While the issuer is unreachable it serves the last good set
// (keys rotate slowly), and fails with jwks_unavailable only when it has none.
func (v *Verifier) JWKS(ctx context.Context, force bool) (*JWKS, error) {
	now := v.clock()
	v.mu.Lock()
	if c := v.jwksCache; c != nil && ((!force && c.expires > now) || (force && c.fetched+v.cooldown > now)) {
		defer v.mu.Unlock()
		return v.jwksCache.value, nil
	}
	if v.jwksFailure != nil && v.jwksFailure.until > now {
		defer v.mu.Unlock()
		if v.jwksCache != nil {
			return v.jwksCache.value, nil
		}
		return nil, fail("jwks_unavailable", v.jwksFailure.message)
	}
	v.mu.Unlock()

	body, failure, err := v.get(ctx, v.issuer+"/.well-known/jwks.json", "")
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if failure != "" {
		v.jwksFailure = &fetchFailure{until: now + v.backoff, message: "JWKS fetch failed (" + failure + ")"}
		if v.jwksCache != nil {
			return v.jwksCache.value, nil
		}
		return nil, fail("jwks_unavailable", v.jwksFailure.message)
	}
	v.jwksFailure = nil
	jwks, err := ParseJWKS(body)
	if err != nil {
		return nil, fmt.Errorf("dbaverify: JWKS is not JSON: %w", err)
	}
	v.jwksCache = &jwksEntry{value: jwks, expires: now + v.jwksTTL, fetched: now}
	return jwks, nil
}

// unionBits is the bitwise OR of two status lists (the longer length).
func unionBits(a, b []byte) []byte {
	if len(a) < len(b) {
		a, b = b, a
	}
	out := append([]byte(nil), a...)
	for i, c := range b {
		out[i] |= c
	}
	return out
}

// statusBits returns the verified, decoded status list at uri.
func (v *Verifier) statusBits(ctx context.Context, uri string) ([]byte, error) {
	now := v.clock()
	v.mu.Lock()
	if cached, ok := v.statusCache[uri]; ok && cached.expires > now {
		v.mu.Unlock()
		return cached.bits, nil
	}
	if failed, ok := v.statusFailures[uri]; ok && failed.until > now {
		v.mu.Unlock()
		return nil, fail("status_unavailable", failed.message)
	}
	v.mu.Unlock()

	body, failure, err := v.get(ctx, uri, "application/statuslist+jwt")
	if err != nil {
		return nil, err
	}
	if failure != "" {
		message := "Status list fetch failed (" + failure + ")"
		v.mu.Lock()
		v.statusFailures[uri] = fetchFailure{until: now + v.backoff, message: message}
		v.mu.Unlock()
		return nil, fail("status_unavailable", message)
	}
	v.mu.Lock()
	delete(v.statusFailures, uri)
	v.mu.Unlock()

	jws := strings.TrimSpace(string(body))
	keys, err := v.JWKS(ctx, false)
	if err != nil {
		return nil, err
	}
	var decoded *DecodedJWS
	if header, err := DecodeJWS(jws); err == nil {
		kid, present := header.Header.Get("kid")
		if key, ok := keys.Find(kid, present); ok {
			// A key that cannot verify (bad point, wrong type) means the list cannot be trusted:
			// status_unavailable (503), as in the JS verifier, rather than an internal error.
			decoded, err = VerifyJWS(jws, key)
			if err != nil {
				decoded = nil
			}
		}
	}
	if decoded == nil {
		return nil, fail("status_unavailable", "Status list did not verify")
	}
	typ, _ := decoded.Header.Get("typ")
	sub, _ := decoded.Payload.Get("sub")
	iss, _ := decoded.Payload.Get("iss")
	if !strictEqual(typ, StatusListTyp) || !strictEqual(sub, uri) || !strictEqual(iss, v.issuer) {
		return nil, fail("status_unavailable", "Status list did not verify")
	}
	exp, _ := decoded.Payload.Get("exp")
	if !isSafeInteger(exp) {
		return nil, fail("status_unavailable", "Status list has no expiry")
	}
	if exp.(float64) < float64(now-ClockSkew) {
		return nil, fail("status_unavailable", "Status list has expired")
	}
	claim, _ := decoded.Payload.Get("status_list")
	bits, err := DecodeStatusList(claim)
	if err != nil {
		return nil, fail("status_unavailable", "Status list could not be decoded")
	}
	// The issuer never clears a bit (indexes are not reused), so every bit seen set stays set: an
	// older copy from a stale cache cannot bring a revoked credential back (spec/credential.md §7).
	v.mu.Lock()
	if previous, ok := v.statusCache[uri]; ok {
		bits = unionBits(bits, previous.bits)
	}
	v.mu.Unlock()
	ttl := v.statusTTL
	if t, _ := decoded.Payload.Get("ttl"); isSafeInteger(t) && int64(t.(float64)) < ttl {
		ttl = int64(t.(float64))
	}
	v.mu.Lock()
	v.statusCache[uri] = statusEntry{bits: bits, expires: now + ttl}
	v.mu.Unlock()
	return bits, nil
}

// IsRevoked reports whether a verified credential has been revoked. It fails with
// status_unavailable when that cannot be known, and callers must then deny (fail closed).
func (v *Verifier) IsRevoked(ctx context.Context, claims Claims) (bool, error) {
	bits, err := v.statusBits(ctx, claims.StatusURI)
	if err != nil {
		return false, err
	}
	return GetBit(bits, claims.StatusIndex) == 1, nil
}

// Verify verifies a credential's signature, claims and revocation. typ is "device" (default),
// "access" or "any".
func (v *Verifier) Verify(ctx context.Context, credential, typ string) (*Credential, error) {
	// Reject malformed input before any network fetch.
	if _, err := DecodeJWS(credential); err != nil {
		return nil, fail("invalid_format", "Not a compact JWS")
	}
	keys, err := v.JWKS(ctx, false)
	if err != nil {
		return nil, err
	}
	opts := CredentialOptions{JWKS: keys, Issuer: v.issuer, Audience: v.opts.Audience, Now: v.clock(), Typ: typ}
	result, err := VerifyCredential(credential, opts)
	if ErrorCode(err) == "unknown_kid" {
		// A new signing key may have been published since the cache was filled.
		if opts.JWKS, err = v.JWKS(ctx, true); err != nil {
			return nil, err
		}
		opts.Now = v.clock()
		result, err = VerifyCredential(credential, opts)
	}
	if err != nil {
		return nil, err
	}
	revoked, err := v.IsRevoked(ctx, result.Claims)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, fail("revoked", "Credential has been revoked")
	}
	return result, nil
}

// Presented is a credential found in request headers.
type Presented struct {
	Kind       string // "device" (Authorization: DBA, with a DPoP proof) or "access" (Bearer)
	Credential string
	Proof      string // the DPoP header; empty when absent
}

// headerValue joins repeated headers with ", " as the Fetch API's Headers.get does.
func headerValue(r *http.Request, name string) string {
	return strings.Join(r.Header.Values(name), ", ")
}

// CredentialFromRequest pulls a DBA credential and proof out of request headers, or returns
// nil when the request carries none (other bearer tokens belong to the site).
func CredentialFromRequest(r *http.Request) *Presented {
	auth := strings.TrimSpace(headerValue(r, "Authorization"))
	space := strings.Index(auth, " ")
	if space <= 0 {
		return nil
	}
	// HTTP authentication schemes are case-insensitive (RFC 9110 §11.1).
	scheme := strings.ToLower(auth[:space])
	value := strings.TrimSpace(auth[space+1:])
	switch scheme {
	case "dba":
		return &Presented{Kind: "device", Credential: value, Proof: headerValue(r, "DPoP")}
	case "bearer":
		// Only DBA access tokens are claimed here.
		segment, _, _ := strings.Cut(value, ".")
		segment = strings.NewReplacer("-", "+", "_", "/").Replace(strings.TrimRight(segment, "="))
		raw, err := base64.RawStdEncoding.DecodeString(segment)
		if err != nil {
			return nil
		}
		header, err := ParseJSON(raw)
		if err != nil {
			return nil
		}
		if typ, _ := get(header, "typ"); strictEqual(typ, AccessTyp) {
			return &Presented{Kind: "access", Credential: value}
		}
	}
	return nil
}

// requestURL is the absolute URL the client used, which DPoP proofs sign.
func (v *Verifier) requestURL(r *http.Request) string {
	if v.opts.RequestURL != nil {
		return v.opts.RequestURL(r)
	}
	if v.opts.PublicOrigin != "" {
		return strings.TrimRight(v.opts.PublicOrigin, "/") + r.URL.RequestURI()
	}
	if r.URL.IsAbs() {
		return r.URL.String()
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

// AuthResult is the outcome of authenticating a request.
type AuthResult struct {
	OK         bool
	Status     int    // HTTP status to send when !OK (401, or 503 when the issuer is unreachable)
	Code       string // "credential_required", "proof_required", "access_tokens_not_accepted" or a VerificationError code
	Message    string
	Kind       string // "device" or "access"
	Credential *Credential
	Proof      *Proof // nil for access tokens
	Token      string // the presented credential string
}

// AuthenticateRequest verifies a request's credential (and proof) without deciding an action.
// A returned error is not the client's fault (e.g. the issuer published a broken document);
// treat it as a 500.
func (v *Verifier) AuthenticateRequest(r *http.Request) (*AuthResult, error) {
	found := CredentialFromRequest(r)
	if found == nil {
		return &AuthResult{Status: 401, Code: "credential_required"}, nil
	}
	if found.Kind == "access" && v.opts.RejectAccessTokens {
		return &AuthResult{Status: 401, Code: "access_tokens_not_accepted"}, nil
	}
	result, err := v.authenticate(r, found)
	var ve *VerificationError
	if errors.As(err, &ve) {
		return &AuthResult{Status: ve.HTTPStatus(), Code: ve.Code, Message: ve.Message}, nil
	}
	return result, err
}

func (v *Verifier) authenticate(r *http.Request, found *Presented) (*AuthResult, error) {
	cred, err := v.Verify(r.Context(), found.Credential, found.Kind)
	if err != nil {
		return nil, err
	}
	var proof *Proof
	if found.Kind == "device" {
		if found.Proof == "" {
			return &AuthResult{Status: 401, Code: "proof_required"}, nil
		}
		proof, err = VerifyProof(found.Proof, ProofOptions{Method: r.Method, URL: v.requestURL(r), Credential: found.Credential, JKT: cred.Claims.JKT, Now: v.clock(), Replay: v.replay})
		if err != nil {
			return nil, err
		}
	}
	return &AuthResult{OK: true, Kind: found.Kind, Credential: cred, Proof: proof, Token: found.Credential}, nil
}

// Check is the action a request wants to perform.
type Check struct {
	Action   string
	Resource string
	// Location overrides: a nil Network uses Options.NetworkLocation(request); a nil Device
	// uses the verified proof's loc claim.
	Location Location
}

// Decision is the outcome of VerifyRequest or Decide.
type Decision struct {
	Allow          bool        `json:"allow"`
	Status         int         `json:"status"` // 200, 401, 403 or 503
	Code           string      `json:"code"`   // "ok", "forbidden", "online_required", or an authentication code
	Message        string      `json:"message,omitempty"`
	Reasons        [][]string  `json:"reasons"` // per grant
	GrantIndex     *int        `json:"grant_index"`
	Grant          any         `json:"grant"`
	Caveats        Caveats     `json:"caveats"`
	OnlineRequired bool        `json:"online_required"`
	Credential     *Credential `json:"-"`
	Proof          *Proof      `json:"-"`
	Kind           string      `json:"kind,omitempty"`
	Device         string      `json:"device,omitempty"`
	Account        string      `json:"account,omitempty"`
	CredentialID   string      `json:"credential_id,omitempty"`
}

// VerifyRequest verifies a request end to end and decides one action. A returned error is not
// the client's fault; see AuthenticateRequest.
func (v *Verifier) VerifyRequest(r *http.Request, check Check) (*Decision, error) {
	auth, err := v.AuthenticateRequest(r)
	if err != nil {
		return nil, err
	}
	if !auth.OK {
		return &Decision{Status: auth.Status, Code: auth.Code, Message: auth.Message, Reasons: [][]string{}}, nil
	}
	d := v.Decide(auth.Credential, check, r, auth.Proof)
	d.Kind = auth.Kind
	return d, nil
}

// AllowedActions returns which of these actions a verified credential allows right now
// (offline checks only).
func (v *Verifier) AllowedActions(cred *Credential, actions []string, r *http.Request, proof *Proof, location Location) []string {
	allowed := []string{}
	for _, action := range actions {
		if v.Decide(cred, Check{Action: action, Location: location}, r, proof).Allow {
			allowed = append(allowed, action)
		}
	}
	return allowed
}

// Decide evaluates the grants of an already-verified credential. r and proof may be nil.
func (v *Verifier) Decide(cred *Credential, check Check, r *http.Request, proof *Proof) *Decision {
	location := check.Location
	if location.Network == nil && r != nil && v.opts.NetworkLocation != nil {
		location.Network = v.opts.NetworkLocation(r)
	}
	if location.Device == nil && proof != nil {
		location.Device = proof.Location
	}
	grants, _ := cred.Payload.Get("grants")
	device, _ := cred.Payload.Get("device")
	attestation, _ := get(device, "attestation")
	result := EvaluateGrants(grants, Context{Now: v.clock(), Action: check.Action, Resource: check.Resource, Location: location, Attestation: attestation})
	d := &Decision{Allow: result.Allow, Status: 403, Code: "forbidden", Reasons: result.Reasons, GrantIndex: result.GrantIndex, Grant: result.Grant,
		Caveats: result.Caveats, OnlineRequired: result.OnlineRequired, Credential: cred, Proof: proof,
		Device: cred.Claims.Subject, Account: cred.Claims.Account, CredentialID: cred.Claims.CredentialID}
	switch {
	case result.Allow:
		d.Status, d.Code = 200, "ok"
	case result.OnlineRequired:
		d.Code = "online_required"
	}
	return d
}

// OnlineDecision is devicebasedauth.org's answer from POST /api/v1/authorize.
type OnlineDecision struct {
	Allow            bool            `json:"allow"`
	Status           int             `json:"status"`
	Code             string          `json:"code"`
	Message          string          `json:"message,omitempty"`
	GrantIndex       *int            `json:"grant_index"`
	Reasons          []string        `json:"reasons"`
	PerGrantReasons  [][]string      `json:"per_grant_reasons,omitempty"`
	Caveats          Caveats         `json:"caveats"`
	StepUp           json.RawMessage `json:"step_up,omitempty"` // present when owner approval is pending
	DeviceID         string          `json:"device_id,omitempty"`
	Account          string          `json:"account,omitempty"`
	CredentialID     string          `json:"cid,omitempty"`
	ExpiresIn        int64           `json:"expires_in"` // seconds an allow may be cached
	CostMicrodollars int64           `json:"cost_microdollars"`
}

// VerifyOnline asks devicebasedauth.org (metered; billed to your audience account). It is needed
// for grants with usage limits, step-up or require.online, and for instant revocation.
func (v *Verifier) VerifyOnline(r *http.Request, check Check) (*OnlineDecision, error) {
	if v.opts.OnlineAPIKey == "" {
		return nil, errors.New("dbaverify: VerifyOnline needs Options.OnlineAPIKey")
	}
	found := CredentialFromRequest(r)
	if found == nil {
		return &OnlineDecision{Status: 401, Code: "credential_required", Reasons: []string{}}, nil
	}
	network := check.Location.Network
	if network == nil && v.opts.NetworkLocation != nil {
		network = v.opts.NetworkLocation(r)
	}
	type requestInfo struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	}
	body, err := json.Marshal(struct {
		Credential string         `json:"credential"`
		Proof      string         `json:"proof,omitempty"`
		Request    requestInfo    `json:"request"`
		Audience   string         `json:"audience"`
		Action     string         `json:"action"`
		Resource   string         `json:"resource,omitempty"`
		Context    map[string]any `json:"context"`
	}{found.Credential, found.Proof, requestInfo{r.Method, v.requestURL(r)}, v.opts.Audience, check.Action, check.Resource, onlineContext(network)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, v.issuer+"/api/v1/authorize", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "ApiKey "+v.opts.OnlineAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
	if err != nil {
		return nil, err
	}
	var out struct {
		OnlineDecision
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("dbaverify: authorize response is not JSON: %w", err)
	}
	d := out.OnlineDecision
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// A 402 means the audience account ran out of credit: the site's problem, not the
		// client's, so report it as unavailable.
		status := resp.StatusCode
		if status == 402 {
			status = 503
		}
		return &OnlineDecision{Status: status, Code: d.Code, Message: out.Error, Reasons: []string{}}, nil
	}
	d.Status = 403
	if d.Allow {
		d.Status = 200
	}
	if d.Reasons == nil {
		d.Reasons = []string{}
	}
	return &d, nil
}

func onlineContext(network *NetworkLocation) map[string]any {
	if network == nil {
		return map[string]any{}
	}
	return map[string]any{"network": network}
}

// CloudflareLocation reads Cloudflare's request headers into a network location. Use it only
// when every request reaches the server through Cloudflare: anyone can send these headers
// directly. Country comes from CF-IPCountry; region and coordinates need Cloudflare's
// "Add visitor location headers" managed transform.
func CloudflareLocation(r *http.Request) *NetworkLocation {
	loc := &NetworkLocation{IP: r.Header.Get("CF-Connecting-IP"), Country: r.Header.Get("CF-IPCountry")}
	if loc.Country == "XX" || loc.Country == "T1" { // unknown, Tor
		loc.Country = ""
	}
	if code := r.Header.Get("CF-Region-Code"); loc.Country != "" && code != "" {
		loc.Region = loc.Country + "-" + code
	}
	parse := func(name string) *float64 {
		if f, err := strconv.ParseFloat(r.Header.Get(name), 64); err == nil {
			return &f
		}
		return nil
	}
	loc.Lat, loc.Lon = parse("CF-IPLatitude"), parse("CF-IPLongitude")
	if loc.Country == "" && loc.IP == "" && loc.Lat == nil {
		return nil
	}
	return loc
}

// RemoteAddrLocation uses the TCP peer address. Use it only when clients connect directly;
// behind a proxy every request would appear to come from the proxy's network.
func RemoteAddrLocation(r *http.Request) *NetworkLocation {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return nil
	}
	return &NetworkLocation{IP: host}
}

type contextKey int

const (
	decisionKey contextKey = iota
	siteResultKey
)

// DecisionFromContext returns the Decision stored by Verifier.Middleware.
func DecisionFromContext(ctx context.Context) *Decision {
	d, _ := ctx.Value(decisionKey).(*Decision)
	return d
}

// writeError writes the repository's JSON error shape, { error, code, ... }.
func writeError(w http.ResponseWriter, status int, code, message string, extra map[string]any) {
	body := map[string]any{"error": message, "code": code}
	if message == "" {
		body["error"] = code
	}
	for k, v := range extra {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Middleware returns HTTP middleware that lets a request through only when its credential
// allows the action check(r) names. Denials get a JSON error with the decision's status and
// code; the allowed Decision is available to handlers through DecisionFromContext.
func (v *Verifier) Middleware(check func(*http.Request) Check) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d, err := v.VerifyRequest(r, check(r))
			if err != nil {
				writeError(w, 500, "verifier_error", "Credential verification failed", nil)
				return
			}
			if !d.Allow {
				writeError(w, d.Status, d.Code, d.Message, map[string]any{"reasons": d.Reasons})
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), decisionKey, d)))
		})
	}
}
