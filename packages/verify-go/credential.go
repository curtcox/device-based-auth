package dbaverify

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Device credentials (typ "dba-device+jwt"), short-lived access tokens (typ "dba-access+jwt")
// and DPoP proofs (RFC 9449, typ "dpop+jwt"). See spec/credential.md.

const (
	CredentialTyp = "dba-device+jwt"
	AccessTyp     = "dba-access+jwt"
	ProofTyp      = "dpop+jwt"
	StatusListTyp = "statuslist+jwt"
	DefaultIssuer = "https://devicebasedauth.org"
	// ClockSkew (seconds) is allowed between the issuer's, the device's and the verifier's clocks.
	ClockSkew = 60
	// ProofMaxAge (seconds) is how old a DPoP proof may be, on top of ClockSkew.
	ProofMaxAge = 60
)

// VerificationError is a verification failure with a stable machine-readable code, the same
// codes the JavaScript library uses (invalid_format, wrong_type, unknown_kid,
// invalid_signature, wrong_issuer, invalid_claims, wrong_audience, not_yet_valid, expired,
// invalid_proof, key_mismatch, stale_proof, use_dpop_nonce, replayed_proof, revoked,
// jwks_unavailable, status_unavailable).
type VerificationError struct {
	Code    string
	Message string
}

func (e *VerificationError) Error() string {
	if e.Message == "" || e.Message == e.Code {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// HTTPStatus is the response status a relying party should send for this failure: 503 when the
// issuer could not be reached (fail closed, but tell the client to retry), else 401.
func (e *VerificationError) HTTPStatus() int {
	if e.Code == "jwks_unavailable" || e.Code == "status_unavailable" {
		return 503
	}
	return 401
}

func fail(code, message string) error { return &VerificationError{Code: code, Message: message} }

// ErrorCode returns the VerificationError code of err, or "" when err is not one.
func ErrorCode(err error) string {
	var ve *VerificationError
	if errors.As(err, &ve) {
		return ve.Code
	}
	return ""
}

var (
	subPattern  = regexp.MustCompile(`^dev_[A-Za-z0-9]{8,64}$`)
	acctPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	cidPattern  = regexp.MustCompile(`^crd_[A-Za-z0-9]{8,64}$`)
)

// ValidateCredentialPayload makes the structural checks shared by issuers (before signing) and
// verifiers (after). typ is the header typ; device credentials must carry cnf.jkt.
func ValidateCredentialPayload(payload *Object, typ string) []string {
	errs := []string{}
	str := func(k string, re *regexp.Regexp) {
		v, _ := payload.Get(k)
		s, ok := v.(string)
		if !ok || (re != nil && !re.MatchString(s)) {
			errs = append(errs, k+" is missing or malformed")
		}
	}
	str("iss", nil)
	str("sub", subPattern)
	str("acct", acctPattern)
	str("jti", nil)
	str("cid", cidPattern)
	for _, k := range []string{"iat", "nbf", "exp"} {
		if v, _ := payload.Get(k); !isSafeInteger(v) {
			errs = append(errs, k+" must be a NumericDate")
		}
	}
	aud, _ := payload.Get("aud")
	audList, ok := aud.([]any)
	badAud := !ok || len(audList) == 0
	for _, a := range audList {
		if _, isString := a.(string); !isString {
			badAud = true
		}
	}
	if badAud {
		errs = append(errs, "aud must be a list of audiences")
	}
	exp, _ := payload.Get("exp")
	nbf, _ := payload.Get("nbf")
	if e, ok := exp.(float64); ok {
		if n, ok := nbf.(float64); ok && e <= n {
			errs = append(errs, "exp must be after nbf")
		}
	}
	if ver, _ := payload.Get("ver"); !strictEqual(ver, float64(VocabularyVersion)) {
		errs = append(errs, fmt.Sprintf("ver must be %d", VocabularyVersion))
	}
	status, _ := payload.Get("status")
	statusList, _ := get(status, "status_list")
	idx, _ := get(statusList, "idx")
	uri, _ := get(statusList, "uri")
	if _, isString := uri.(string); !truthy(statusList) || !isSafeInteger(idx) || idx.(float64) < 0 || !isString {
		errs = append(errs, "status.status_list must have idx and uri")
	}
	if typ == CredentialTyp {
		cnf, _ := payload.Get("cnf")
		if jkt, _ := get(cnf, "jkt"); func() bool { _, ok := jkt.(string); return !ok }() {
			errs = append(errs, "cnf.jkt is required")
		}
	}
	grants, _ := payload.Get("grants")
	return append(errs, ValidateGrants(grants)...)
}

// Claims are the typed claims of a verified credential or access token.
type Claims struct {
	Issuer       string   `json:"iss"`
	Subject      string   `json:"sub"` // device id, dev_…
	Account      string   `json:"acct"`
	Audience     []string `json:"aud"`
	CredentialID string   `json:"cid"` // crd_…, stable across renewals
	JTI          string   `json:"jti"` // <cid>.<version>
	IssuedAt     int64    `json:"iat"`
	NotBefore    int64    `json:"nbf"`
	Expires      int64    `json:"exp"`
	JKT          string   `json:"jkt,omitempty"` // cnf.jkt; empty for access tokens
	StatusIndex  int64    `json:"status_idx"`
	StatusURI    string   `json:"status_uri"`
	Grants       []any    `json:"grants"`
	Device       *Object  `json:"device,omitempty"` // self-reported {name, kind, key_protection}
}

func claimsFrom(p *Object) Claims {
	s := func(k string) string { v, _ := p.Get(k); str, _ := v.(string); return str }
	n := func(v any) int64 { f, _ := v.(float64); return int64(f) }
	c := Claims{Issuer: s("iss"), Subject: s("sub"), Account: s("acct"), CredentialID: s("cid"), JTI: s("jti")}
	aud, _ := p.Get("aud")
	for _, a := range aud.([]any) {
		c.Audience = append(c.Audience, a.(string))
	}
	iat, _ := p.Get("iat")
	nbf, _ := p.Get("nbf")
	exp, _ := p.Get("exp")
	c.IssuedAt, c.NotBefore, c.Expires = n(iat), n(nbf), n(exp)
	cnf, _ := p.Get("cnf")
	jkt, _ := get(cnf, "jkt")
	c.JKT, _ = jkt.(string)
	status, _ := p.Get("status")
	sl, _ := get(status, "status_list")
	idx, _ := get(sl, "idx")
	uri, _ := get(sl, "uri")
	c.StatusIndex = n(idx)
	c.StatusURI, _ = uri.(string)
	grants, _ := p.Get("grants")
	c.Grants, _ = grants.([]any)
	device, _ := p.Get("device")
	c.Device, _ = device.(*Object)
	return c
}

// Credential is a verified credential or access token.
type Credential struct {
	Header  *Object // the JWS header
	Payload *Object // every claim, including unknown ones (which verifiers must ignore)
	Claims  Claims  // the known claims, typed
}

// JWKS is the issuer's JSON Web Key Set. Keys are kept as parsed JSON because a key lookup
// compares kid values with JavaScript === semantics.
type JWKS struct {
	Keys []any
}

// ParseJWKS parses a JWKS document. A missing or non-array "keys" member is an empty set.
func ParseJWKS(data []byte) (*JWKS, error) {
	v, err := ParseJSON(data)
	if err != nil {
		return nil, err
	}
	keys, _ := get(v, "keys")
	list, _ := keys.([]any)
	return &JWKS{Keys: list}, nil
}

// Find returns the key whose kid equals the given kid. As in JavaScript (k.kid === header.kid),
// an absent kid matches a key with no kid.
func (s *JWKS) Find(kid any, kidPresent bool) (any, bool) {
	if s == nil {
		return nil, false
	}
	for _, k := range s.Keys {
		o, ok := asObject(k)
		if !ok {
			continue
		}
		v, present := o.Get("kid")
		if (!present && !kidPresent) || (present && kidPresent && strictEqual(v, kid)) {
			return k, true
		}
	}
	return nil, false
}

// CredentialOptions configure VerifyCredential.
type CredentialOptions struct {
	JWKS     *JWKS
	Issuer   string // default DefaultIssuer
	Audience string // your audience name; "" skips the audience check
	Now      int64  // seconds; 0 means the current time
	Typ      string // "device" (default), "access" or "any"
}

func nowOr(now int64) int64 {
	if now == 0 {
		return time.Now().Unix()
	}
	return now
}

// VerifyCredential verifies a credential's (or access token's) signature and claims.
// Revocation is checked separately: with status lists (Verifier does this) or online.
func VerifyCredential(jws string, opts CredentialOptions) (*Credential, error) {
	issuer := opts.Issuer
	if issuer == "" {
		issuer = DefaultIssuer
	}
	now := nowOr(opts.Now)
	decoded, err := DecodeJWS(jws)
	if err != nil {
		return nil, fail("invalid_format", "Not a compact JWS")
	}
	allowed := []string{CredentialTyp}
	switch opts.Typ {
	case "any":
		allowed = []string{CredentialTyp, AccessTyp}
	case "access":
		allowed = []string{AccessTyp}
	}
	typ, _ := decoded.Header.Get("typ")
	if !contains(allowed, typ) {
		return nil, fail("wrong_type", "Expected typ "+strings.Join(allowed, " or "))
	}
	kid, kidPresent := decoded.Header.Get("kid")
	jwk, ok := opts.JWKS.Find(kid, kidPresent)
	if !ok {
		return nil, fail("unknown_kid", "Unknown signing key "+jsToString(kid))
	}
	if _, err := VerifyJWS(jws, jwk); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			return nil, fail("invalid_signature", "Signature does not verify")
		}
		// The issuer published an unusable key: an operational fault, not the client's.
		return nil, fmt.Errorf("dbaverify: issuer key %s: %w", jsToString(kid), err)
	}
	payload := decoded.Payload
	if iss, _ := payload.Get("iss"); !strictEqual(iss, issuer) {
		return nil, fail("wrong_issuer", "Issuer is not "+issuer)
	}
	if problems := ValidateCredentialPayload(payload, typ.(string)); len(problems) > 0 {
		return nil, fail("invalid_claims", strings.Join(problems, "; "))
	}
	claims := claimsFrom(payload)
	if opts.Audience != "" && !contains(claims.Audience, opts.Audience) {
		return nil, fail("wrong_audience", "Not valid for "+opts.Audience)
	}
	if now+ClockSkew < claims.NotBefore {
		return nil, fail("not_yet_valid", "Credential is not valid yet")
	}
	if now-ClockSkew >= claims.Expires {
		return nil, fail("expired", "Credential has expired")
	}
	return &Credential{Header: decoded.Header, Payload: payload, Claims: claims}, nil
}

// Htu normalizes a URL for the DPoP htu claim: scheme, host and path only (RFC 9449 §4.3).
//
// The JavaScript library uses the WHATWG URL parser, which lowercases the scheme and host,
// drops the default port, resolves dot segments and gives special schemes a "/" path. Go's
// url.Parse does none of that, so it is done here; otherwise a proof made by a browser for
// "https://Example.com:443/a/./b" would not match the same request seen by a Go server.
func Htu(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("dbaverify: invalid URL %q", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		// WHATWG serializes IPv6 hosts compressed and lowercase.
		if addr, err := netip.ParseAddr(host); err == nil {
			host = addr.String()
		}
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && !(scheme == "http" && port == "80") && !(scheme == "https" && port == "443") {
		host += ":" + port
	}
	return scheme + "://" + host + removeDotSegments(u.EscapedPath()), nil
}

func removeDotSegments(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")[1:]
	out := []string{}
	for i, seg := range segments {
		last := i == len(segments)-1
		switch strings.ToLower(seg) {
		case ".", "%2e":
			if last {
				out = append(out, "")
			}
		case "..", ".%2e", "%2e.", "%2e%2e":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, seg)
		}
	}
	return "/" + strings.Join(out, "/")
}

// Replay remembers DPoP proof ids. Check returns false when the key was already used.
type Replay interface {
	Check(key string, now int64) bool
}

// ReplayCache is a small in-memory DPoP jti replay cache, per process. Run several instances
// behind a load balancer and a proof could be replayed once against each; share a Replay
// implementation (e.g. backed by Redis) if that matters to you.
type ReplayCache struct {
	ttl  int64
	max  int
	mu   sync.Mutex
	seen map[string]*list.Element
	fifo *list.List // of replayEntry, oldest first
}

type replayEntry struct {
	key string
	exp int64
}

// NewReplayCache creates a cache. ttl 0 means ProofMaxAge*2+ClockSkew (180 s, the proof
// acceptance window); max 0 means 100,000 entries.
func NewReplayCache(ttl int64, max int) *ReplayCache {
	if ttl == 0 {
		ttl = ProofMaxAge*2 + ClockSkew
	}
	if max == 0 {
		max = 100000
	}
	return &ReplayCache{ttl: ttl, max: max, seen: map[string]*list.Element{}, fifo: list.New()}
}

// Check records key and reports whether it was new.
func (c *ReplayCache) Check(key string, now int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Entries share one TTL, so insertion order is expiry order.
	for e := c.fifo.Front(); e != nil; e = c.fifo.Front() {
		entry := e.Value.(replayEntry)
		if entry.exp > now {
			break
		}
		c.fifo.Remove(e)
		delete(c.seen, entry.key)
	}
	if _, ok := c.seen[key]; ok {
		return false
	}
	if len(c.seen) >= c.max {
		oldest := c.fifo.Front()
		c.fifo.Remove(oldest)
		delete(c.seen, oldest.Value.(replayEntry).key)
	}
	c.seen[key] = c.fifo.PushBack(replayEntry{key: key, exp: now + c.ttl})
	return true
}

// ProofOptions configure VerifyProof.
type ProofOptions struct {
	Method     string // the request method
	URL        string // the absolute request URL (query and fragment are ignored)
	Credential string // the presented credential; when set the proof's ath must match it
	JKT        string // the credential's cnf.jkt; when set the proof key must match it
	Now        int64  // seconds; 0 means the current time
	Nonce      string // when set, the proof must carry this nonce (use_dpop_nonce otherwise)
	Replay     Replay // when set, each proof jti is accepted once
}

// Proof is a verified DPoP proof.
type Proof struct {
	Payload  *Object         // every claim (jti, htm, htu, iat, ath, nonce, loc, …)
	JTI      string          // the proof's unique id
	JKT      string          // thumbprint of the key that signed it
	Location *DeviceLocation // the device-reported loc claim, nil when absent
}

// VerifyProof verifies a DPoP proof for a request.
func VerifyProof(proof string, opts ProofOptions) (*Proof, error) {
	now := nowOr(opts.Now)
	decoded, err := DecodeJWS(proof)
	if err != nil {
		return nil, fail("invalid_proof", "DPoP proof is not a compact JWS")
	}
	header, payload := decoded.Header, decoded.Payload
	typ, _ := header.Get("typ")
	alg, _ := header.Get("alg")
	jwk, _ := header.Get("jwk")
	if !strictEqual(typ, ProofTyp) || !strictEqual(alg, "ES256") || !truthy(jwk) {
		return nil, fail("invalid_proof", "DPoP proof header must have typ dpop+jwt, alg ES256 and jwk")
	}
	thumbprint, err := JWKThumbprint(jwk)
	if err != nil {
		return nil, fail("invalid_proof", "DPoP proof jwk is not a P-256 key")
	}
	if opts.JKT != "" && thumbprint != opts.JKT {
		return nil, fail("key_mismatch", "DPoP proof was not signed by the credential key")
	}
	// An unusable key (not on the curve) is the client's fault here, so it is invalid_proof.
	// (In JavaScript the WebCrypto import error escapes verifyProof instead.)
	if _, err := VerifyJWS(proof, jwk); err != nil {
		return nil, fail("invalid_proof", "DPoP proof signature does not verify")
	}
	if htm, _ := payload.Get("htm"); !strictEqual(htm, strings.ToUpper(opts.Method)) {
		return nil, fail("invalid_proof", "DPoP proof htm does not match the request method")
	}
	expected, err := Htu(opts.URL)
	if err != nil {
		return nil, err
	}
	if htu, _ := payload.Get("htu"); !strictEqual(htu, expected) {
		return nil, fail("invalid_proof", "DPoP proof htu does not match the request URL")
	}
	iat, _ := payload.Get("iat")
	if !isSafeInteger(iat) || int64(iat.(float64)) > now+ClockSkew || int64(iat.(float64)) < now-ProofMaxAge-ClockSkew {
		return nil, fail("stale_proof", "DPoP proof iat is outside the allowed window")
	}
	jtiV, _ := payload.Get("jti")
	jti, ok := jtiV.(string)
	if !ok || jsLength(jti) < 8 || jsLength(jti) > 128 {
		return nil, fail("invalid_proof", "DPoP proof jti is missing")
	}
	if opts.Credential != "" {
		if ath, _ := payload.Get("ath"); !strictEqual(ath, SHA256B64U(opts.Credential)) {
			return nil, fail("invalid_proof", "DPoP proof ath does not match the credential")
		}
	}
	if opts.Nonce != "" {
		if nonce, _ := payload.Get("nonce"); !strictEqual(nonce, opts.Nonce) {
			return nil, fail("use_dpop_nonce", "DPoP nonce required")
		}
	}
	if opts.Replay != nil && !opts.Replay.Check(thumbprint+":"+jti, now) {
		return nil, fail("replayed_proof", "DPoP proof was already used")
	}
	loc, _ := payload.Get("loc")
	return &Proof{Payload: payload, JTI: jti, JKT: thumbprint, Location: DeviceLocationFromClaim(loc)}, nil
}

// ProofParams describe a DPoP proof to create.
type ProofParams struct {
	Key        *ecdsa.PrivateKey // the device key
	Method     string
	URL        string
	Credential string          // binds the proof to this credential (ath) when set
	Nonce      string          // a verifier-issued nonce, when required
	Location   *DeviceLocation // optional device-reported location
	Now        int64           // seconds; 0 means the current time
	JTI        string          // random when empty
}

// CreateProof creates a DPoP proof for one request with the device key (for Go clients and
// tests; the private key never leaves the device).
func CreateProof(p ProofParams) (string, error) {
	jti := p.JTI
	if jti == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		jti = B64U(b)
	}
	htu, err := Htu(p.URL)
	if err != nil {
		return "", err
	}
	payload := NewObject("jti", jti, "htm", strings.ToUpper(p.Method), "htu", htu, "iat", nowOr(p.Now))
	if p.Credential != "" {
		payload.Set("ath", SHA256B64U(p.Credential))
	}
	if p.Nonce != "" {
		payload.Set("nonce", p.Nonce)
	}
	if p.Location != nil {
		payload.Set("loc", p.Location)
	}
	header := NewObject("typ", ProofTyp, "jwk", PublicJWKFromKey(&p.Key.PublicKey))
	return SignJWS(header, payload, p.Key)
}
