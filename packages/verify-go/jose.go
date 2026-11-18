package dbaverify

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"regexp"
	"strings"
)

// Minimal JOSE (ES256 only). DBA has exactly one algorithm, so there is no algorithm
// negotiation to get wrong: a token can never pick its own verification method.

var b64uPattern = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

// ErrInvalidSignature is returned by VerifyJWS when the input is not a well-formed ES256 JWS
// or the signature does not verify.
var ErrInvalidSignature = errors.New("dbaverify: signature does not verify")

// B64U encodes bytes as unpadded base64url.
func B64U(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// UnB64U decodes unpadded base64url. Like the JavaScript library it rejects padding and any
// character outside the base64url alphabet.
func UnB64U(s string) ([]byte, error) {
	if !b64uPattern.MatchString(s) {
		return nil, errors.New("invalid base64url")
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// SHA256B64U is the base64url SHA-256 of a string (used for DPoP ath and PKCE).
func SHA256B64U(s string) string {
	sum := sha256.Sum256([]byte(s))
	return B64U(sum[:])
}

// PublicJWK keeps only the public members of a P-256 JWK, in a fixed order. It fails for
// anything that is not an EC P-256 key with string x and y.
func PublicJWK(jwk any) (*Object, error) {
	kty, _ := get(jwk, "kty")
	crv, _ := get(jwk, "crv")
	x, _ := get(jwk, "x")
	y, _ := get(jwk, "y")
	xs, xok := x.(string)
	ys, yok := y.(string)
	if !strictEqual(kty, "EC") || !strictEqual(crv, "P-256") || !xok || !yok {
		return nil, errors.New("expected a P-256 public JWK")
	}
	return NewObject("kty", "EC", "crv", "P-256", "x", xs, "y", ys), nil
}

// JWKThumbprint is the RFC 7638 SHA-256 thumbprint of a P-256 JWK (base64url). The required
// members are serialized in lexicographic order with no whitespace.
func JWKThumbprint(jwk any) (string, error) {
	pub, err := PublicJWK(jwk)
	if err != nil {
		return "", err
	}
	crv, _ := pub.Get("crv")
	kty, _ := pub.Get("kty")
	x, _ := pub.Get("x")
	y, _ := pub.Get("y")
	return SHA256B64U(jsonStringify(NewObject("crv", crv, "kty", kty, "x", x, "y", y))), nil
}

// PublicKeyFromJWK imports a P-256 public JWK. Like WebCrypto it requires 32-byte coordinates
// on the curve.
func PublicKeyFromJWK(jwk any) (*ecdsa.PublicKey, error) {
	pub, err := PublicJWK(jwk)
	if err != nil {
		return nil, err
	}
	xv, _ := pub.Get("x")
	yv, _ := pub.Get("y")
	x, errX := UnB64U(xv.(string))
	y, errY := UnB64U(yv.(string))
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("malformed P-256 JWK coordinates")
	}
	// crypto/ecdh rejects points that are not on the curve (and the point at infinity).
	if _, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...)); err != nil {
		return nil, errors.New("P-256 JWK is not a point on the curve")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}

// PrivateKeyFromJWK imports a P-256 private JWK (with d). Used by devices and tests.
func PrivateKeyFromJWK(jwk any) (*ecdsa.PrivateKey, error) {
	pub, err := PublicKeyFromJWK(jwk)
	if err != nil {
		return nil, err
	}
	dv, _ := get(jwk, "d")
	ds, ok := dv.(string)
	if !ok {
		return nil, errors.New("private JWK needs d")
	}
	d, err := UnB64U(ds)
	if err != nil || len(d) != 32 {
		return nil, errors.New("malformed private JWK d")
	}
	priv, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		return nil, errors.New("malformed private JWK d")
	}
	if !priv.PublicKey().Equal(mustECDH(pub)) {
		return nil, errors.New("private JWK d does not match x and y")
	}
	return &ecdsa.PrivateKey{PublicKey: *pub, D: new(big.Int).SetBytes(d)}, nil
}

func mustECDH(pub *ecdsa.PublicKey) *ecdh.PublicKey {
	k, err := pub.ECDH()
	if err != nil {
		return nil
	}
	return k
}

// PublicJWKFromKey exports an ECDSA P-256 public key as a JWK.
func PublicJWKFromKey(key *ecdsa.PublicKey) *Object {
	x := make([]byte, 32)
	y := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	return NewObject("kty", "EC", "crv", "P-256", "x", B64U(x), "y", B64U(y))
}

// GenerateKey creates a P-256 device key.
func GenerateKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// DecodedJWS is a split and decoded compact JWS. Nothing in it is trusted until VerifyJWS
// (or a function built on it) succeeds.
type DecodedJWS struct {
	Header       *Object
	Payload      *Object
	Signature    []byte
	SigningInput string
}

var errInvalidFormat = errors.New("invalid_format")

// DecodeJWS splits and decodes a compact JWS without verifying it. Use it to display a
// credential; never act on what it says until it verifies.
func DecodeJWS(jws string) (*DecodedJWS, error) {
	// The JavaScript limit counts UTF-16 units; any non-ASCII input fails base64url anyway.
	if jsLength(jws) > 65536 {
		return nil, errInvalidFormat
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, errInvalidFormat
	}
	header, err := decodeSegment(parts[0])
	if err != nil {
		return nil, errInvalidFormat
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, errInvalidFormat
	}
	signature, err := UnB64U(parts[2])
	if err != nil {
		return nil, errInvalidFormat
	}
	h, ok := header.(*Object)
	if !ok {
		// JavaScript accepts an array header (typeof [] is "object"); it has no members.
		if _, isArray := header.([]any); !isArray {
			return nil, errInvalidFormat
		}
		h = NewObject()
	}
	p, ok := payload.(*Object)
	if !ok {
		return nil, errInvalidFormat
	}
	return &DecodedJWS{Header: h, Payload: p, Signature: signature, SigningInput: parts[0] + "." + parts[1]}, nil
}

func decodeSegment(s string) (any, error) {
	raw, err := UnB64U(s)
	if err != nil {
		return nil, err
	}
	return ParseJSON(raw)
}

// VerifyJWS verifies a compact ES256 JWS against a public JWK. It returns ErrInvalidSignature
// when the token is malformed, is not ES256, or the signature does not verify, and a different
// error when the key itself is unusable.
func VerifyJWS(jws string, jwk any) (*DecodedJWS, error) {
	decoded, err := DecodeJWS(jws)
	if err != nil {
		return nil, ErrInvalidSignature
	}
	if alg, _ := decoded.Header.Get("alg"); !strictEqual(alg, "ES256") || len(decoded.Signature) != 64 {
		return nil, ErrInvalidSignature
	}
	pub, err := PublicKeyFromJWK(jwk)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(decoded.SigningInput))
	// JOSE signatures are raw r || s (32 bytes each), not ASN.1 DER.
	r := new(big.Int).SetBytes(decoded.Signature[:32])
	s := new(big.Int).SetBytes(decoded.Signature[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, ErrInvalidSignature
	}
	return decoded, nil
}

// SignJWS signs a compact JWS with ES256. alg is always forced to ES256. header and payload
// may be *Object, map[string]any or any JSON-marshalable value.
func SignJWS(header, payload any, key *ecdsa.PrivateKey) (string, error) {
	h, ok := asObject(header)
	if !ok {
		h = NewObject()
	}
	copied := NewObject()
	for _, k := range h.Keys() {
		v, _ := h.Get(k)
		copied.Set(k, v)
	}
	copied.Set("alg", "ES256")
	input := B64U([]byte(jsonStringify(copied))) + "." + B64U([]byte(jsonStringify(payload)))
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + B64U(sig), nil
}
