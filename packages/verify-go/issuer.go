package dbaverify

import (
	"crypto/ecdsa"
	"errors"
	"strings"
)

// Signing helpers for issuers and tests. Relying parties do not need these; they exist so Go
// test suites can mint credentials and status lists with the test-only keys published in
// spec/vectors/credentials.json, exactly as the JavaScript issuer.js does.

// IssuerSigner is an issuer signing key.
type IssuerSigner struct {
	Kid string
	Key *ecdsa.PrivateKey
}

// PublicJWK is the signer's public key as a JWKS entry.
func (s IssuerSigner) PublicJWK() *Object {
	jwk := PublicJWKFromKey(&s.Key.PublicKey)
	jwk.Set("kid", s.Kid)
	jwk.Set("alg", "ES256")
	jwk.Set("use", "sig")
	return jwk
}

// JWKSFor builds a JWKS from issuer signers (public halves only).
func JWKSFor(signers ...IssuerSigner) *JWKS {
	keys := make([]any, len(signers))
	for i, s := range signers {
		keys[i] = s.PublicJWK()
	}
	return &JWKS{Keys: keys}
}

// SignCredential signs a device credential (typ CredentialTyp) or access token (AccessTyp)
// after validating its payload, so an issuer can never sign something verifiers reject.
func SignCredential(payload any, signer IssuerSigner, typ string) (string, error) {
	if typ == "" {
		typ = CredentialTyp
	}
	p, ok := asObject(payload)
	if !ok {
		return "", errors.New("invalid credential: payload must be an object")
	}
	if problems := ValidateCredentialPayload(p, typ); len(problems) > 0 {
		return "", errors.New("invalid credential: " + strings.Join(problems, "; "))
	}
	return SignJWS(NewObject("typ", typ, "kid", signer.Kid), p, signer.Key)
}

// StatusListParams describe a status list token.
type StatusListParams struct {
	URI      string // the list's URL; becomes sub
	Bytes    []byte // the bit array
	Issuer   string
	TTL      int64 // seconds verifiers may cache it; default 60
	Now      int64 // seconds; 0 means the current time
	Lifetime int64 // seconds until exp; default 86400
}

// SignStatusList signs a status list token for the bytes of one list.
func SignStatusList(p StatusListParams, signer IssuerSigner) (string, error) {
	if p.TTL == 0 {
		p.TTL = 60
	}
	if p.Lifetime == 0 {
		p.Lifetime = 86400
	}
	now := nowOr(p.Now)
	payload := NewObject("iss", p.Issuer, "sub", p.URI, "iat", now, "exp", now+p.Lifetime, "ttl", p.TTL, "status_list", EncodeStatusList(p.Bytes))
	return SignJWS(NewObject("typ", StatusListTyp, "kid", signer.Kid), payload, signer.Key)
}
