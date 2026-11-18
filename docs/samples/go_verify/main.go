// Verify a devicebasedauth.org credential in Go with only the standard library: check its ES256
// signature against the issuer's JWKS, its issuer and expiry, then print its grants.
//
//	DBA_ORIGIN=http://localhost:8787 DBA_CREDENTIAL="$(cat ~/.config/dba/default/credential.jwt)" go run .
//
// A relying party must also check the DPoP proof and revocation (spec/credential.md §5); use
// @devicebasedauth/verify or follow the spec for those.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type payload struct {
	Iss    string            `json:"iss"`
	Sub    string            `json:"sub"`
	Acct   string            `json:"acct"`
	Aud    []string          `json:"aud"`
	Cid    string            `json:"cid"`
	Exp    int64             `json:"exp"`
	Nbf    int64             `json:"nbf"`
	Grants []json.RawMessage `json:"grants"`
}

const clockSkew = 60

func decodeSegment(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func fetchKeys(origin string) ([]jwk, error) {
	client := http.Client{Timeout: 10 * time.Second}
	response, err := client.Get(origin + "/.well-known/jwks.json")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch failed: %s", response.Status)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&set); err != nil {
		return nil, err
	}
	return set.Keys, nil
}

func publicKey(key jwk) (*ecdsa.PublicKey, error) {
	if key.Kty != "EC" || key.Crv != "P-256" {
		return nil, errors.New("issuer key is not P-256")
	}
	x, errX := base64.RawURLEncoding.DecodeString(key.X)
	y, errY := base64.RawURLEncoding.DecodeString(key.Y)
	if errX != nil || errY != nil {
		return nil, errors.New("issuer key is malformed")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("issuer key is not on the curve")
	}
	return pub, nil
}

// verify checks the signature and claims and returns the payload.
func verify(credential, origin string, keys []jwk) (*header, *payload, error) {
	parts := strings.Split(strings.TrimSpace(credential), ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("not a compact JWS")
	}
	var h header
	var p payload
	if err := decodeSegment(parts[0], &h); err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	if err := decodeSegment(parts[1], &p); err != nil {
		return nil, nil, fmt.Errorf("payload: %w", err)
	}
	// ES256 is the only algorithm; never let the token choose another.
	if h.Alg != "ES256" || (h.Typ != "dba-device+jwt" && h.Typ != "dba-access+jwt") {
		return nil, nil, fmt.Errorf("unexpected typ %q / alg %q", h.Typ, h.Alg)
	}
	var pub *ecdsa.PublicKey
	for _, key := range keys {
		if key.Kid == h.Kid {
			var err error
			if pub, err = publicKey(key); err != nil {
				return nil, nil, err
			}
		}
	}
	if pub == nil {
		return nil, nil, fmt.Errorf("unknown signing key %q", h.Kid)
	}
	// JOSE signatures are raw r || s (32 bytes each), not DER.
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return nil, nil, errors.New("malformed signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, nil, errors.New("signature does not verify")
	}
	if p.Iss != origin {
		return nil, nil, fmt.Errorf("issuer is %q, not %q", p.Iss, origin)
	}
	now := time.Now().Unix()
	if now+clockSkew < p.Nbf || now-clockSkew >= p.Exp {
		return nil, nil, errors.New("credential is not valid now")
	}
	return &h, &p, nil
}

func main() {
	origin := strings.TrimRight(os.Getenv("DBA_ORIGIN"), "/")
	if origin == "" {
		origin = "https://devicebasedauth.org"
	}
	credential := os.Getenv("DBA_CREDENTIAL")
	if len(os.Args) > 1 {
		credential = os.Args[1]
	}
	if credential == "" {
		fmt.Fprintln(os.Stderr, "usage: go run . <credential>   (or set DBA_CREDENTIAL)")
		os.Exit(2)
	}
	keys, err := fetchKeys(origin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "JWKS:", err)
		os.Exit(1)
	}
	h, p, err := verify(credential, origin, keys)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid credential:", err)
		os.Exit(1)
	}
	fmt.Printf("Signature: valid (issuer key %s)\n", h.Kid)
	fmt.Printf("Credential: %s (%s)\n", p.Cid, h.Typ)
	fmt.Printf("Device: %s\n", p.Sub)
	fmt.Printf("Account: %s\n", p.Acct)
	fmt.Printf("Sites: %s\n", strings.Join(p.Aud, ", "))
	fmt.Printf("Expires: %s\n", time.Unix(p.Exp, 0).UTC().Format(time.RFC3339))
	for i, grant := range p.Grants {
		fmt.Printf("Grant %d: %s\n", i+1, grant)
	}
}
