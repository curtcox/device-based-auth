package dbaverify

import (
	"errors"
	"fmt"
	"strings"
)

// ConfirmationTyp is the JWS typ of a confirmation (spec/credential.md §9).
const ConfirmationTyp = "dba-confirmation+jwt"

// ConfirmationOptions configure VerifyConfirmation.
type ConfirmationOptions struct {
	JWKS       *JWKS
	Issuer     string      // default DefaultIssuer
	Audience   string      // your audience name; "" skips the audience check
	Credential *Credential // the already-verified credential the confirmation was presented with
}

// VerifyConfirmation verifies a confirmation for an already-verified device credential: issuer
// signature, issuer, and the binding to the credential (same cid, sub and cnf.jkt). Time is not
// checked here: pass the returned payload as Context.Confirmation and the evaluator compares iat
// and exp with its clock, as devicebasedauth.org does with its own record online.
func VerifyConfirmation(jws string, opts ConfirmationOptions) (*Object, error) {
	issuer := opts.Issuer
	if issuer == "" {
		issuer = DefaultIssuer
	}
	decoded, err := DecodeJWS(jws)
	if err != nil {
		return nil, fail("invalid_format", "Confirmation is not a compact JWS")
	}
	if typ, _ := decoded.Header.Get("typ"); !strictEqual(typ, ConfirmationTyp) {
		return nil, fail("wrong_type", "Expected typ "+ConfirmationTyp)
	}
	kid, kidPresent := decoded.Header.Get("kid")
	jwk, ok := opts.JWKS.Find(kid, kidPresent)
	if !ok {
		return nil, fail("unknown_kid", "Unknown signing key "+jsToString(kid))
	}
	if _, err := VerifyJWS(jws, jwk); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			return nil, fail("invalid_signature", "Confirmation signature does not verify")
		}
		return nil, fmt.Errorf("dbaverify: issuer key %s: %w", jsToString(kid), err)
	}
	p := decoded.Payload
	if iss, _ := p.Get("iss"); !strictEqual(iss, issuer) {
		return nil, fail("wrong_issuer", "Issuer is not "+issuer)
	}
	var problems []string
	cid, _ := p.Get("cid")
	sub, _ := p.Get("sub")
	cnf, _ := p.Get("cnf")
	jkt, _ := get(cnf, "jkt")
	_, cidOK := cid.(string)
	_, subOK := sub.(string)
	_, jktOK := jkt.(string)
	if !cidOK || !subOK || !jktOK {
		problems = append(problems, "cid, sub and cnf.jkt are required")
	}
	iat, _ := p.Get("iat")
	exp, _ := p.Get("exp")
	if !isSafeInteger(iat) || !isSafeInteger(exp) || exp.(float64) <= iat.(float64) {
		problems = append(problems, "iat and exp must be NumericDates with exp after iat")
	}
	if byTimeout, _ := p.Get("by_timeout"); func() bool { _, ok := byTimeout.(bool); return !ok }() {
		problems = append(problems, "by_timeout must be true or false")
	}
	aud, _ := p.Get("aud")
	audList, audOK := aud.([]any)
	for _, a := range audList {
		if _, isString := a.(string); !isString {
			audOK = false
		}
	}
	if !audOK {
		problems = append(problems, "aud must be a list of audiences")
	}
	if len(problems) > 0 {
		return nil, fail("invalid_claims", strings.Join(problems, "; "))
	}
	if opts.Credential == nil || cid != opts.Credential.Claims.CredentialID || sub != opts.Credential.Claims.Subject {
		return nil, fail("wrong_credential", "Confirmation is for another credential")
	}
	if jkt != opts.Credential.Claims.JKT || opts.Credential.Claims.JKT == "" {
		return nil, fail("key_mismatch", "Confirmation is for another device key")
	}
	if opts.Audience != "" && !listIncludes(aud, opts.Audience) {
		return nil, fail("wrong_audience", "Confirmation is not valid for "+opts.Audience)
	}
	return p, nil
}
