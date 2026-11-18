package dbaverify

import (
	"os"
	"reflect"
	"testing"
)

// These tests run every case of spec/vectors exactly as spec/vectors.test.js does for the
// JavaScript reference implementation.

func loadVectors(t *testing.T, name string) *Object {
	t.Helper()
	data, err := os.ReadFile("../../spec/vectors/" + name)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	return v.(*Object)
}

func str(v any, key string) string { x, _ := get(v, key); s, _ := x.(string); return s }

func num(v any, key string) *float64 {
	x, _ := get(v, key)
	if f, ok := x.(float64); ok {
		return &f
	}
	return nil
}

// contextFromVector converts a vector's JSON context with the JavaScript semantics: members
// that are absent or of the wrong type behave as undefined.
func contextFromVector(c any) Context {
	now, _ := get(c, "now")
	online, _ := get(c, "online")
	ctx := Context{Now: int64(now.(float64)), Action: str(c, "action"), Resource: str(c, "resource"), Online: truthy(online)}
	location, _ := get(c, "location")
	if network, _ := get(location, "network"); truthy(network) {
		ctx.Location.Network = &NetworkLocation{Country: str(network, "country"), Region: str(network, "region"), Lat: num(network, "lat"), Lon: num(network, "lon"), IP: str(network, "ip")}
	}
	device, _ := get(location, "device")
	ctx.Location.Device = DeviceLocationFromClaim(device)
	ctx.Attestation, _ = get(c, "attestation")
	return ctx
}

func TestEvaluationVectors(t *testing.T) {
	cases, _ := loadVectors(t, "evaluation.json").Get("cases")
	if len(cases.([]any)) == 0 {
		t.Fatal("no evaluation vectors")
	}
	for _, c := range cases.([]any) {
		t.Run(str(c, "name"), func(t *testing.T) {
			grants, _ := get(c, "grants")
			context, _ := get(c, "context")
			expected, _ := get(c, "expected")
			result := EvaluateGrants(grants, contextFromVector(context))

			wantAllow, _ := get(expected, "allow")
			if result.Allow != wantAllow.(bool) {
				t.Errorf("allow = %v, want %v", result.Allow, wantAllow)
			}
			wantIndex, _ := get(expected, "grant_index")
			switch {
			case wantIndex == nil && result.GrantIndex != nil:
				t.Errorf("grant_index = %d, want null", *result.GrantIndex)
			case wantIndex != nil && (result.GrantIndex == nil || float64(*result.GrantIndex) != wantIndex.(float64)):
				t.Errorf("grant_index = %v, want %v", result.GrantIndex, wantIndex)
			}
			wantReasons, _ := get(expected, "reasons")
			want := [][]string{}
			for _, list := range wantReasons.([]any) {
				reasons := []string{}
				for _, r := range list.([]any) {
					reasons = append(reasons, r.(string))
				}
				want = append(want, reasons)
			}
			if !reflect.DeepEqual(result.Reasons, want) {
				t.Errorf("reasons = %q, want %q", result.Reasons, want)
			}
		})
	}
}

func vectorJWKS(t *testing.T, vectors *Object) *JWKS {
	t.Helper()
	jwks, _ := vectors.Get("jwks")
	keys, _ := get(jwks, "keys")
	return &JWKS{Keys: keys.([]any)}
}

// outcome is the {valid, code} shape the vectors expect.
func outcome(err error) map[string]any {
	if err == nil {
		return map[string]any{"valid": true}
	}
	return map[string]any{"valid": false, "code": ErrorCode(err)}
}

func expectedOutcome(c any) map[string]any {
	expected, _ := get(c, "expected")
	out := map[string]any{}
	o, _ := asObject(expected)
	for _, k := range o.Keys() {
		v, _ := o.Get(k)
		out[k] = v
	}
	return out
}

func TestCredentialVectors(t *testing.T) {
	vectors := loadVectors(t, "credentials.json")
	jwks := vectorJWKS(t, vectors)
	issuer, _ := vectors.Get("issuer")
	creds, _ := vectors.Get("credentials")
	for _, c := range creds.([]any) {
		t.Run(str(c, "name"), func(t *testing.T) {
			_, err := VerifyCredential(str(c, "jws"), CredentialOptions{JWKS: jwks, Issuer: issuer.(string), Audience: str(c, "audience"), Now: int64(*num(c, "now"))})
			if got, want := outcome(err), expectedOutcome(c); !reflect.DeepEqual(got, want) {
				t.Errorf("got %v (%v), want %v", got, err, want)
			}
		})
	}
}

func TestProofVectors(t *testing.T) {
	vectors := loadVectors(t, "credentials.json")
	proofs, _ := vectors.Get("proofs")
	for _, c := range proofs.([]any) {
		t.Run(str(c, "name"), func(t *testing.T) {
			_, err := VerifyProof(str(c, "proof"), ProofOptions{Method: str(c, "method"), URL: str(c, "url"), Credential: str(c, "credential"), JKT: str(c, "jkt"), Now: int64(*num(c, "now")), Nonce: str(c, "nonce")})
			if got, want := outcome(err), expectedOutcome(c); !reflect.DeepEqual(got, want) {
				t.Errorf("got %v (%v), want %v", got, err, want)
			}
		})
	}
}

func TestStatusListVector(t *testing.T) {
	vectors := loadVectors(t, "credentials.json")
	jwks := vectorJWKS(t, vectors)
	statusList, _ := vectors.Get("status_list")
	decoded, err := VerifyJWS(str(statusList, "jwt"), jwks.Keys[0])
	if err != nil {
		t.Fatal(err)
	}
	claim, _ := decoded.Payload.Get("status_list")
	bits, err := DecodeStatusList(claim)
	if err != nil {
		t.Fatal(err)
	}
	revoked := []float64{}
	for i := int64(0); i <= 8; i++ {
		if GetBit(bits, i) == 1 {
			revoked = append(revoked, float64(i))
		}
	}
	wantList, _ := get(statusList, "revoked_indexes")
	want := []float64{}
	for _, v := range wantList.([]any) {
		want = append(want, v.(float64))
	}
	if !reflect.DeepEqual(revoked, want) {
		t.Errorf("revoked = %v, want %v", revoked, want)
	}
}

func TestDeviceJKTVector(t *testing.T) {
	vectors := loadVectors(t, "credentials.json")
	device, _ := vectors.Get("test_only_device_private_jwk")
	jkt, err := JWKThumbprint(device)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := vectors.Get("device_jkt"); jkt != want {
		t.Errorf("thumbprint = %s, want %s", jkt, want)
	}
}
