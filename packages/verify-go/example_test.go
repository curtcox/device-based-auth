package dbaverify_test

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	dbaverify "github.com/curtcox/device-based-auth/packages/verify-go"
)

// The code between the README markers is the usage example in README.md, and
// TestReadmeMatchesExamples keeps the two identical, so the README sample is always tested.

func Example() {
	// README:begin middleware
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
	// README:end

	// Output: 401 {"code":"credential_required","error":"credential_required","reasons":[]}
}

func ExampleEvaluateGrants() {
	// README:begin grants
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
	// README:end

	// Output:
	// true [[]]
	// false [[outside_time_window]]
}
