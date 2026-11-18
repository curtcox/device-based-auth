package dbaverify

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// Helpers for a site that accepts devicebasedauth.org credentials as API keys (device-bound),
// the Go counterpart of the JavaScript createSiteAuth. (The OpenID Connect sign-in client in
// site.js is not ported; any OIDC library can talk to devicebasedauth.org.)

// LinkInfo is passed to SiteOptions.LinkedUser.
type LinkInfo struct {
	Request    *http.Request
	Credential *Credential
	Kind       string // "device" or "access"
}

// SiteOptions configure a SiteAuth.
type SiteOptions struct {
	Options
	// Namespace is the site's action namespace ("hashbin").
	Namespace string
	// Scopes are the site's own scope names ("content:write", …); actions are
	// Namespace + ":" + scope.
	Scopes []string
	// LinkedUser maps a devicebasedauth.org account to a local user id, or "" when the account
	// has not been linked to a local account yet.
	LinkedUser func(ctx context.Context, dbaAccount string, info LinkInfo) (string, error)
}

// SiteAuth authenticates requests for a site.
type SiteAuth struct {
	opts     SiteOptions
	verifier *Verifier
	actions  []string
}

// SiteResult is the outcome of SiteAuth.Authenticate.
type SiteResult struct {
	OK           bool     `json:"ok"`
	Status       int      `json:"status,omitempty"`
	Code         string   `json:"code,omitempty"`
	Message      string   `json:"message,omitempty"`
	UserID       string   `json:"user_id,omitempty"`
	DBAAccount   string   `json:"dba_account,omitempty"`
	DeviceID     string   `json:"device_id,omitempty"`
	CredentialID string   `json:"credential_id,omitempty"`
	Kind         string   `json:"kind,omitempty"`
	Session      bool     `json:"session"` // the credential may sign in (namespace:session)
	Scopes       []string `json:"scopes"`  // site scopes allowed right now (offline checks)
	// Caveats: the tightest spend cap among this site's grants.
	Caveats    Caveats     `json:"caveats"`
	Credential *Credential `json:"-"`
	Proof      *Proof      `json:"-"`
}

// NewSiteAuth creates a SiteAuth.
func NewSiteAuth(opts SiteOptions) (*SiteAuth, error) {
	if opts.Namespace == "" || len(opts.Scopes) == 0 || opts.LinkedUser == nil {
		return nil, errors.New("dbaverify: NewSiteAuth needs Namespace, Scopes and LinkedUser")
	}
	verifier, err := NewVerifier(opts.Options)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var actions []string
	for _, scope := range append(append([]string{}, opts.Scopes...), "session") {
		if !seen[scope] {
			seen[scope] = true
			actions = append(actions, opts.Namespace+":"+scope)
		}
	}
	return &SiteAuth{opts: opts, verifier: verifier, actions: actions}, nil
}

// Verifier is the underlying Verifier.
func (s *SiteAuth) Verifier() *Verifier { return s.verifier }

// Authenticate returns (nil, nil) when the request carries no DBA credential, so the site can
// fall through to its other authentication; otherwise a result that is OK or says why not.
func (s *SiteAuth) Authenticate(r *http.Request) (*SiteResult, error) {
	auth, err := s.verifier.AuthenticateRequest(r)
	if err != nil {
		return nil, err
	}
	if !auth.OK {
		if auth.Code == "credential_required" {
			return nil, nil
		}
		return &SiteResult{Status: auth.Status, Code: auth.Code, Message: auth.Message, Scopes: []string{}}, nil
	}
	claims := auth.Credential.Claims
	userID, err := s.opts.LinkedUser(r.Context(), claims.Account, LinkInfo{Request: r, Credential: auth.Credential, Kind: auth.Kind})
	if err != nil {
		return nil, err
	}
	if userID == "" {
		return &SiteResult{Status: 403, Code: "account_not_linked", DBAAccount: claims.Account, Scopes: []string{},
			Message: "Link devicebasedauth.org account " + claims.Account + " to your " + s.opts.Audience + " account first"}, nil
	}
	result := &SiteResult{OK: true, UserID: userID, DBAAccount: claims.Account, DeviceID: claims.Subject, CredentialID: claims.CredentialID,
		Kind: auth.Kind, Scopes: []string{}, Credential: auth.Credential, Proof: auth.Proof}
	for _, action := range s.verifier.AllowedActions(auth.Credential, s.actions, r, auth.Proof, Location{}) {
		scope := action[len(s.opts.Namespace)+1:]
		if scope == "session" {
			result.Session = true
		} else {
			result.Scopes = append(result.Scopes, scope)
		}
	}
	// The tightest spend cap among this site's grants applies to everything the credential
	// does here; caps on other sites' grants are theirs to enforce.
	prefix := s.opts.Namespace + ":"
	for _, g := range claims.Grants {
		actions, _ := get(g, "actions")
		list, ok := actions.([]any)
		if !ok {
			continue
		}
		ours := false
		for _, a := range list {
			if as, ok := a.(string); ok && strings.HasPrefix(as, prefix) {
				ours = true
			}
		}
		limits, _ := get(g, "limits")
		if spend, ok := get(limits, "spend_usd_per_month"); ours && ok {
			if f, isNum := spend.(float64); isNum && (result.Caveats.SpendUSDPerMonth == nil || f < *result.Caveats.SpendUSDPerMonth) {
				result.Caveats.SpendUSDPerMonth = &f
			}
		}
	}
	return result, nil
}

// Allows decides one site action (without the namespace) for an authenticated result,
// including resource-scoped grants.
func (s *SiteAuth) Allows(result *SiteResult, action, resource string) bool {
	if result == nil || !result.OK {
		return false
	}
	return s.verifier.Decide(result.Credential, Check{Action: s.opts.Namespace + ":" + action, Resource: resource}, nil, result.Proof).Allow
}

// SiteResultFromContext returns the SiteResult stored by SiteAuth.Middleware, or nil when the
// request carried no DBA credential.
func SiteResultFromContext(ctx context.Context) *SiteResult {
	r, _ := ctx.Value(siteResultKey).(*SiteResult)
	return r
}

// Middleware authenticates DBA credentials in front of a handler. Requests without one pass
// through untouched (the site's other auth decides); a credential that fails gets a JSON error;
// an accepted one is available through SiteResultFromContext. Handlers still decide each
// action with Allows or the result's Scopes.
func (s *SiteAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, err := s.Authenticate(r)
		if err != nil {
			writeError(w, 500, "verifier_error", "Credential verification failed", nil)
			return
		}
		if result == nil {
			next.ServeHTTP(w, r)
			return
		}
		if !result.OK {
			var extra map[string]any
			if result.DBAAccount != "" {
				extra = map[string]any{"dba_account": result.DBAAccount}
			}
			writeError(w, result.Status, result.Code, result.Message, extra)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), siteResultKey, result)))
	})
}
