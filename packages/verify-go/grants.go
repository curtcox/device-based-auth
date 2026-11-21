package dbaverify

import (
	"regexp"
	"strings"
)

// Grant vocabulary v1: validation and evaluation. The normative description is
// spec/evaluation.md, and spec/vectors/evaluation.json must pass. Grants are untrusted JSON
// (parsed with ParseJSON), handled dynamically so that unknown members can be detected and
// reported exactly as the JavaScript evaluator reports them.
//
// This file holds the vocabulary, matching and evaluation; grants_validate.go validation,
// grants_time.go zones and time windows, grants_place.go networks and places.

// VocabularyVersion is the grant vocabulary version credentials carry in "ver".
const VocabularyVersion = 1

// Days are the weekday names grants use, Sunday first (time.Weekday order).
var Days = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// UsePeriods are the periods of limits.uses.
var UsePeriods = []string{"minute", "hour", "day", "month", "total"}

// Limits are the size limits on grant lists.
var Limits = struct{ Grants, Actions, Resources, Windows, Places, Networks, ResourceLength int }{32, 64, 64, 16, 64, 64, 256}

var (
	grantKeys     = keySet("actions", "resources", "when", "where", "limits", "require")
	whenKeys      = keySet("tz", "windows", "not_before", "not_after")
	windowKeys    = keySet("days", "from", "to")
	whereKeys     = keySet("source", "countries", "regions", "areas", "networks")
	areaKeys      = keySet("lat", "lon", "radius_m")
	limitKeys     = keySet("uses", "spend_usd_per_month")
	usesKeys      = keySet("count", "per")
	requireKeys   = keySet("online", "step_up", "attestation", "verified_boot", "app_ids", "gates", "gates_reuse_s", "confirmation")
	gateEntryKeys = keySet("any", "timeout_s", "on_timeout")
	gateIDPattern = regexp.MustCompile(`^gate_[A-Za-z0-9]{8,64}$`)

	maxAppIDs = 16

	attestationLevels = map[string][]string{"hardware": {"tee", "strongbox", "secure_enclave", "tpm"}, "strongbox": {"strongbox"}}
	// An Apple app id: the 10-character team id, a dot, the bundle id.
	appIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}\.[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$`)
	// An Android app: "android:", the package name, ":", the SHA-256 of its signing certificate in hex.
	androidAppIDPattern = regexp.MustCompile(`^android:[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+:[0-9a-f]{64}$`)

	actionPattern  = regexp.MustCompile(`^[a-z0-9-]{1,32}(?::[a-z0-9_.-]{1,64})*:(?:[a-z0-9_.-]{1,64}|\*)$`)
	timePattern    = regexp.MustCompile(`^(?:[01]\d|2[0-3]):[0-5]\d$|^24:00$`)
	countryPattern = regexp.MustCompile(`^[A-Z]{2}$`)
	regionPattern  = regexp.MustCompile(`^[A-Z]{2}-[A-Z0-9]{1,3}$`)
)

// GateLimits bound gate entries (spec/evaluation.md §3.6).
var GateLimits = struct{ Entries, Gates, MinTimeout, MaxTimeout, DefaultTimeout, MaxReuse int }{3, 5, 10, 86400, 300, 3600}

// GateKinds are the gate kinds an audience policy can name; "owner" is the built-in step-up approver.
var GateKinds = []string{"owner", "dba-device", "totp", "webauthn", "webhook", "duo", "okta-verify"}

// GateEntry is one entry of require.gates with defaults filled in: one allow from any of its
// gates satisfies it; with no answer by TimeoutS it settles as OnTimeout.
type GateEntry struct {
	Any       []string `json:"any"`
	TimeoutS  int      `json:"timeout_s"`
	OnTimeout string   `json:"on_timeout"`
}

// confirmationSkew is the clock skew allowed on confirmations, as on credentials.
const confirmationSkew = 60

func keySet(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}

func contains(list []string, v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// listIncludes is Array.prototype.includes on a parsed JSON array.
func listIncludes(list any, v any) bool {
	items, ok := list.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if strictEqual(item, v) {
			return true
		}
	}
	return false
}

// ActionMatches reports whether an action pattern (exact, or ending in ":*") matches an action.
// "ns:a:*" matches only actions starting with "ns:a:", so a wildcard needs a segment boundary.
func ActionMatches(pattern, action string) bool {
	if pattern == action {
		return true
	}
	return strings.HasSuffix(pattern, ":*") && strings.HasPrefix(action, pattern[:len(pattern)-1])
}

// ResourceMatches reports whether a resource pattern ("*", "prefix*" or exact) matches a
// resource. An empty resource (none) matches only "*".
func ResourceMatches(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return resource != "" && strings.HasPrefix(resource, pattern[:len(pattern)-1])
	}
	return resource != "" && pattern == resource
}

// ActionNamespace is the namespace of an action ("hashbin" for "hashbin:content:write").
func ActionNamespace(action string) string { ns, _, _ := strings.Cut(action, ":"); return ns }

// Context is what a request is evaluated in.
type Context struct {
	Now      int64    // the verifier's clock, seconds; device clocks are never trusted
	Action   string   // e.g. "hashbin:content:write"
	Resource string   // audience-defined; "" means none (matches only "*")
	Location Location // observed network location and device-reported location
	Online   bool     // true only when devicebasedauth.org itself evaluates (it enforces counters)
	// Attestation is the presented credential's device.attestation (a JSON object), or nil.
	Attestation any
	// Confirmation holds the claims ({iat, exp, by_timeout}) of a verified confirmation
	// (VerifyConfirmation), or nil.
	Confirmation any
	// Policy is the audience's catalog entry for the action ({gates: {require, kinds, fail_open}}), or nil.
	Policy any
	// GateKinds maps gate ids to kinds ({gate id: kind}); only devicebasedauth.org knows them (online).
	GateKinds any
}

// Online lists the checks of a grant that only devicebasedauth.org can make.
type Online struct {
	Uses       any         `json:"uses,omitempty"`          // the grant's limits.uses ({count, per})
	StepUp     bool        `json:"step_up,omitempty"`       // the owner must approve each use
	Required   bool        `json:"required,omitempty"`      // require.online
	Gates      []GateEntry `json:"gates,omitempty"`         // gates that must approve each use
	GatesReuse int         `json:"gates_reuse_s,omitempty"` // seconds one approval covers repeated uses
	FailOpen   *bool       `json:"fail_open,omitempty"`     // false: the audience refuses allows by timeout
	GatePolicy bool        `json:"gate_policy,omitempty"`   // the audience requires gates on this action
}

// IsEmpty reports whether the grant needs no online checks.
func (o Online) IsEmpty() bool {
	return o.Uses == nil && !o.StepUp && !o.Required && o.Gates == nil && !o.GatePolicy
}

// GrantResult is the outcome for one grant.
type GrantResult struct {
	OK      bool     `json:"ok"`
	Reasons []string `json:"reasons"`
	Online  Online   `json:"online"`
}

// Caveats are conditions the audience enforces itself after an allow.
type Caveats struct {
	SpendUSDPerMonth *float64 `json:"spend_usd_per_month,omitempty"`
}

// Result is the decision over a grant list (the JavaScript evaluateGrants result).
type Result struct {
	Allow          bool          `json:"allow"`
	GrantIndex     *int          `json:"grant_index"` // nil when nothing allowed
	Grant          any           `json:"grant"`       // the allowing grant, or nil
	Online         Online        `json:"online"`      // online checks of the allowing grant
	Caveats        Caveats       `json:"caveats"`
	Reasons        [][]string    `json:"reasons"`         // per grant, in grant order
	OnlineRequired bool          `json:"online_required"` // denied only because checks need online authorization
	Results        []GrantResult `json:"results"`
}

// EvaluateGrant evaluates one grant against a request context.
func EvaluateGrant(grant any, ctx Context) GrantResult {
	reasons := []string{}
	online := Online{}
	var unknown []string
	if g, ok := asObject(grant); !ok {
		unknown = []string{"grant"}
	} else {
		for _, k := range g.Keys() {
			if !grantKeys[k] {
				unknown = append(unknown, k)
			}
		}
		for _, nested := range []struct {
			key     string
			allowed map[string]bool
		}{{"when", whenKeys}, {"where", whereKeys}, {"limits", limitKeys}, {"require", requireKeys}} {
			v, _ := g.Get(nested.key)
			if o, ok := asObject(v); ok {
				for _, k := range o.Keys() {
					if !nested.allowed[k] {
						unknown = append(unknown, nested.key+"."+k)
					}
				}
			}
		}
	}
	if len(unknown) > 0 {
		for _, k := range unknown {
			reasons = append(reasons, "unknown_constraint:"+k)
		}
		return GrantResult{OK: false, Reasons: reasons, Online: online}
	}
	if len(ValidateGrant(grant, "grant")) > 0 {
		return GrantResult{OK: false, Reasons: []string{"invalid_grant"}, Online: online}
	}
	g, _ := asObject(grant)
	now := ctx.Now

	actions, _ := g.Get("actions")
	matched := false
	for _, p := range actions.([]any) {
		if ActionMatches(p.(string), ctx.Action) {
			matched = true
			break
		}
	}
	if !matched {
		reasons = append(reasons, "action_not_granted")
	}

	resources, ok := g.Get("resources")
	patterns := []any{"*"}
	if ok && truthy(resources) {
		patterns = resources.([]any)
	}
	matched = false
	for _, p := range patterns {
		if ResourceMatches(p.(string), ctx.Resource) {
			matched = true
			break
		}
	}
	if !matched {
		reasons = append(reasons, "resource_not_granted")
	}

	if when, _ := g.Get("when"); truthy(when) {
		if nb, ok := get(when, "not_before"); ok && float64(now) < nb.(float64) {
			reasons = append(reasons, "before_not_before")
		}
		if na, ok := get(when, "not_after"); ok && float64(now) >= na.(float64) {
			reasons = append(reasons, "after_not_after")
		}
		if windows, _ := get(when, "windows"); truthy(windows) {
			tz, _ := get(when, "tz")
			zone, _ := loadZone(tz)
			local := LocalTimeAt(now, zone)
			inside := false
			for _, w := range windows.([]any) {
				if inWindow(w, local) {
					inside = true
					break
				}
			}
			if !inside {
				reasons = append(reasons, "outside_time_window")
			}
		}
	}

	if where, _ := g.Get("where"); truthy(where) {
		source, _ := get(where, "source")
		if strictEqual(source, "network") || strictEqual(source, "both") {
			checkNetwork(where, ctx.Location.Network, &reasons)
		}
		if strictEqual(source, "device") || strictEqual(source, "both") {
			checkDevice(where, ctx.Location.Device, now, &reasons)
		}
	}

	// Key attestation is a fact about the credential (device.attestation, signed by the issuer),
	// so it is checked offline like time and place.
	require, _ := g.Get("require")
	_, attested := asObject(ctx.Attestation)
	apps, hasApps := get(require, "app_ids")
	appListed := false
	// Android's app identity comes from the OS, not the secure hardware, so it counts only when the
	// same attestation shows verified boot and a locked bootloader (spec/evaluation.md §3.6). Each
	// kind of app id matches only its own attestation format.
	attFormat, _ := get(ctx.Attestation, "format")
	android := attested && strictEqual(attFormat, "android-key")
	appTrusted := true
	if android {
		boot, _ := get(ctx.Attestation, "verified_boot")
		locked, _ := get(ctx.Attestation, "device_locked")
		appTrusted = strictEqual(boot, "verified") && strictEqual(locked, true)
	}
	if appID, _ := get(ctx.Attestation, "app_id"); attested && appTrusted {
		if list, isList := apps.([]any); isList {
			if id, isString := appID.(string); isString && strings.HasPrefix(id, "android:") == android {
				for _, a := range list {
					appListed = appListed || strictEqual(a, appID)
				}
			}
		}
	}
	if level, ok := get(require, "attestation"); ok {
		securityLevel, _ := get(ctx.Attestation, "security_level")
		allowed := false
		if name, isString := level.(string); isString && attested {
			for _, l := range attestationLevels[name] {
				allowed = allowed || strictEqual(securityLevel, l)
			}
		}
		// Apple App Attest vouches for the app that reported the key, not for the key itself, so it
		// counts only for production builds of apps the grant names (spec/evaluation.md §3.6).
		format, _ := get(ctx.Attestation, "format")
		environment, _ := get(ctx.Attestation, "environment")
		if attested && strictEqual(format, "apple-appattest") && !(appListed && strictEqual(environment, "production")) {
			allowed = false
		}
		if !allowed {
			reasons = append(reasons, "attestation_required")
		}
	}
	if hasApps && !appListed {
		reasons = append(reasons, "attested_app_required")
	}
	if v, _ := get(require, "verified_boot"); truthy(v) {
		boot, _ := get(ctx.Attestation, "verified_boot")
		locked, _ := get(ctx.Attestation, "device_locked")
		if !attested || !strictEqual(boot, "verified") || !strictEqual(locked, true) {
			reasons = append(reasons, "verified_boot_required")
		}
	}

	// A confirmation is checked offline too: verifiers verify the DBA-Confirmation header and pass
	// its claims in; DBA's own /authorize passes its record (spec/evaluation.md §3.6).
	var policy any
	if p, _ := get(ctx.Policy, "gates"); func() bool { _, ok := asObject(p); return ok }() {
		policy = p
	}
	failOpen, _ := get(policy, "fail_open")
	if v, _ := get(require, "confirmation"); truthy(v) {
		iat, _ := get(ctx.Confirmation, "iat")
		exp, _ := get(ctx.Confirmation, "exp")
		byTimeout, _ := get(ctx.Confirmation, "by_timeout")
		_, isObj := asObject(ctx.Confirmation)
		switch {
		case !isObj || !isSafeInteger(iat) || !isSafeInteger(exp) || float64(now+confirmationSkew) < iat.(float64):
			reasons = append(reasons, "confirmation_required")
		case float64(now-confirmationSkew) >= exp.(float64):
			reasons = append(reasons, "confirmation_expired")
		case !strictEqual(byTimeout, false) && strictEqual(failOpen, false):
			reasons = append(reasons, "confirmation_by_timeout_refused")
		}
	}
	gates := GrantGates(grant)
	if requireGates, _ := get(policy, "require"); strictEqual(requireGates, true) {
		// Only DBA knows each gate's kind, so a policy that requires gates is checked online;
		// offline it makes the grant online-only (spec/evaluation.md §3.8).
		online.GatePolicy = true
		if ctx.Online {
			kinds, _ := get(policy, "kinds")
			_, kindsListed := kinds.([]any)
			accepted := func(id string) bool {
				var kind any = "owner"
				if id != "owner" {
					kind, _ = get(ctx.GateKinds, id)
				}
				if _, isString := kind.(string); !isString {
					return false
				}
				return !kindsListed || listIncludes(kinds, kind)
			}
			ok := false
			for _, entry := range gates {
				all := true
				for _, id := range entry.Any {
					all = all && accepted(id)
				}
				ok = ok || all
			}
			if !ok {
				reasons = append(reasons, "gate_required")
			}
		}
	}

	limits, _ := g.Get("limits")
	if uses, _ := get(limits, "uses"); truthy(uses) {
		online.Uses = uses
	}
	if v, _ := get(require, "step_up"); truthy(v) {
		online.StepUp = true
	}
	if v, _ := get(require, "online"); truthy(v) {
		online.Required = true
	}
	if gates != nil {
		online.Gates = gates
		if reuse, _ := get(require, "gates_reuse_s"); isSafeInteger(reuse) {
			online.GatesReuse = int(reuse.(float64))
		}
		if strictEqual(failOpen, false) {
			f := false
			online.FailOpen = &f
		}
	}
	if len(reasons) == 0 && !online.IsEmpty() && !ctx.Online {
		reasons = append(reasons, "online_required")
	}
	return GrantResult{OK: len(reasons) == 0, Reasons: reasons, Online: online}
}

// EvaluateGrants evaluates every grant. The request is allowed when any grant passes; nothing
// is allowed by default. grants is normally the []any from a verified credential's payload.
func EvaluateGrants(grants any, ctx Context) Result {
	list, ok := normalizeGo(grants).([]any)
	if !ok {
		return Result{Reasons: [][]string{{"invalid_grants"}}, Results: []GrantResult{}}
	}
	ctx.Confirmation, ctx.Policy, ctx.GateKinds = normalizeGo(ctx.Confirmation), normalizeGo(ctx.Policy), normalizeGo(ctx.GateKinds)
	results := make([]GrantResult, len(list))
	index := -1
	for i, g := range list {
		results[i] = EvaluateGrant(normalizeGo(g), ctx)
		if index < 0 && results[i].OK {
			index = i
		}
	}
	reasons := make([][]string, len(results))
	onlineRequired := false
	for i, r := range results {
		reasons[i] = r.Reasons
		if index < 0 && len(r.Reasons) == 1 && r.Reasons[0] == "online_required" {
			onlineRequired = true
		}
	}
	result := Result{Allow: index >= 0, Reasons: reasons, OnlineRequired: onlineRequired, Results: results}
	if index >= 0 {
		i := index
		result.GrantIndex = &i
		result.Grant = list[index]
		result.Online = results[index].Online
		limits, _ := get(list[index], "limits")
		if spend, ok := get(limits, "spend_usd_per_month"); ok {
			if f, isNum := spend.(float64); isNum {
				result.Caveats.SpendUSDPerMonth = &f
			}
		}
	}
	return result
}
