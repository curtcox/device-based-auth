package dbaverify

import (
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // grants name IANA zones; do not depend on the host having zoneinfo installed
)

// Grant vocabulary v1: validation and evaluation. The normative description is
// spec/evaluation.md, and spec/vectors/evaluation.json must pass. Grants are untrusted JSON
// (parsed with ParseJSON), handled dynamically so that unknown members can be detected and
// reported exactly as the JavaScript evaluator reports them.

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

// deviceLocationMaxAge is how old (seconds) a device-reported location may be.
const deviceLocationMaxAge = 300

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

var zoneCache sync.Map // name -> *time.Location

// loadZone resolves an IANA zone. Only successes are cached; zone names come from
// issuer-signed grants, so the cache is bounded by what the issuer accepts.
func loadZone(tz any) (*time.Location, bool) {
	name, ok := tz.(string)
	// Go accepts "" (UTC) and "Local" (the host zone); Intl.DateTimeFormat accepts neither.
	if !ok || name == "" || name == "Local" {
		return nil, false
	}
	if loc, ok := zoneCache.Load(name); ok {
		return loc.(*time.Location), true
	}
	loc := resolveZone(name)
	if loc == nil {
		return nil, false
	}
	zoneCache.Store(name, loc)
	return loc, true
}

// offsetZone matches the UTC offsets Intl.DateTimeFormat accepts as time zones: ±HH, ±HHMM, ±HH:MM.
var offsetZone = regexp.MustCompile(`^([+-])([01]\d|2[0-3])(?::?([0-5]\d))?$`)

// resolveZone loads a zone the way Intl.DateTimeFormat accepts it. Intl matches IANA names
// case-insensitively and accepts fixed offsets; time.LoadLocation does neither, so offsets are
// built directly and a few capitalizations of each name segment are tried ("america/chicago",
// "etc/gmt+5", "us/central"). Names with irregular capitals (e.g. "port-au-prince") still fail,
// which denies the grant: never wider than the JavaScript.
func resolveZone(name string) *time.Location {
	if m := offsetZone.FindStringSubmatch(name); m != nil {
		h, _ := strconv.Atoi(m[2])
		mins, _ := strconv.Atoi(m[3])
		offset := h*3600 + mins*60
		if m[1] == "-" {
			offset = -offset
		}
		return time.FixedZone(name, offset)
	}
	if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		return nil
	}
	if loc, err := time.LoadLocation(name); err == nil {
		return loc
	}
	candidates := []string{""}
	for i, segment := range strings.Split(name, "/") {
		var next []string
		for _, prefix := range candidates {
			if i > 0 {
				prefix += "/"
			}
			next = append(next, prefix+titleCase(segment), prefix+strings.ToUpper(segment))
		}
		candidates = next
		if len(candidates) > 16 {
			return nil
		}
	}
	for _, candidate := range candidates {
		if candidate == name || candidate == "Local" {
			continue
		}
		if loc, err := time.LoadLocation(candidate); err == nil {
			return loc
		}
	}
	return nil
}

// titleCase capitalizes each run of letters ("new_york" -> "New_York").
func titleCase(s string) string {
	b := []byte(strings.ToLower(s))
	start := true
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			if start {
				b[i] = c - 'a' + 'A'
			}
			start = false
		} else {
			start = true
		}
	}
	return string(b)
}

// ValidTimeZone reports whether the IANA zone is known (embedded tzdata is always available).
func ValidTimeZone(tz string) bool { _, ok := loadZone(tz); return ok }

// parseIP parses an IPv4 or IPv6 address exactly as the JavaScript parseIp does (which is more
// lenient than net/netip about IPv4 leading zeros and stricter about zones), returning a
// netip.Addr so that range checks can use net/netip.
func parseIP(ip string) (netip.Addr, bool) {
	if ipv4Pattern.MatchString(ip) {
		var b [4]byte
		for i, part := range strings.Split(ip, ".") {
			n, _ := strconv.Atoi(part)
			if n > 255 {
				return netip.Addr{}, false
			}
			b[i] = byte(n)
		}
		return netip.AddrFrom4(b), true
	}
	if !ipv6Chars.MatchString(ip) || !strings.Contains(ip, ":") {
		return netip.Addr{}, false
	}
	address := ip
	if m := ipv4Suffix.FindStringSubmatch(address); m != nil {
		v4, ok := parseIP(m[1])
		if !ok {
			return netip.Addr{}, false
		}
		b := v4.As4()
		hi := uint32(b[0])<<8 | uint32(b[1])
		lo := uint32(b[2])<<8 | uint32(b[3])
		address = address[:len(address)-len(m[1])] + strconv.FormatUint(uint64(hi), 16) + ":" + strconv.FormatUint(uint64(lo), 16)
	}
	halves := strings.Split(address, "::")
	if len(halves) > 2 {
		return netip.Addr{}, false
	}
	var head, tail []string
	if halves[0] != "" {
		head = strings.Split(halves[0], ":")
	}
	if len(halves) == 2 && halves[1] != "" {
		tail = strings.Split(halves[1], ":")
	}
	missing := 8 - len(head) - len(tail)
	if (len(halves) == 1 && missing != 0) || missing < 0 {
		return netip.Addr{}, false
	}
	groups := append([]string{}, head...)
	if len(halves) == 2 {
		for i := 0; i < missing; i++ {
			groups = append(groups, "0")
		}
	}
	groups = append(groups, tail...)
	if len(groups) != 8 {
		return netip.Addr{}, false
	}
	var b [16]byte
	for i, g := range groups {
		if !hexGroup.MatchString(g) {
			return netip.Addr{}, false
		}
		n, _ := strconv.ParseUint(g, 16, 16)
		b[2*i] = byte(n >> 8)
		b[2*i+1] = byte(n)
	}
	return netip.AddrFrom16(b), true
}

var (
	ipv4Pattern = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	ipv6Chars   = regexp.MustCompile(`^[0-9a-fA-F:.]+$`)
	ipv4Suffix  = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})$`)
	hexGroup    = regexp.MustCompile(`^[0-9a-fA-F]{1,4}$`)
	prefixText  = regexp.MustCompile(`^\d{1,3}$`)
)

// ParseCIDR parses a CIDR range as the JavaScript parseCidr does. Host bits need not be zero.
func ParseCIDR(cidr string) (netip.Prefix, bool) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 || !prefixText.MatchString(parts[1]) {
		return netip.Prefix{}, false
	}
	addr, ok := parseIP(parts[0])
	if !ok {
		return netip.Prefix{}, false
	}
	bits, _ := strconv.Atoi(parts[1])
	if bits > addr.BitLen() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}

// IPInCIDR reports whether ip is inside the CIDR range. Address families never match each
// other (an IPv4-mapped IPv6 address does not match an IPv4 range), as in the JavaScript.
func IPInCIDR(ip, cidr string) bool {
	addr, ok := parseIP(ip)
	if !ok {
		return false
	}
	prefix, ok := ParseCIDR(cidr)
	return ok && prefix.Contains(addr)
}

// DistanceMeters is the great-circle (haversine) distance between two points in meters.
func DistanceMeters(lat1, lon1, lat2, lon2 float64) float64 {
	rad := func(d float64) float64 { return d * math.Pi / 180 }
	const R = 6371008.8
	dLat := rad(lat2 - lat1)
	dLon := rad(lon2 - lon1)
	sLat, sLon := math.Sin(dLat/2), math.Sin(dLon/2)
	h := sLat*sLat + math.Cos(rad(lat1))*math.Cos(rad(lat2))*sLon*sLon
	return 2 * R * math.Asin(math.Min(1, math.Sqrt(h)))
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

func checkKeys(value any, allowed map[string]bool, path string, errs *[]string) bool {
	o, ok := asObject(value)
	if !ok {
		*errs = append(*errs, path+" must be an object")
		return false
	}
	for _, k := range o.Keys() {
		if !allowed[k] {
			*errs = append(*errs, path+"."+k+" is not a known constraint")
		}
	}
	return true
}

func checkStringList(value any, path string, errs *[]string, max int, test func(string) bool, message string) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 || len(list) > max {
		*errs = append(*errs, fmt.Sprintf("%s must be a list of 1–%d entries", path, max))
		return
	}
	for i, item := range list {
		s, ok := item.(string)
		if !ok || !test(s) {
			*errs = append(*errs, fmt.Sprintf("%s[%d] %s", path, i, message))
		}
	}
}

// ValidateGrant validates one grant (as parsed by ParseJSON) and returns human-readable
// problems, empty when valid. Issuers reject anything invalid; verifiers deny such grants.
func ValidateGrant(grant any, path string) []string {
	errs := []string{}
	if !checkKeys(grant, grantKeys, path, &errs) {
		return errs
	}
	g, _ := asObject(grant)
	actions, _ := g.Get("actions")
	checkStringList(actions, path+".actions", &errs, Limits.Actions, actionPattern.MatchString, `must look like "namespace:verb" or "namespace:*"`)
	if resources, ok := g.Get("resources"); ok {
		checkStringList(resources, path+".resources", &errs, Limits.Resources, func(r string) bool { n := jsLength(r); return n > 0 && n <= Limits.ResourceLength },
			fmt.Sprintf("must be 1–%d characters", Limits.ResourceLength))
	}
	if when, ok := g.Get("when"); ok && checkKeys(when, whenKeys, path+".when", &errs) {
		validateWhen(when, path, &errs)
	}
	if where, ok := g.Get("where"); ok && checkKeys(where, whereKeys, path+".where", &errs) {
		validateWhere(where, path, &errs)
	}
	if limits, ok := g.Get("limits"); ok && checkKeys(limits, limitKeys, path+".limits", &errs) {
		if uses, ok := get(limits, "uses"); ok && checkKeys(uses, usesKeys, path+".limits.uses", &errs) {
			count, _ := get(uses, "count")
			if !isSafeInteger(count) || count.(float64) < 1 || count.(float64) > 1e9 {
				errs = append(errs, path+".limits.uses.count must be an integer from 1 to 1,000,000,000")
			}
			if per, _ := get(uses, "per"); !contains(UsePeriods, per) {
				errs = append(errs, path+".limits.uses.per must be one of "+strings.Join(UsePeriods, ", "))
			}
		}
		if spend, ok := get(limits, "spend_usd_per_month"); ok && !(isFinite(spend) && spend.(float64) >= 0 && spend.(float64) <= 1e6) {
			errs = append(errs, path+".limits.spend_usd_per_month must be a number from 0 to 1,000,000")
		}
	}
	if require, ok := g.Get("require"); ok && checkKeys(require, requireKeys, path+".require", &errs) {
		for _, key := range []string{"online", "step_up", "verified_boot"} {
			if v, ok := get(require, key); ok {
				if _, isBool := v.(bool); !isBool {
					errs = append(errs, path+".require."+key+" must be true or false")
				}
			}
		}
		if v, ok := get(require, "attestation"); ok {
			if level, isString := v.(string); !isString || attestationLevels[level] == nil {
				errs = append(errs, path+`.require.attestation must be "hardware" or "strongbox"`)
			}
		}
		validateGates(require, path+".require", &errs)
		if v, ok := get(require, "confirmation"); ok {
			if _, isBool := v.(bool); !isBool {
				errs = append(errs, path+".require.confirmation must be true or false")
			}
		}
		if apps, ok := get(require, "app_ids"); ok {
			checkStringList(apps, path+".require.app_ids", &errs, maxAppIDs, func(a string) bool {
				return len(a) <= 200 && (appIDPattern.MatchString(a) || androidAppIDPattern.MatchString(a))
			}, "must be an app id (Apple TEAMID.bundle.id, or android:<package>:<signing certificate SHA-256, lowercase hex>)")
		}
	}
	return errs
}

func validateGates(require any, path string, errs *[]string) {
	gates, hasGates := get(require, "gates")
	stepUp, _ := get(require, "step_up")
	if hasGates {
		list, ok := gates.([]any)
		if !ok || len(list) == 0 || len(list) > GateLimits.Entries {
			*errs = append(*errs, fmt.Sprintf("%s.gates must be a list of 1–%d gate entries", path, GateLimits.Entries))
		} else {
			for i, entry := range list {
				ep := fmt.Sprintf("%s.gates[%d]", path, i)
				if !checkKeys(entry, gateEntryKeys, ep, errs) {
					continue
				}
				anyValue, _ := get(entry, "any")
				ids, isList := anyValue.([]any)
				valid := isList && len(ids) >= 1 && len(ids) <= GateLimits.Gates
				seen := map[string]bool{}
				for _, id := range ids {
					s, isString := id.(string)
					if !isString || !(s == "owner" || gateIDPattern.MatchString(s)) || seen[s] {
						valid = false
						break
					}
					seen[s] = true
				}
				if !valid {
					*errs = append(*errs, fmt.Sprintf(`%s.any must list 1–%d different gates ("owner" or gate ids like "gate_01JE…")`, ep, GateLimits.Gates))
				}
				if t, ok := get(entry, "timeout_s"); ok && !(isSafeInteger(t) && t.(float64) >= float64(GateLimits.MinTimeout) && t.(float64) <= float64(GateLimits.MaxTimeout)) {
					*errs = append(*errs, fmt.Sprintf("%s.timeout_s must be an integer from %d to %d", ep, GateLimits.MinTimeout, GateLimits.MaxTimeout))
				}
				if o, ok := get(entry, "on_timeout"); ok && !strictEqual(o, "deny") && !strictEqual(o, "allow") {
					*errs = append(*errs, ep+`.on_timeout must be "deny" or "allow"`)
				}
			}
		}
		if strictEqual(stepUp, true) {
			*errs = append(*errs, path+` has both step_up and gates; step_up means gates [{ "any": ["owner"] }], so list "owner" in gates instead`)
		}
	}
	if reuse, ok := get(require, "gates_reuse_s"); ok {
		if !(isSafeInteger(reuse) && reuse.(float64) >= 0 && reuse.(float64) <= float64(GateLimits.MaxReuse)) {
			*errs = append(*errs, fmt.Sprintf("%s.gates_reuse_s must be an integer from 0 to %d", path, GateLimits.MaxReuse))
		}
		if !hasGates && !strictEqual(stepUp, true) {
			*errs = append(*errs, path+".gates_reuse_s needs gates or step_up")
		}
	}
}

// GrantGates returns the gate entries a valid grant requires, with defaults filled in, or nil
// when it requires none. require.step_up: true yields the owner gate it stands for.
func GrantGates(grant any) []GateEntry {
	require, _ := get(normalizeGo(grant), "require")
	if gates, ok := get(require, "gates"); ok {
		if list, isList := gates.([]any); isList {
			out := make([]GateEntry, 0, len(list))
			for _, entry := range list {
				e := GateEntry{TimeoutS: GateLimits.DefaultTimeout, OnTimeout: "deny"}
				ids, _ := get(entry, "any")
				idList, _ := ids.([]any)
				for _, id := range idList {
					s, _ := id.(string)
					e.Any = append(e.Any, s)
				}
				if t, ok := get(entry, "timeout_s"); ok && t != nil {
					if f, isNum := t.(float64); isNum {
						e.TimeoutS = int(f)
					}
				}
				if o, ok := get(entry, "on_timeout"); ok && o != nil {
					if s, isString := o.(string); isString {
						e.OnTimeout = s
					}
				}
				out = append(out, e)
			}
			return out
		}
	}
	if v, _ := get(require, "step_up"); strictEqual(v, true) {
		return []GateEntry{{Any: []string{"owner"}, TimeoutS: 600, OnTimeout: "deny"}}
	}
	return nil
}

func validateWhen(when any, path string, errs *[]string) {
	tz, _ := get(when, "tz")
	nb, hasNB := get(when, "not_before")
	na, hasNA := get(when, "not_after")
	if windows, ok := get(when, "windows"); ok {
		if _, valid := loadZone(tz); !valid {
			*errs = append(*errs, path+".when.tz must be an IANA time zone when windows are given")
		}
		list, isList := windows.([]any)
		if !isList || len(list) == 0 || len(list) > Limits.Windows {
			*errs = append(*errs, fmt.Sprintf("%s.when.windows must be a list of 1–%d windows", path, Limits.Windows))
		} else {
			for i, w := range list {
				wp := fmt.Sprintf("%s.when.windows[%d]", path, i)
				if !checkKeys(w, windowKeys, wp, errs) {
					continue
				}
				if days, ok := get(w, "days"); ok {
					dl, isList := days.([]any)
					bad := !isList || len(dl) == 0
					for _, d := range dl {
						if !contains(Days, d) {
							bad = true
						}
					}
					if bad {
						*errs = append(*errs, wp+".days must list days from "+strings.Join(Days, ", "))
					}
				}
				from, _ := get(w, "from")
				to, _ := get(w, "to")
				// Window times must be strings: ["08:00"] is invalid (as in the JS evaluator).
				if !isTimeString(from) || strictEqual(from, "24:00") {
					*errs = append(*errs, wp+".from must be HH:MM (00:00–23:59)")
				}
				if !isTimeString(to) {
					*errs = append(*errs, wp+".to must be HH:MM (00:00–24:00)")
				}
				if strictEqual(from, to) {
					*errs = append(*errs, wp+" from and to must differ")
				}
			}
		}
	} else if _, hasTZ := get(when, "tz"); hasTZ {
		if _, valid := loadZone(tz); !valid {
			*errs = append(*errs, path+".when.tz must be an IANA time zone")
		}
	}
	if hasNB && !isSafeInteger(nb) {
		*errs = append(*errs, path+".when.not_before must be a NumericDate (seconds)")
	}
	if hasNA && !isSafeInteger(na) {
		*errs = append(*errs, path+".when.not_after must be a NumericDate (seconds)")
	}
	if isSafeInteger(nb) && isSafeInteger(na) && nb.(float64) >= na.(float64) {
		*errs = append(*errs, path+".when.not_before must be earlier than not_after")
	}
}

// nullishString is `value ?? ""` (an empty string) followed by the String() coercion RegExp.test applies.
func isTimeString(v any) bool {
	s, ok := v.(string)
	return ok && timePattern.MatchString(s)
}

func nullishString(v any) string {
	if v == nil {
		return ""
	}
	return jsToString(v)
}

func validateWhere(where any, path string, errs *[]string) {
	source, _ := get(where, "source")
	if !contains([]string{"network", "device", "both"}, source) {
		*errs = append(*errs, path+`.where.source must be "network", "device" or "both"`)
	}
	countries, hasCountries := get(where, "countries")
	regions, hasRegions := get(where, "regions")
	areas, hasAreas := get(where, "areas")
	networks, hasNetworks := get(where, "networks")
	if hasCountries {
		checkStringList(countries, path+".where.countries", errs, Limits.Places, countryPattern.MatchString, `must be an ISO 3166-1 alpha-2 code like "US"`)
	}
	if hasRegions {
		checkStringList(regions, path+".where.regions", errs, Limits.Places, regionPattern.MatchString, `must be an ISO 3166-2 code like "US-MO"`)
	}
	if hasAreas {
		list, isList := areas.([]any)
		if !isList || len(list) == 0 || len(list) > Limits.Places {
			*errs = append(*errs, fmt.Sprintf("%s.where.areas must be a list of 1–%d areas", path, Limits.Places))
		} else {
			for i, a := range list {
				ap := fmt.Sprintf("%s.where.areas[%d]", path, i)
				if !checkKeys(a, areaKeys, ap, errs) {
					continue
				}
				lat, _ := get(a, "lat")
				lon, _ := get(a, "lon")
				radius, _ := get(a, "radius_m")
				if !(isFinite(lat) && lat.(float64) >= -90 && lat.(float64) <= 90) {
					*errs = append(*errs, ap+".lat must be between -90 and 90")
				}
				if !(isFinite(lon) && lon.(float64) >= -180 && lon.(float64) <= 180) {
					*errs = append(*errs, ap+".lon must be between -180 and 180")
				}
				if !(isFinite(radius) && radius.(float64) >= 10 && radius.(float64) <= 20037508) {
					*errs = append(*errs, ap+".radius_m must be between 10 and 20,037,508")
				}
			}
		}
	}
	if hasNetworks {
		checkStringList(networks, path+".where.networks", errs, Limits.Networks, func(n string) bool { _, ok := ParseCIDR(n); return ok }, `must be a CIDR range like "203.0.113.0/24"`)
	}
	if !hasCountries && !hasRegions && !hasAreas && !hasNetworks {
		*errs = append(*errs, path+".where needs at least one of countries, regions, areas or networks")
	}
	if strictEqual(source, "device") && (truthy(countries) || truthy(regions) || truthy(networks)) {
		*errs = append(*errs, path+`.where with source "device" can only use areas (a device reports coordinates, not countries or networks)`)
	}
}

// ValidateGrants validates a grant list.
func ValidateGrants(grants any) []string {
	list, ok := grants.([]any)
	if !ok || len(list) == 0 || len(list) > Limits.Grants {
		return []string{fmt.Sprintf("grants must be a list of 1–%d grants", Limits.Grants)}
	}
	errs := []string{}
	for i, g := range list {
		errs = append(errs, ValidateGrant(g, fmt.Sprintf("grants[%d]", i))...)
	}
	return errs
}

// LocalTime is a weekday (0 = Sunday) and minutes since local midnight.
type LocalTime struct{ Day, Minutes int }

// LocalTimeAt converts an instant to local weekday and minute in a zone.
func LocalTimeAt(now int64, loc *time.Location) LocalTime {
	t := time.Unix(now, 0).In(loc)
	return LocalTime{Day: int(t.Weekday()), Minutes: t.Hour()*60 + t.Minute()}
}

// minutes parses "HH:MM". A non-string (which only an array can be after validation, through
// JavaScript's String() coercion) is NaN, as Number() of an array slice is in JavaScript.
func minutes(v any) float64 {
	s, ok := v.(string)
	if !ok || len(s) < 4 {
		return math.NaN()
	}
	h, err1 := strconv.Atoi(s[:2])
	m, err2 := strconv.Atoi(s[3:])
	if err1 != nil || err2 != nil {
		return math.NaN()
	}
	return float64(h*60 + m)
}

// inWindow reports whether a local time is inside a window. An overnight window (from > to)
// belongs to the day it starts on, so "mon 22:00–06:00" covers early Tuesday morning.
func inWindow(window any, local LocalTime) bool {
	days, ok := get(window, "days")
	inDays := func(day string) bool {
		if !ok || days == nil {
			return true
		}
		return listIncludes(days, day)
	}
	fromV, _ := get(window, "from")
	toV, _ := get(window, "to")
	from := minutes(fromV)
	to := minutes(toV)
	if strictEqual(toV, "24:00") {
		to = 1440
	}
	today := Days[local.Day]
	yesterday := Days[(local.Day+6)%7]
	m := float64(local.Minutes)
	if from < to {
		return inDays(today) && m >= from && m < to
	}
	return (inDays(today) && m >= from) || (inDays(yesterday) && m < to)
}

// NetworkLocation is what the verifier observed about the connection. Empty strings and nil
// coordinates mean unknown.
type NetworkLocation struct {
	Country string   `json:"country,omitempty"`
	Region  string   `json:"region,omitempty"` // ISO 3166-2, e.g. "US-MO"
	Lat     *float64 `json:"lat,omitempty"`
	Lon     *float64 `json:"lon,omitempty"`
	IP      string   `json:"ip,omitempty"`
}

// DeviceLocation is the device-reported "loc" claim of a verified DPoP proof. Nil fields were
// absent or not numbers.
type DeviceLocation struct {
	Lat  *float64 `json:"lat,omitempty"`
	Lon  *float64 `json:"lon,omitempty"`
	AccM *float64 `json:"acc_m,omitempty"`
	T    *float64 `json:"t,omitempty"`
}

// DeviceLocationFromClaim converts a proof's loc claim. A falsy claim (absent, null, 0, "")
// is no location; any other value is a location whose non-numeric members are unknown.
func DeviceLocationFromClaim(v any) *DeviceLocation {
	if !truthy(v) {
		return nil
	}
	num := func(key string) *float64 {
		x, _ := get(v, key)
		if f, ok := x.(float64); ok {
			return &f
		}
		return nil
	}
	return &DeviceLocation{Lat: num("lat"), Lon: num("lon"), AccM: num("acc_m"), T: num("t")}
}

// Location carries both location sources.
type Location struct {
	Network *NetworkLocation `json:"network,omitempty"`
	Device  *DeviceLocation  `json:"device,omitempty"`
}

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

func finite(p *float64) bool { return p != nil && !math.IsNaN(*p) && !math.IsInf(*p, 0) }

func placeMatches(where any, lat, lon, accM *float64, country, region string, kind string) bool {
	if kind == "network" {
		if countries, _ := get(where, "countries"); country != "" && listIncludes(countries, country) {
			return true
		}
		if regions, _ := get(where, "regions"); region != "" && listIncludes(regions, region) {
			return true
		}
	}
	areas, _ := get(where, "areas")
	if truthy(areas) && finite(lat) && finite(lon) {
		slack := 0.0
		if kind == "device" {
			// Accuracy is held against the device; an unknown or negative accuracy (which would
			// shrink the distance) never matches.
			slack = math.Inf(1)
			if finite(accM) && *accM >= 0 {
				slack = *accM
			}
		}
		list, _ := areas.([]any)
		for _, a := range list {
			alat, _ := get(a, "lat")
			alon, _ := get(a, "lon")
			radius, _ := get(a, "radius_m")
			if DistanceMeters(alat.(float64), alon.(float64), *lat, *lon)+slack <= radius.(float64) {
				return true
			}
		}
		return false
	}
	return false
}

func hasPlaces(where any) bool {
	for _, k := range []string{"countries", "regions", "areas"} {
		if v, _ := get(where, k); truthy(v) {
			return true
		}
	}
	return false
}

func checkNetwork(where any, loc *NetworkLocation, reasons *[]string) {
	if loc == nil {
		*reasons = append(*reasons, "location_unavailable:network")
		return
	}
	if hasPlaces(where) && !placeMatches(where, loc.Lat, loc.Lon, nil, loc.Country, loc.Region, "network") {
		*reasons = append(*reasons, "outside_location:network")
	}
	if networks, _ := get(where, "networks"); truthy(networks) {
		list, _ := networks.([]any)
		matched := false
		for _, n := range list {
			if s, ok := n.(string); ok && IPInCIDR(loc.IP, s) {
				matched = true
				break
			}
		}
		if !matched {
			*reasons = append(*reasons, "network_not_allowed")
		}
	}
}

func checkDevice(where any, loc *DeviceLocation, now int64, reasons *[]string) {
	if loc == nil {
		*reasons = append(*reasons, "location_unavailable:device")
		return
	}
	if !(finite(loc.T) && math.Abs(float64(now)-*loc.T) <= deviceLocationMaxAge) {
		*reasons = append(*reasons, "location_stale:device")
		return
	}
	if hasPlaces(where) && !placeMatches(where, loc.Lat, loc.Lon, loc.AccM, "", "", "device") {
		*reasons = append(*reasons, "outside_location:device")
	}
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
