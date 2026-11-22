package dbaverify

import (
	"fmt"
	"strings"
)

// Grant validation: ValidateGrants reports every problem in a grant list as a human-readable
// message, worded exactly as the JavaScript validator words it (members: spec/evaluation.md §3).

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
	validateGrantNet(g, path, &errs)
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
