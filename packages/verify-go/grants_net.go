package dbaverify

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// The net grant constraint (vocabulary 2, spec/evaluation.md §3.10): rules about the connection a
// request arrives on rather than the place it comes from. It mirrors packages/verify/src/net.js.
//
// Everything that needs I/O (address lists, DNS answers, relay hops, a timed round trip, a
// customer webhook) is resolved by the verifier first and handed in through the Context, so this
// stays pure. net.server is validated but not evaluated by verifiers: it binds the device's own
// SDK or CLI.

// NetLimits bound the net constraint.
var NetLimits = struct{ CIDRs, Lists, Names, Relays, MaxHops, MaxRttMs, Samples, MaxReuse, URILength int }{64, 8, 16, 16, 4, 5000, 5, 300, 512}

var (
	netKeys       = keySet("client", "server")
	directionKeys = keySet("addresses", "route", "latency")
	addressKeys   = keySet("of", "cidrs", "lists", "dns", "webhook")
	listKeys      = keySet("id", "uri")
	dnsKeys       = keySet("names", "dnssec")
	routeKeys     = keySet("relays", "min_hops", "max_hops", "require_attested")
	latencyKeys   = keySet("max_rtt_ms", "samples", "reuse_s")

	// AddressListIDPattern matches address list ids ("adl_…").
	AddressListIDPattern = regexp.MustCompile(`^adl_[A-Za-z0-9]{8,64}$`)
	deviceIDPattern      = regexp.MustCompile(`^dev_[A-Za-z0-9]{8,64}$`)
	labelPattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	digitsPattern        = regexp.MustCompile(`^\d+$`)
	routeErrorPattern    = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	// The JavaScript LIST_URI (an https URL, or http on loopback for local development), with
	// JavaScript's \s, which unlike Go's includes Unicode spaces.
	listURIPattern = regexp.MustCompile(`^(?:https://[^` + jsSpace + `/]+|http://(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?)/[^` + jsSpace + `]*$`)
)

const jsSpace = `\t\n\v\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

// ValidHostName reports whether name is a lower-case DNS host name with at least two labels and
// a non-numeric last label.
func ValidHostName(name string) bool {
	if jsLength(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 || digitsPattern.MatchString(labels[len(labels)-1]) {
		return false
	}
	for _, l := range labels {
		if !labelPattern.MatchString(l) {
			return false
		}
	}
	return true
}

// SameIP reports whether two strings are the same address however each is written
// ("2001:db8::1", "2001:DB8:0::1"). Address families never match each other.
func SameIP(a, b string) bool {
	x, okX := parseIP(a)
	y, okY := parseIP(b)
	return okX && okY && x == y
}

// sameIPAny is sameIp on JSON values: anything but a string is no address.
func sameIPAny(a string, b any) bool { s, ok := b.(string); return ok && SameIP(a, s) }

func ipInCIDRAny(ip string, cidr any) bool { s, ok := cidr.(string); return ok && IPInCIDR(ip, s) }

func unknownIn(value any, allowed map[string]bool, path string) []string {
	o, ok := asObject(value)
	if !ok {
		return nil
	}
	var out []string
	for _, k := range o.Keys() {
		if !allowed[k] {
			out = append(out, path+"."+k)
		}
	}
	return out
}

// netUnknownKeys returns the paths of members net does not know (each becomes
// unknown_constraint:<path>).
func netUnknownKeys(net any) []string {
	if _, ok := asObject(net); !ok {
		return nil
	}
	paths := unknownIn(net, netKeys, "net")
	for _, side := range []string{"client", "server"} {
		d, _ := get(net, side)
		p := "net." + side
		paths = append(paths, unknownIn(d, directionKeys, p)...)
		if _, ok := asObject(d); !ok {
			continue
		}
		addresses, _ := get(d, "addresses")
		route, _ := get(d, "route")
		latency, _ := get(d, "latency")
		paths = append(paths, unknownIn(addresses, addressKeys, p+".addresses")...)
		paths = append(paths, unknownIn(route, routeKeys, p+".route")...)
		paths = append(paths, unknownIn(latency, latencyKeys, p+".latency")...)
		if _, ok := asObject(addresses); ok {
			dns, _ := get(addresses, "dns")
			paths = append(paths, unknownIn(dns, dnsKeys, p+".addresses.dns")...)
			lists, _ := get(addresses, "lists")
			if list, isList := lists.([]any); isList {
				for i, l := range list {
					paths = append(paths, unknownIn(l, listKeys, fmt.Sprintf("%s.addresses.lists[%d]", p, i))...)
				}
			}
		}
	}
	return paths
}

// setKey is a key under which JavaScript's Set (SameValueZero) treats two JSON values as one:
// primitives by value, objects and arrays never (each is its own value).
func setKey(v any, i int, absent bool) string {
	if absent {
		return "u"
	}
	switch t := v.(type) {
	case nil:
		return "n"
	case bool:
		return fmt.Sprintf("b%t", t)
	case float64:
		if t == 0 {
			t = 0 // -0 and 0 are the same
		}
		return fmt.Sprintf("f%v", t)
	case string:
		return "s" + t
	}
	return fmt.Sprintf("o%d", i)
}

func hasDuplicates(keys []string) bool {
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			return true
		}
		seen[k] = true
	}
	return false
}

func checkNetList(value any, path string, errs *[]string, max int, test func(any) bool, message string) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 || len(list) > max {
		*errs = append(*errs, fmt.Sprintf("%s must be a list of 1–%d entries", path, max))
		return
	}
	keys := make([]string, len(list))
	for i, v := range list {
		keys[i] = setKey(v, i, false)
	}
	if hasDuplicates(keys) {
		*errs = append(*errs, path+" has duplicates")
	}
	for i, v := range list {
		if !test(v) {
			*errs = append(*errs, fmt.Sprintf("%s[%d] %s", path, i, message))
		}
	}
}

func stringTest(test func(string) bool) func(any) bool {
	return func(v any) bool { s, ok := v.(string); return ok && test(s) }
}

// netInt is isInt: a safe integer from min to max.
func netInt(v any, min, max int) bool {
	return isSafeInteger(v) && v.(float64) >= float64(min) && v.(float64) <= float64(max)
}

// nullish is `value ?? fallback` for a member that may be absent or null.
func nullish(v any, ok bool, fallback float64) any {
	if !ok || v == nil {
		return fallback
	}
	return v
}

func validListEntry(l any) bool {
	id, _ := get(l, "id")
	uri, _ := get(l, "uri")
	idS, okID := id.(string)
	uriS, okURI := uri.(string)
	_, isObj := asObject(l)
	return isObj && okID && AddressListIDPattern.MatchString(idS) && okURI && jsLength(uriS) <= NetLimits.URILength && listURIPattern.MatchString(uriS)
}

func validateAddresses(a any, side string, hasRoute bool, path string, errs *[]string) {
	if _, ok := asObject(a); !ok {
		*errs = append(*errs, path+" must be an object")
		return
	}
	of, hasOf := get(a, "of")
	if hasOf && !strictEqual(of, "peer") && !strictEqual(of, "origin") {
		*errs = append(*errs, path+`.of must be "peer" or "origin"`)
	}
	if strictEqual(of, "origin") && side == "server" {
		*errs = append(*errs, path+`.of "origin" is only for net.client (a device sees the server's address directly)`)
	}
	if strictEqual(of, "origin") && !hasRoute {
		*errs = append(*errs, path+`.of "origin" needs a route: the first relay records the device's address`)
	}
	cidrs, hasCIDRs := get(a, "cidrs")
	if hasCIDRs {
		checkNetList(cidrs, path+".cidrs", errs, NetLimits.CIDRs, stringTest(func(c string) bool { _, ok := ParseCIDR(c); return ok }), `must be a CIDR range like "203.0.113.0/24"`)
	}
	lists, hasLists := get(a, "lists")
	if hasLists {
		checkNetList(lists, path+".lists", errs, NetLimits.Lists, validListEntry, `must be { id: "adl_…", uri: "https://…" }`)
		if list, isList := lists.([]any); isList {
			ids := make([]string, len(list))
			for i, l := range list {
				id, ok := get(l, "id")
				ids[i] = setKey(id, i, !ok)
			}
			if hasDuplicates(ids) {
				*errs = append(*errs, path+".lists names a list twice")
			}
		}
	}
	dns, hasDNS := get(a, "dns")
	if hasDNS {
		if _, ok := asObject(dns); !ok {
			*errs = append(*errs, path+".dns must be an object")
		} else {
			names, _ := get(dns, "names")
			checkNetList(names, path+".dns.names", errs, NetLimits.Names, stringTest(ValidHostName), `must be a lower-case host name like "vpn.example.com"`)
			if v, ok := get(dns, "dnssec"); ok {
				if _, isBool := v.(bool); !isBool {
					*errs = append(*errs, path+".dns.dnssec must be true or false")
				}
			}
		}
	}
	webhook, hasWebhook := get(a, "webhook")
	if hasWebhook {
		if side == "server" {
			*errs = append(*errs, path+".webhook is only for net.client (devicebasedauth.org asks the webhook during online authorization)")
		} else if s, ok := webhook.(string); !ok || !gateIDPattern.MatchString(s) {
			*errs = append(*errs, path+`.webhook must be a webhook gate id like "gate_…"`)
		}
	}
	if !hasCIDRs && !hasLists && !hasDNS && !hasWebhook {
		*errs = append(*errs, path+" needs at least one of cidrs, lists, dns or webhook")
	}
}

func validateRoute(r any, path string, errs *[]string) {
	if _, ok := asObject(r); !ok {
		*errs = append(*errs, path+" must be an object")
		return
	}
	relays, _ := get(r, "relays")
	checkNetList(relays, path+".relays", errs, NetLimits.Relays, stringTest(deviceIDPattern.MatchString), `must be a relay device id like "dev_…"`)
	minV, minOK := get(r, "min_hops")
	maxV, maxOK := get(r, "max_hops")
	min, max := nullish(minV, minOK, 1), nullish(maxV, maxOK, float64(NetLimits.MaxHops))
	minValid := netInt(min, 1, NetLimits.MaxHops)
	if !minValid {
		*errs = append(*errs, fmt.Sprintf("%s.min_hops must be an integer 1–%d", path, NetLimits.MaxHops))
	}
	if !netInt(max, 1, NetLimits.MaxHops) {
		*errs = append(*errs, fmt.Sprintf("%s.max_hops must be an integer 1–%d", path, NetLimits.MaxHops))
	} else if minValid && min.(float64) > max.(float64) {
		*errs = append(*errs, path+".min_hops must not exceed max_hops")
	}
	if v, ok := get(r, "require_attested"); ok {
		if _, isBool := v.(bool); !isBool {
			*errs = append(*errs, path+".require_attested must be true or false")
		}
	}
}

func validateLatency(l any, path string, errs *[]string) {
	if _, ok := asObject(l); !ok {
		*errs = append(*errs, path+" must be an object")
		return
	}
	if v, _ := get(l, "max_rtt_ms"); !netInt(v, 1, NetLimits.MaxRttMs) {
		*errs = append(*errs, fmt.Sprintf("%s.max_rtt_ms must be an integer 1–%d", path, NetLimits.MaxRttMs))
	}
	if v, ok := get(l, "samples"); ok && !netInt(v, 1, NetLimits.Samples) {
		*errs = append(*errs, fmt.Sprintf("%s.samples must be an integer 1–%d", path, NetLimits.Samples))
	}
	if v, ok := get(l, "reuse_s"); ok && !netInt(v, 0, NetLimits.MaxReuse) {
		*errs = append(*errs, fmt.Sprintf("%s.reuse_s must be an integer 0–%d", path, NetLimits.MaxReuse))
	}
}

// ValidateNet returns validation errors for a grant's net member (unknown members are reported
// separately, as "<path> is not allowed", by ValidateGrant).
func ValidateNet(net any, path string) []string {
	if _, ok := asObject(net); !ok {
		return []string{path + " must be an object"}
	}
	errs := []string{}
	_, hasClient := get(net, "client")
	_, hasServer := get(net, "server")
	if !hasClient && !hasServer {
		errs = append(errs, path+" needs client or server")
	}
	for _, side := range []string{"client", "server"} {
		d, ok := get(net, side)
		p := path + "." + side
		if !ok {
			continue
		}
		if _, isObj := asObject(d); !isObj {
			errs = append(errs, p+" must be an object")
			continue
		}
		addresses, hasAddresses := get(d, "addresses")
		route, hasRoute := get(d, "route")
		latency, hasLatency := get(d, "latency")
		if !hasAddresses && !hasRoute && !hasLatency {
			errs = append(errs, p+" needs at least one of addresses, route or latency")
		}
		if hasAddresses {
			validateAddresses(addresses, side, hasRoute, p+".addresses", &errs)
		}
		if hasRoute {
			validateRoute(route, p+".route", &errs)
		}
		if hasLatency {
			validateLatency(latency, p+".latency", &errs)
		}
	}
	return errs
}

// validateGrantNet adds the errors of a grant's net member, as validateGrant does.
func validateGrantNet(g *Object, path string, errs *[]string) {
	net, ok := g.Get("net")
	if !ok {
		return
	}
	for _, k := range netUnknownKeys(net) {
		*errs = append(*errs, path+"."+k+" is not allowed")
	}
	*errs = append(*errs, ValidateNet(net, path+".net")...)
}

// GrantsNeedVersion2 reports whether any grant needs vocabulary 2 (uses net).
func GrantsNeedVersion2(grants any) bool {
	list, ok := normalizeGo(grants).([]any)
	if !ok {
		return false
	}
	for _, g := range list {
		if o, isObj := asObject(normalizeGo(g)); isObj && o.Has("net") {
			return true
		}
	}
	return false
}

// checkNetClient checks net.client of a valid grant, adding reasons in the order of
// spec/evaluation.md §3.10. It sets online.AddressWebhook when only the webhook could still allow
// the address.
func checkNetClient(client any, ctx Context, reasons *[]string, online *Online) {
	if !truthy(client) {
		return
	}
	var route any
	if relays, _ := get(ctx.Route, "relays"); func() bool { _, ok := relays.([]any); return ok }() {
		route = ctx.Route
	}
	if a, _ := get(client, "addresses"); truthy(a) {
		var address any
		if of, _ := get(a, "of"); strictEqual(of, "origin") {
			address, _ = get(route, "origin")
		} else if ctx.Location.Network != nil {
			address = ctx.Location.Network.IP
		}
		checkAddresses(a, address, ctx, reasons, online)
	}
	if r, _ := get(client, "route"); truthy(r) {
		if ctx.RouteError != nil {
			e, isString := ctx.RouteError.(string)
			if !isString || !routeErrorPattern.MatchString(e) {
				e = "malformed"
			}
			*reasons = append(*reasons, "route_invalid:"+e)
		} else if route == nil {
			*reasons = append(*reasons, "route_required")
		} else {
			relaysV, _ := get(route, "relays")
			relays := relaysV.([]any)
			hops := float64(len(relays))
			minV, minOK := get(r, "min_hops")
			maxV, maxOK := get(r, "max_hops")
			if hops < nullish(minV, minOK, 1).(float64) || hops > nullish(maxV, maxOK, float64(NetLimits.MaxHops)).(float64) {
				*reasons = append(*reasons, "route_invalid:hop_count")
			}
			if ra, _ := get(r, "require_attested"); truthy(ra) {
				attestedV, _ := get(route, "attested")
				attested, isList := attestedV.([]any)
				ok := isList && len(attested) == len(relays)
				for _, x := range attested {
					ok = ok && strictEqual(x, true)
				}
				if !ok {
					*reasons = append(*reasons, "route_invalid:relay_not_attested")
				}
			}
			allowedRelays, _ := get(r, "relays")
			for _, id := range relays {
				if !listIncludes(allowedRelays, id) {
					*reasons = append(*reasons, "route_relay_not_allowed")
					break
				}
			}
		}
	}
	if l, _ := get(client, "latency"); truthy(l) {
		var rtt *float64
		if ctx.Location.Network != nil {
			rtt = ctx.Location.Network.RttMs
		}
		maxRtt, _ := get(l, "max_rtt_ms")
		if rtt == nil || math.IsNaN(*rtt) || math.IsInf(*rtt, 0) || *rtt < 0 {
			*reasons = append(*reasons, "rtt_required")
		} else if *rtt > maxRtt.(float64) {
			*reasons = append(*reasons, "rtt_exceeded")
		}
	}
}

// ownObject returns obj[key] when it is an object whose member field is a list (JavaScript's
// Object.hasOwn(obj, key) && isObject(obj[key]) && Array.isArray(obj[key][field])), or nil.
func ownObject(obj any, key, field string) any {
	v, ok := get(obj, key)
	if _, isObj := asObject(v); !ok || !isObj {
		return nil
	}
	if f, _ := get(v, field); func() bool { _, isList := f.([]any); return isList }() {
		return v
	}
	return nil
}

func checkAddresses(a any, addressV any, ctx Context, reasons *[]string, online *Online) {
	address, isString := addressV.(string)
	if !isString || address == "" {
		*reasons = append(*reasons, "address_unavailable")
		return
	}
	cidrs, _ := get(a, "cidrs")
	lists, _ := get(a, "lists")
	dns, _ := get(a, "dns")
	names, _ := get(dns, "names")
	dnssec, _ := get(dns, "dnssec")
	cidrList, _ := cidrs.([]any)
	listList, _ := lists.([]any)
	nameList, _ := names.([]any)
	listOf := func(l any) any {
		id, _ := get(l, "id")
		s, _ := id.(string)
		return ownObject(ctx.AddressLists, s, "cidrs")
	}
	answerOf := func(n any) any { s, _ := n.(string); return ownObject(ctx.DNS, s, "addrs") }
	dnsOK := func(answer any) bool {
		v, _ := get(answer, "dnssec")
		return answer != nil && (!strictEqual(dnssec, true) || strictEqual(v, true))
	}
	allowed := false
	for _, c := range cidrList {
		allowed = allowed || ipInCIDRAny(address, c)
	}
	for _, l := range listList {
		if list := listOf(l); list != nil && !allowed {
			c, _ := get(list, "cidrs")
			for _, x := range c.([]any) {
				allowed = allowed || ipInCIDRAny(address, x)
			}
		}
	}
	for _, n := range nameList {
		if answer := answerOf(n); dnsOK(answer) && !allowed {
			addrs, _ := get(answer, "addrs")
			for _, x := range addrs.([]any) {
				allowed = allowed || sameIPAny(address, x)
			}
		}
	}
	if allowed {
		return
	}
	if webhook, _ := get(a, "webhook"); truthy(webhook) {
		// Only devicebasedauth.org can ask the webhook, so offline the grant becomes online-only.
		id := webhook.(string)
		if !ctx.Online {
			online.AddressWebhook = id
			return
		}
		if answer, ok := get(ctx.AddressWebhook, id); ok && strictEqual(answer, true) {
			return
		}
	}
	*reasons = append(*reasons, "address_not_allowed")
	for _, l := range listList {
		if listOf(l) == nil {
			id, _ := get(l, "id")
			*reasons = append(*reasons, "address_list_unavailable:"+jsToString(id))
		}
	}
	for _, n := range nameList {
		name := jsToString(n)
		if answer := answerOf(n); answer == nil {
			*reasons = append(*reasons, "dns_unresolved:"+name)
		} else if !dnsOK(answer) {
			*reasons = append(*reasons, "dns_unvalidated:"+name)
		}
	}
}

// normalizeDeep is normalizeGo applied at every level, so Go callers may pass literal maps and
// slices anywhere in a net constraint or its context.
func normalizeDeep(v any) any {
	switch t := normalizeGo(v).(type) {
	case *Object:
		if t == nil {
			return nil
		}
		o := &Object{values: map[string]any{}}
		for _, k := range t.order {
			x, _ := t.Get(k)
			o.Set(k, normalizeDeep(x))
		}
		return o
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = normalizeDeep(item)
		}
		return out
	default:
		return t
	}
}
