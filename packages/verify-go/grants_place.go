package dbaverify

import (
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Place in grants: IP addresses and CIDR ranges, distances, and the "where" checks against the
// verifier-observed network location and the device-reported location.

// deviceLocationMaxAge is how old (seconds) a device-reported location may be.
const deviceLocationMaxAge = 300

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

// NetworkLocation is what the verifier observed about the connection. Empty strings and nil
// coordinates mean unknown.
type NetworkLocation struct {
	Country string   `json:"country,omitempty"`
	Region  string   `json:"region,omitempty"` // ISO 3166-2, e.g. "US-MO"
	Lat     *float64 `json:"lat,omitempty"`
	Lon     *float64 `json:"lon,omitempty"`
	IP      string   `json:"ip,omitempty"`
	RttMs   *float64 `json:"rtt_ms,omitempty"` // measured round-trip time to the device, for net.client.latency
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
