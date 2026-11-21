package dbaverify

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // grants name IANA zones; do not depend on the host having zoneinfo installed
)

// Time in grants: IANA and fixed-offset zones, and the weekly windows of "when".

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
