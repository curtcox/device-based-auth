package dbaverify

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Object is a JSON object that remembers its members the way a JavaScript object does.
//
// Credentials and grants are untrusted JSON, and the JavaScript evaluator reports problems in
// Object.keys order (array-index-like keys first, ascending, then the rest in insertion order).
// A Go map would lose that order and could also not tell an absent member from a null one,
// which the evaluator distinguishes (`when: null` is invalid, an absent `when` is not).
type Object struct {
	order  []string
	values map[string]any
}

// NewObject builds an Object from alternating key, value pairs. It is a convenience for tests
// and for callers constructing payloads in Go.
func NewObject(pairs ...any) *Object {
	o := &Object{values: map[string]any{}}
	for i := 0; i+1 < len(pairs); i += 2 {
		o.Set(pairs[i].(string), pairs[i+1])
	}
	return o
}

// Get returns a member and whether it is present (a present member may be nil, i.e. JSON null).
func (o *Object) Get(key string) (any, bool) {
	if o == nil {
		return nil, false
	}
	v, ok := o.values[key]
	return v, ok
}

// Has reports whether the member is present.
func (o *Object) Has(key string) bool { _, ok := o.Get(key); return ok }

// Set adds or replaces a member. Like JavaScript, replacing keeps the original position.
// Go integers, []string and map[string]any values are stored as ParseJSON would produce them.
func (o *Object) Set(key string, value any) {
	if o.values == nil {
		o.values = map[string]any{}
	}
	if _, ok := o.values[key]; !ok {
		o.order = append(o.order, key)
	}
	o.values[key] = normalizeGo(value)
}

// Len is the number of members.
func (o *Object) Len() int {
	if o == nil {
		return 0
	}
	return len(o.order)
}

// Keys returns the member names in JavaScript Object.keys order.
func (o *Object) Keys() []string {
	if o == nil {
		return nil
	}
	var indexes, rest []string
	for _, k := range o.order {
		if isArrayIndex(k) {
			indexes = append(indexes, k)
		} else {
			rest = append(rest, k)
		}
	}
	sort.Slice(indexes, func(i, j int) bool {
		a, _ := strconv.ParseUint(indexes[i], 10, 64)
		b, _ := strconv.ParseUint(indexes[j], 10, 64)
		return a < b
	})
	return append(indexes, rest...)
}

// MarshalJSON writes the object with its members in JavaScript order.
func (o *Object) MarshalJSON() ([]byte, error) { return []byte(jsonStringify(o)), nil }

// UnmarshalJSON lets an Object be a field of a struct decoded with encoding/json.
func (o *Object) UnmarshalJSON(data []byte) error {
	v, err := ParseJSON(data)
	if err != nil {
		return err
	}
	obj, ok := v.(*Object)
	if !ok {
		return errors.New("dbaverify: expected a JSON object")
	}
	*o = *obj
	return nil
}

// isArrayIndex matches the keys JavaScript orders first: canonical integers 0..2^32-2.
func isArrayIndex(k string) bool {
	if k == "" || len(k) > 10 || (len(k) > 1 && k[0] == '0') {
		return false
	}
	for _, c := range k {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(k, 10, 64)
	return err == nil && n < math.MaxUint32
}

// ParseJSON decodes JSON the way JSON.parse does: objects become *Object, arrays []any,
// numbers float64 (JavaScript has no other number type, and the evaluator's integer checks
// are Number.isSafeInteger on doubles), strings, booleans and nil.
func ParseJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("dbaverify: trailing data after JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := &Object{values: map[string]any{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, errors.New("dbaverify: invalid object key")
				}
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				o.Set(key, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return o, nil
		case '[':
			list := []any{}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return list, nil
		}
		return nil, errors.New("dbaverify: unexpected delimiter")
	case json.Number:
		// Out-of-range numbers become ±Inf, as in JavaScript.
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return nil, err
		}
		return f, nil
	default:
		return t, nil // string, bool or nil
	}
}

// jsonStringify serializes like JSON.stringify: no HTML escaping, JavaScript number format,
// object members in Object.keys order. The JWK thumbprint hashes this output, so it must match
// byte for byte.
func jsonStringify(v any) string {
	var b strings.Builder
	writeJSON(&b, v)
	return b.String()
}

func writeJSON(b *strings.Builder, v any) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case float64:
		b.WriteString(jsNumberString(t))
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case string:
		writeJSONString(b, t)
	case []any:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSON(b, item)
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(b, item)
		}
		b.WriteByte(']')
	case *Object:
		if t == nil {
			b.WriteString("null")
			return
		}
		b.WriteByte('{')
		for i, k := range t.Keys() {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(b, k)
			b.WriteByte(':')
			writeJSON(b, t.values[k])
		}
		b.WriteByte('}')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		o := &Object{}
		for _, k := range keys {
			o.Set(k, t[k])
		}
		writeJSON(b, o)
	default:
		// Typed Go values (structs, other numeric types): fall back to encoding/json, then
		// re-read so the output still follows JavaScript formatting.
		raw, err := json.Marshal(t)
		if err != nil {
			b.WriteString("null")
			return
		}
		parsed, err := ParseJSON(raw)
		if err != nil {
			b.WriteString("null")
			return
		}
		writeJSON(b, parsed)
	}
}

func writeJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteString(strconv.FormatInt(int64(r)>>4, 16))
				b.WriteString(strconv.FormatInt(int64(r)&15, 16))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// jsNumberString formats a double like Number.prototype.toString.
func jsNumberString(f float64) string {
	switch {
	case math.IsNaN(f) || math.IsInf(f, 0):
		return "null" // JSON.stringify writes non-finite numbers as null
	case f == 0:
		return "0"
	}
	abs := math.Abs(f)
	if abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	s := strconv.FormatFloat(f, 'e', -1, 64) // e.g. 1e+21, 1e-07
	mantissa, exp, _ := strings.Cut(s, "e")
	sign := exp[0]
	digits := strings.TrimLeft(exp[1:], "0")
	return mantissa + "e" + string(sign) + digits
}

// jsLength is String.prototype.length: UTF-16 code units, not bytes.
func jsLength(s string) int {
	n := 0
	for _, r := range s {
		l := utf16.RuneLen(r)
		if l < 0 {
			l = 1
		}
		n += l
	}
	return n
}

// truthy is JavaScript truthiness for parsed JSON values.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case float64:
		return t != 0 && !math.IsNaN(t)
	case string:
		return t != ""
	}
	return true
}

// strictEqual is === for parsed JSON values: objects and arrays are equal only to themselves,
// which for freshly parsed values means never.
func strictEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	}
	return false
}

// asObject returns v as an *Object, also accepting map[string]any from Go callers.
func asObject(v any) (*Object, bool) {
	switch t := v.(type) {
	case *Object:
		return t, t != nil
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		o := &Object{values: map[string]any{}}
		for _, k := range keys {
			o.Set(k, t[k])
		}
		return o, true
	}
	return nil, false
}

// normalizeGo converts Go-built values (map[string]any, []string, ints) to the shapes
// ParseJSON produces, so Go callers may pass literal grants.
func normalizeGo(v any) any {
	switch t := v.(type) {
	case map[string]any:
		o, _ := asObject(t)
		return o
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = normalizeGo(item)
		}
		return out
	case []string:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = item
		}
		return out
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case float32:
		return float64(t)
	}
	return v
}

// get reads a member from v when it is an object; absent otherwise (like `value?.key`).
func get(v any, key string) (any, bool) {
	o, ok := asObject(v)
	if !ok {
		return nil, false
	}
	return o.Get(key)
}

// isSafeInteger is Number.isSafeInteger.
func isSafeInteger(v any) bool {
	f, ok := v.(float64)
	return ok && !math.IsInf(f, 0) && f == math.Trunc(f) && math.Abs(f) <= 9007199254740991
}

// isFinite is Number.isFinite (no coercion: only numbers qualify).
func isFinite(v any) bool {
	f, ok := v.(float64)
	return ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

// jsToString is String(value) for parsed JSON values; RegExp.test coerces its argument this way.
func jsToString(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if math.IsNaN(t) {
			return "NaN"
		}
		if math.IsInf(t, 1) {
			return "Infinity"
		}
		if math.IsInf(t, -1) {
			return "-Infinity"
		}
		return jsNumberString(t)
	case string:
		return t
	case []any:
		parts := make([]string, len(t))
		for i, item := range t {
			if item != nil {
				parts[i] = jsToString(item)
			}
		}
		return strings.Join(parts, ",")
	}
	return "[object Object]"
}
