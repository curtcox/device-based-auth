package dbaverify

import (
	"encoding/json"
	"os"
	"testing"
)

// TestJavaScriptCrosscheck compares edge cases beyond spec/vectors (JavaScript key order,
// String() coercions, IP parsing quirks, Intl time zone names, WHATWG URL normalization) with
// results recorded from the JavaScript reference by testdata/crosscheck.mjs.
func TestJavaScriptCrosscheck(t *testing.T) {
	data, err := os.ReadFile("testdata/crosscheck.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	cases, _ := get(v, "cases")
	for _, c := range cases.([]any) {
		t.Run(str(c, "name"), func(t *testing.T) {
			grants, _ := get(c, "grants")
			context, _ := get(c, "context")
			expected, _ := get(c, "result")
			r := EvaluateGrants(grants, contextFromVector(context))
			gotMap := map[string]any{"allow": r.Allow, "grant_index": r.GrantIndex, "reasons": r.Reasons, "online_required": r.OnlineRequired}
			if exp, _ := asObject(expected); exp.Has("caveats") {
				gotMap["caveats"] = r.Caveats
			}
			got, _ := json.Marshal(gotMap)
			want, _ := json.Marshal(expected)
			// Re-marshal want through a map so both sides have sorted keys.
			var wantMap map[string]any
			_ = json.Unmarshal(want, &wantMap)
			want, _ = json.Marshal(wantMap)
			if string(got) != string(want) {
				t.Errorf("got  %s\nwant %s", got, want)
			}
		})
	}
	htus, _ := get(v, "htus")
	for _, h := range htus.([]any) {
		pair := h.([]any)
		if got, err := Htu(pair[0].(string)); got != pair[1] {
			t.Errorf("Htu(%q) = %q (%v), want %q", pair[0], got, err, pair[1])
		}
	}
}
