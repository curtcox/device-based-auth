package dbaverify

import (
	"reflect"
	"strings"
	"testing"
)

// Unit checks ported from packages/verify/src/net.test.js. Evaluation is covered by the "net: …"
// cases of spec/vectors/evaluation.json and the net cases of testdata/crosscheck.json.

func mustParse(t *testing.T, s string) any {
	t.Helper()
	v, err := ParseJSON([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNetValidAcceptsEverySourceAndRule(t *testing.T) {
	grant := mustParse(t, `{"actions":["hashbin:content:write"],"net":{
		"client":{"addresses":{"of":"origin","cidrs":["203.0.113.0/24"],"lists":[{"id":"adl_OFFICE0001","uri":"https://status.devicebasedauth.org/v1/addresses/adl_OFFICE0001"}],"dns":{"names":["vpn.example.com"],"dnssec":true},"webhook":"gate_ADDRHOOK1"},
		          "route":{"relays":["dev_RELAYHQ001"],"min_hops":1,"max_hops":2,"require_attested":true},"latency":{"max_rtt_ms":40,"samples":3,"reuse_s":60}},
		"server":{"addresses":{"cidrs":["198.51.100.0/24"]},"route":{"relays":["dev_RELAYHQ001"]},"latency":{"max_rtt_ms":80}}}}`)
	if errs := ValidateGrant(grant, "grant"); len(errs) != 0 {
		t.Errorf("errors = %q", errs)
	}
}

// netValidationTable holds [net as JSON, validateGrant errors] recorded from the JavaScript.
const netValidationTable = `[["{\"client\":{\"addresses\":{}}}",["grant.net.client.addresses needs at least one of cidrs, lists, dns or webhook"]],["{\"server\":{\"addresses\":{\"of\":\"origin\",\"cidrs\":[\"10.0.0.0/8\"]},\"route\":{\"relays\":[\"dev_RELAYHQ001\"]}}}",["grant.net.server.addresses.of \"origin\" is only for net.client (a device sees the server's address directly)"]],["{\"client\":{\"addresses\":{\"cidrs\":[\"10.0.0.0/8\",\"10.0.0.0/8\"]}}}",["grant.net.client.addresses.cidrs has duplicates"]],["{\"client\":{\"addresses\":{\"lists\":[{\"uri\":\"https://a.example/x\"},\"x\",null]}}}",["grant.net.client.addresses.lists[0] must be { id: \"adl_…\", uri: \"https://…\" }","grant.net.client.addresses.lists[1] must be { id: \"adl_…\", uri: \"https://…\" }","grant.net.client.addresses.lists[2] must be { id: \"adl_…\", uri: \"https://…\" }","grant.net.client.addresses.lists names a list twice"]],["{\"client\":{\"addresses\":{\"of\":\"x\",\"dns\":{\"names\":[\"Example.com\",\"a.b\"],\"dnssec\":1},\"webhook\":\"nope\"}}}",["grant.net.client.addresses.of must be \"peer\" or \"origin\"","grant.net.client.addresses.dns.names[0] must be a lower-case host name like \"vpn.example.com\"","grant.net.client.addresses.dns.dnssec must be true or false","grant.net.client.addresses.webhook must be a webhook gate id like \"gate_…\""]],["{\"client\":{\"addresses\":{\"of\":\"origin\",\"dns\":[]}}}",["grant.net.client.addresses.of \"origin\" needs a route: the first relay records the device's address","grant.net.client.addresses.dns must be an object"]],["{\"client\":{\"route\":{\"relays\":[],\"min_hops\":0,\"max_hops\":5,\"require_attested\":\"yes\"}}}",["grant.net.client.route.relays must be a list of 1–16 entries","grant.net.client.route.min_hops must be an integer 1–4","grant.net.client.route.max_hops must be an integer 1–4","grant.net.client.route.require_attested must be true or false"]],["{\"client\":{\"route\":{\"relays\":[\"dev_RELAYHQ001\",\"dev_RELAYHQ001\"],\"min_hops\":3,\"max_hops\":2}},\"server\":[]}",["grant.net.client.route.relays has duplicates","grant.net.client.route.min_hops must not exceed max_hops","grant.net.server must be an object"]],["{\"client\":{\"latency\":{\"samples\":null,\"reuse_s\":1.5}}}",["grant.net.client.latency.max_rtt_ms must be an integer 1–5000","grant.net.client.latency.samples must be an integer 1–5","grant.net.client.latency.reuse_s must be an integer 0–300"]],["{\"client\":{\"latency\":\"x\"},\"server\":{\"addresses\":{\"webhook\":\"gate_ADDRHOOK1\"}},\"zeta\":1}",["grant.net.zeta is not allowed","grant.net.client.latency must be an object","grant.net.server.addresses.webhook is only for net.client (devicebasedauth.org asks the webhook during online authorization)"]],["{}",["grant.net needs client or server"]],["null",["grant.net must be an object"]]]`

func TestNetValidationMessagesMatchJavaScript(t *testing.T) {
	for _, row := range mustParse(t, netValidationTable).([]any) {
		pair := row.([]any)
		grant := mustParse(t, `{"actions":["hashbin:content:write"],"net":`+pair[0].(string)+`}`)
		want := []string{}
		for _, e := range pair[1].([]any) {
			want = append(want, e.(string))
		}
		if got := ValidateGrant(grant, "grant"); !reflect.DeepEqual(got, want) {
			t.Errorf("net %s:\n got  %q\n want %q", pair[0], got, want)
		}
	}
	grant := mustParse(t, `{"actions":["hashbin:content:write"],"net":{"client":{"latency":{"max_rtt_ms":4,"extra":1}}}}`)
	if got := ValidateGrant(grant, "grant"); !reflect.DeepEqual(got, []string{"grant.net.client.latency.extra is not allowed"}) {
		t.Errorf("unknown member: %q", got)
	}
}

func TestValidHostName(t *testing.T) {
	for name, want := range map[string]bool{
		"vpn-egress.example.com": true, "localhost": false, "Example.com": false, "192.0.2.1": false,
		"-bad.example.com": false, strings.Repeat("a", 64) + ".com": false, "a.b1": true,
	} {
		if got := ValidHostName(name); got != want {
			t.Errorf("ValidHostName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestSameIP(t *testing.T) {
	if !SameIP("2001:db8::1", "2001:DB8:0:0::1") {
		t.Error("same IPv6 address written two ways")
	}
	if SameIP("192.0.2.1", "::ffff:192.0.2.1") {
		t.Error("an IPv4 address matched its IPv4-mapped IPv6 form")
	}
	if SameIP("nope", "nope") {
		t.Error("non-addresses matched")
	}
}

func TestCredentialsUsingNetCarryVocabulary2(t *testing.T) {
	const netGrant = `{"actions":["hashbin:content:write"],"net":{"client":{"latency":{"max_rtt_ms":40}}}}`
	const plain = `{"actions":["hashbin:content:write"]}`
	payload := func(grant string, ver string) *Object {
		return mustParse(t, `{"iss":"https://devicebasedauth.org","sub":"dev_ABCDEFGH12","acct":"acct_1","aud":["hashbin.org"],"cid":"crd_ABCDEFGH12","jti":"crd_ABCDEFGH12.1","iat":1,"nbf":1,"exp":2,"cnf":{"jkt":"x"},"status":{"status_list":{"idx":0,"uri":"u"}},"grants":[`+grant+`],"ver":`+ver+`}`).(*Object)
	}
	if !GrantsNeedVersion2(mustParse(t, "["+netGrant+"]")) || GrantsNeedVersion2(mustParse(t, "["+plain+"]")) {
		t.Error("GrantsNeedVersion2")
	}
	for _, c := range []struct {
		grant, ver string
		want       []string
	}{
		{netGrant, "2", []string{}},
		{plain, "2", []string{}},
		{plain, "1", []string{}},
		{netGrant, "1", []string{"ver must be 2 when a grant uses net"}},
		{plain, "3", []string{"ver must be 1 or 2"}},
		{plain, "\"2\"", []string{"ver must be 1 or 2"}},
	} {
		if got := ValidateCredentialPayload(payload(c.grant, c.ver), CredentialTyp); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ver %s with %s: %q, want %q", c.ver, c.grant, got, c.want)
		}
	}
}

func TestNetFromGoValues(t *testing.T) {
	// Go callers may pass literal maps in the resolved context.
	grant := mustParse(t, `{"actions":["a:b"],"net":{"client":{"addresses":{"dns":{"names":["vpn.example.com"]}},"route":{"relays":["dev_RELAYHQ001"]},"latency":{"max_rtt_ms":40}}}}`)
	rtt := 12.0
	r := EvaluateGrants([]any{grant}, Context{
		Now: 1, Action: "a:b", Location: Location{Network: &NetworkLocation{IP: "2001:db8::1", RttMs: &rtt}},
		DNS:   map[string]any{"vpn.example.com": map[string]any{"addrs": []string{"2001:DB8:0::1"}}},
		Route: map[string]any{"relays": []string{"dev_RELAYHQ001"}},
	})
	if !r.Allow {
		t.Errorf("reasons = %q", r.Reasons)
	}
	r = EvaluateGrants([]any{mustParse(t, `{"actions":["a:b"],"net":{"client":{"addresses":{"cidrs":["10.0.0.0/8"],"webhook":"gate_ADDRHOOK1"}}}}`)},
		Context{Now: 1, Action: "a:b", Location: Location{Network: &NetworkLocation{IP: "1.2.3.4"}}})
	if r.Allow || !r.OnlineRequired || r.Results[0].Online.AddressWebhook != "gate_ADDRHOOK1" {
		t.Errorf("offline webhook: %+v", r)
	}
}
