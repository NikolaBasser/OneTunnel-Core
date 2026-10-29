package protocol

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestLoyalLargeFileLimit(t *testing.T) {
	data, e := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{{Code: "TEST", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "large.example"}}}}})
	if e != nil {
		t.Fatal(e)
	}
	data = protowire.AppendTag(data, 2, protowire.BytesType)
	data = protowire.AppendBytes(data, make([]byte, 65*1024*1024))
	got, e := ImportLoyalsoldier("geosite", "test", data)
	if e != nil || len(got.DomainSuffix) != 1 {
		t.Fatal("file above old 64 MiB limit rejected", e)
	}
	if _, e = ImportLoyalsoldier("geosite", "test", make([]byte, MaxGeoFileBytes+1)); e == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestLoyalFormats(t *testing.T) {
	site := &geodata.GeoSiteList{Entry: []*geodata.GeoSite{{Code: "TEST", Domain: []*geodata.Domain{
		{Type: geodata.Domain_Full, Value: "exact.example"}, {Type: geodata.Domain_Domain, Value: "suffix.example"},
		{Type: geodata.Domain_Substr, Value: "keyword"}, {Type: geodata.Domain_Regex, Value: `^regex[0-9]+\.example$`},
		{Type: geodata.Domain_Domain, Value: "attribute.example", Attribute: []*geodata.Domain_Attribute{{Key: "cn", TypedValue: &geodata.Domain_Attribute_BoolValue{BoolValue: true}}}},
	}}}}
	bytes, e := proto.Marshal(site)
	if e != nil {
		t.Fatal(e)
	}
	d, e := ImportLoyalsoldier("geosite", "test", bytes)
	if e != nil {
		t.Fatal(e)
	}
	for _, domain := range []string{"exact.example", "a.suffix.example", "has-keyword.example", "regex42.example"} {
		if d.match(RouteQuery{Domain: domain}) != 1 {
			t.Fatal(domain)
		}
	}
	if d.match(RouteQuery{Domain: "sub.exact.example"}) != 0 || d.match(RouteQuery{}) != -1 {
		t.Fatal("exact/unknown semantics")
	}
	attr, e := ImportLoyalsoldier("geosite", "test@cn", bytes)
	if e != nil || len(attr.DomainSuffix) != 1 || attr.DomainSuffix[0] != "attribute.example" {
		t.Fatalf("attribute: %v %v", attr, e)
	}
	ip := &geodata.GeoIPList{Entry: []*geodata.GeoIP{{Code: "TEST", Cidr: []*geodata.CIDR{{Ip: []byte{203, 0, 113, 5}, Prefix: 24}, {Ip: []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Prefix: 32}}}}}
	b, _ := proto.Marshal(ip)
	ips, e := ImportLoyalsoldier("geoip", "test", b)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"203.0.113.99", "2001:db8::123"} {
		if ips.match(RouteQuery{IP: v}) != 1 {
			t.Fatal(v)
		}
	}
	n := &NetworkOptions{RuleSets: []RuleSet{{Name: "loyal-test", Data: d}}, Rules: []NetworkRule{{Kind: "rule-set", Value: "loyal-test", Action: "reject"}}}
	normalized, e := NormalizeNetworkOptions(n)
	if e != nil {
		t.Fatal(e)
	}
	clone := CloneNetworkOptions(normalized)
	clone.RuleSets[0].Data.Domain[0] = "changed.example"
	if normalized.RuleSets[0].Data.Domain[0] != "exact.example" {
		t.Fatal("aliased snapshot")
	}
	prediction, e := ExplainRoute(n, RouteQuery{Domain: "a.suffix.example", Port: 443})
	if e != nil || prediction.Decision != "reject" {
		t.Fatalf("prediction %+v %v", prediction, e)
	}
	config := object{"outbounds": []any{}}
	if e := appendPolicy(config, &Plan{}, normalized); e != nil {
		t.Fatal(e)
	}
	out, _ := json.Marshal(config)
	if !strings.Contains(string(out), "domain_keyword") || !strings.Contains(string(out), "domain_regex") {
		t.Fatal(string(out))
	}
	encoded, e := json.Marshal(normalized)
	if e != nil {
		t.Fatal(e)
	}
	var round NetworkOptions
	if e = json.Unmarshal(encoded, &round); e != nil {
		t.Fatal(e)
	}
	if round.RuleSets[0].Data.match(RouteQuery{Domain: "regex42.example"}) != 1 {
		t.Fatal("snapshot roundtrip")
	}
}

func TestLoyalSnapshotBounds(t *testing.T) {
	for _, raw := range []string{`{"Snapshot":"not-base64"}`, `{"Snapshot":"","Domain":["example.org"]}`, `{"Unexpected":true}`} {
		var d RuleSetData
		if json.Unmarshal([]byte(raw), &d) == nil {
			t.Fatal("accepted invalid snapshot", raw)
		}
	}
	var packed bytes.Buffer
	writer := gzip.NewWriter(&packed)
	writer.Write(bytes.Repeat([]byte{' '}, MaxRuleDataBytes+1))
	writer.Close()
	raw, _ := json.Marshal(struct{ Snapshot []byte }{packed.Bytes()})
	var d RuleSetData
	if json.Unmarshal(raw, &d) == nil {
		t.Fatal("unbounded decompression")
	}
	mixed := &NetworkOptions{RuleSets: []RuleSet{{Name: "mixed", Data: &RuleSetData{Domain: []string{"example.org"}}, Members: []NetworkRule{{Kind: "domain", Value: "example.net"}}}}}
	if _, e := NormalizeNetworkOptions(mixed); e == nil {
		t.Fatal("mixed set representations")
	}
}

func TestLoyalRejectsInvalidWithoutTruncation(t *testing.T) {
	for _, tc := range []struct{ format, category, body string }{
		{"geosite", "test", "bad protobuf"}, {"geoip", "test", "bad protobuf"},
		{"clash-domain", "", "payload:\n - '+.good.example'\n - '*.bad.example'"},
		{"clash-domain", "", "payload:\n - good.example\nother: value"},
		{"clash-ipcidr", "", "payload:\n - '2001:db8::/129'"},
		{"clash-domain", "", "payload: []"}, {"unknown", "", "payload:\n - good.example"},
	} {
		if _, e := ImportLoyalsoldier(tc.format, tc.category, []byte(tc.body)); e == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
	duplicate := &geodata.GeoSiteList{Entry: []*geodata.GeoSite{{Code: "TEST"}, {Code: "test"}}}
	b, _ := proto.Marshal(duplicate)
	if _, e := ImportLoyalsoldier("geosite", "test", b); e == nil {
		t.Fatal("duplicate category")
	}
	reverse := &geodata.GeoIPList{Entry: []*geodata.GeoIP{{Code: "TEST", ReverseMatch: true}}}
	b, _ = proto.Marshal(reverse)
	if _, e := ImportLoyalsoldier("geoip", "test", b); e == nil {
		t.Fatal("inverse lost")
	}
	if _, e := ImportLoyalsoldier("geosite", "missing", b); e == nil {
		t.Fatal("missing category")
	}
	d := &RuleSetData{Domain: []string{"example.org"}, IPCIDR: []string{"203.0.113.0/24"}}
	if e := d.normalize(); e != nil {
		t.Fatal(e)
	}
	if d.match(RouteQuery{Domain: "no.example"}) != -1 || d.match(RouteQuery{Domain: "no.example", IP: "203.0.113.1"}) != 1 {
		t.Fatal("mixed OR/unknown")
	}
	if (&RuleSetData{DomainRegex: []string{"["}}).normalize() == nil {
		t.Fatal("invalid regex")
	}
	if (&RuleSetData{DomainKeyword: []string{strings.Repeat("x", MaxRuleDataBytes+1)}}).normalize() == nil {
		t.Fatal("oversize")
	}
}
