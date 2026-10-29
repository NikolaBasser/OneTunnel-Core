package profiles

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

func geoSiteFixture(t *testing.T, category, domain string) []byte {
	t.Helper()
	b, e := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{{Code: category, Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: domain}}}}})
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestLoyalDraftImport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if e := os.WriteFile(path, geoSiteFixture(t, "test", "example.org"), 0600); e != nil {
		t.Fatal(e)
	}
	input := &NetworkInput{Mode: "default", RulesText: "domain | direct | before.example"}
	request := &RuleImportInput{Format: "geosite", Category: "test", Name: "loyal-test", Action: "reject", Path: path}
	r, e := importRuleDraft(context.Background(), input, request)
	if e != nil || r.Count != 1 || len(r.SHA256) != 64 {
		t.Fatalf("%+v %v", r, e)
	}
	if input.RulesText != "domain | direct | before.example" {
		t.Fatal("mutated caller draft")
	}
	var policy struct {
		Rules    []protocol.NetworkRule
		RuleSets []protocol.RuleSet
	}
	if json.Unmarshal([]byte(r.RulesText), &policy) != nil || len(policy.Rules) != 2 || policy.Rules[0].Value != "before.example" || policy.Rules[1].Action != "reject" {
		t.Fatal(r.RulesText)
	}
	input.RulesText = r.RulesText
	if _, e = importRuleDraft(context.Background(), input, request); e == nil {
		t.Fatal("silent replacement")
	}
	request.Replace = true
	request.Action = "direct"
	r, e = importRuleDraft(context.Background(), input, request)
	if e != nil {
		t.Fatal(e)
	}
	json.Unmarshal([]byte(r.RulesText), &policy)
	if len(policy.Rules) != 2 || policy.Rules[1].Action != "reject" {
		t.Fatal("replacement changed action/order")
	}
	request.Name = "../bad"
	if _, e = importRuleDraft(context.Background(), input, request); e == nil {
		t.Fatal("invalid name")
	}
	for _, c := range []string{"../../secret", "applications", "proxy?x=1", ""} {
		if _, e := loyalURL("clash-domain", c); e == nil {
			t.Fatal(c)
		}
	}
}

func TestLoyalLiveDownloads(t *testing.T) {
	if os.Getenv("ONETUNNEL_LOYAL_LIVE") != "1" {
		t.Skip("explicit VM network acceptance")
	}
	for _, tc := range []struct{ format, category string }{
		{"geosite", "youtube"}, {"geosite", "category-ads-all"}, {"geoip", "ru"}, {"geoip", "telegram"},
	} {
		t.Run(tc.format+"/"+tc.category, func(t *testing.T) {
			r, e := importRuleDraft(context.Background(), &NetworkInput{Mode: "default"}, &RuleImportInput{Format: tc.format, Category: tc.category, Name: "loyal-test", Action: "proxy", Download: true})
			if e != nil {
				t.Fatal(e)
			}
			if r.Count == 0 || !strings.Contains(r.RulesText, "loyal-test") {
				t.Fatal("empty")
			}
			t.Logf("records=%d snapshot_bytes=%d source_sha256=%s", r.Count, len(r.RulesText), r.SHA256)
		})
	}
}

func TestLoyalLargeCombinedStorage(t *testing.T) {
	if os.Getenv("ONETUNNEL_LOYAL_LIVE") != "1" {
		t.Skip("explicit VM network acceptance")
	}
	input := &NetworkInput{Mode: "default"}
	for i, category := range []string{"category-ads-all", "youtube", "google"} {
		r, e := importRuleDraft(context.Background(), input, &RuleImportInput{Format: "geosite", Category: category, Name: []string{"loyal-ads", "loyal-video", "loyal-search"}[i], Action: []string{"reject", "direct", "proxy"}[i], Download: true})
		if e != nil {
			t.Fatal(e)
		}
		input.RulesText = r.RulesText
	}
	n, e := input.Parse()
	if e != nil || len(n.RuleSets) != 3 {
		t.Fatal(e)
	}
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Loyal snapshot", "Manual")
	p.Network = n
	store := managementStore(t, Document{Profiles: []Profile{p}})
	doc, e := store.Load()
	if e != nil || !protocol.NetworkOptionsEquivalent(doc.Profiles[0].Network, n) {
		t.Fatal("encrypted roundtrip", e)
	}
	app := &Application{Store: store}
	view, e := app.networkPreferencesView(p.ID)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := (&NetworkInput{Mode: view.Mode, RulesText: view.RulesText}).Parse()
	if e != nil || !protocol.NetworkOptionsEquivalent(restored, n) {
		t.Fatal("editor roundtrip", e)
	}
	t.Logf("combined_rules_text_bytes=%d sets=%d", len(view.RulesText), len(n.RuleSets))
}
