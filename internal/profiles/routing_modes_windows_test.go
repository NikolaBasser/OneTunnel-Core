package profiles

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestRoutingModeBanks(t *testing.T) {
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Routing", "Manual")
	store := managementStore(t, Document{Profiles: []Profile{p}})
	app := &Application{Store: store}
	fixture := filepath.Join(t.TempDir(), "preset.txt")
	os.WriteFile(fixture, geoSiteFixture(t, "test", "preset.example"), 0600)
	imported, e := importRuleDraft(context.Background(), &NetworkInput{Mode: "default"}, &RuleImportInput{Format: "geosite", Category: "test", Name: "loyal-test", Action: "reject", Path: fixture})
	if e != nil {
		t.Fatal(e)
	}
	input := &NetworkInput{Mode: "https", ServerIP: "1.1.1.1", ServerName: "cloudflare-dns.com", AllowLAN: true, RoutingMode: "custom", CustomRulesText: "domain-suffix | direct | custom.example", PresetRulesText: imported.RulesText}
	save := func(mode string) NetworkPreferencesView {
		t.Helper()
		v, e := app.networkPreferencesView(p.ID)
		if e != nil {
			t.Fatal(e)
		}
		input.RoutingMode = mode
		if _, e = app.saveNetworkPreferences(Request{ID: p.ID, Token: v.Token, NetworkInput: input}); e != nil {
			t.Fatal(e)
		}
		v, e = app.networkPreferencesView(p.ID)
		if e != nil {
			t.Fatal(e)
		}
		input.CustomRulesText, input.PresetRulesText = v.CustomRulesText, v.PresetRulesText
		return v
	}
	for _, mode := range []string{"custom", "preset", "none", "custom", "preset", "none"} {
		view := save(mode)
		if view.RoutingMode != mode || view.CustomRulesText == "" || view.PresetRulesText == "" {
			t.Fatal("lost banks", view.RoutingMode)
		}
		doc, e := store.Load()
		if e != nil {
			t.Fatal(e)
		}
		n := doc.Profiles[0].Network
		if n == nil || n.DNS.ServerIP != "1.1.1.1" || n.AllowLAN != (mode != "none") || !view.AllowLAN {
			t.Fatal("routing switch changed DNS/LAN")
		}
		custom, e := protocol.ExplainRoute(n, protocol.RouteQuery{Domain: "a.custom.example", IP: "203.0.113.8", Port: 443})
		if e != nil {
			t.Fatal(e)
		}
		preset, e := protocol.ExplainRoute(n, protocol.RouteQuery{Domain: "a.preset.example", IP: "203.0.113.8", Port: 443})
		if e != nil {
			t.Fatal(e)
		}
		expectedCustom, expectedPreset := "proxy", "proxy"
		if mode == "custom" {
			expectedCustom = "direct"
		}
		if mode == "preset" {
			expectedPreset = "reject"
		}
		if custom.Decision != expectedCustom || preset.Decision != expectedPreset {
			t.Fatalf("mode=%s custom=%+v preset=%+v", mode, custom, preset)
		}
		if mode == "none" && len(n.Rules)+len(n.Targets)+len(n.RuleSets) != 0 {
			t.Fatal("inactive rules reached runtime")
		}
		plan, e := protocol.CompileWithNetwork(p.Source, p.Protocol, true, 18001, 18002, "unused", nil, n)
		if e != nil {
			t.Fatal(e)
		}
		if mode != "custom" && strings.Contains(plan.Proxy, "custom.example") || mode != "preset" && strings.Contains(plan.Proxy, "preset.example") {
			t.Fatal("compiler included inactive bank", mode)
		}
	}
	view, _ := app.networkPreferencesView(p.ID)
	before := storeBytes(t, store)
	for _, bad := range []NetworkInput{
		{Mode: "default", RoutingMode: "invalid"},
		{Mode: "default", RoutingMode: "none", CustomRulesText: "broken draft"},
		{Mode: "default", RoutingMode: "preset", PresetRulesText: "domain | direct | custom.example"},
	} {
		if _, e := app.saveNetworkPreferences(Request{ID: p.ID, Token: view.Token, NetworkInput: &bad}); e == nil {
			t.Fatal("accepted invalid mode/bank")
		}
	}
	if !bytes.Equal(before, storeBytes(t, store)) {
		t.Fatal("invalid save changed store")
	}
	doc, _ := store.Load()
	wire, _ := json.Marshal(presentationDocument(doc))
	if strings.Contains(string(wire), "RoutingProfiles") {
		t.Fatal("private banks leaked in metadata")
	}
	// Duplicating and portable replacement retain both inactive banks and selection.
	org, e := app.profileOrganization(p.ID)
	if e != nil {
		t.Fatal(e)
	}
	copy, e := app.duplicateProfile(p.ID, "Routing copy", "Manual", org.Token)
	if e != nil {
		t.Fatal(e)
	}
	cloned, e := app.networkPreferencesView(copy.Selected.ID)
	if e != nil || cloned.RoutingMode != view.RoutingMode || cloned.CustomRulesText != view.CustomRulesText || cloned.PresetRulesText != view.PresetRulesText {
		t.Fatal("copy lost inactive banks", e)
	}
	backup := filepath.Join(t.TempDir(), "routing.otbackup")
	if _, e = app.exportBackup(backup, "routing-modes-test-password"); e != nil {
		t.Fatal(e)
	}
	restored := managementStore(t, Document{})
	target := &Application{Store: restored}
	preview, e := target.previewBackupRestore(backup, "routing-modes-test-password")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = target.applyBackupRestore(preview.Token, false); e != nil {
		t.Fatal(e)
	}
	restoredView, e := target.networkPreferencesView(p.ID)
	if e != nil || restoredView.RoutingMode != "none" || restoredView.CustomRulesText != view.CustomRulesText || restoredView.PresetRulesText != view.PresetRulesText {
		t.Fatal("backup lost inactive routes", e)
	}
	doc.Profiles = nil
	if e = store.Save(doc); e != nil {
		t.Fatal(e)
	}
	doc, e = store.Load()
	if e != nil || len(doc.RoutingProfiles) != 0 {
		t.Fatal("orphaned banks retained", e)
	}
}

func TestRoutingModeLegacyMigration(t *testing.T) {
	qualified := &protocol.NetworkOptions{RuleSets: []protocol.RuleSet{{Name: "loyal-test", Data: &protocol.RuleSetData{Domain: []string{"example.org"}}}}, Rules: []protocol.NetworkRule{{Kind: "rule-set", Value: "loyal-test", Action: "reject", Network: "tcp"}}}
	if inferRouting(qualified) != "custom" {
		t.Fatal("qualified imported rule lost its custom editor")
	}
	if _, e := (RoutingPreferences{Mode: "preset", PresetRulesText: routeText(qualified)}).normalized(); e == nil {
		t.Fatal("manual conditions accepted in preset bank")
	}
	for _, text := range []string{"", "domain | reject | legacy.example"} {
		n, e := (NetworkInput{Mode: "default", RulesText: text}).Parse()
		if e != nil {
			t.Fatal(e)
		}
		p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Legacy", "Manual")
		p.Network = n
		doc := Document{Profiles: []Profile{p}}
		v := routingView(doc, p)
		expected := "none"
		if text != "" {
			expected = "custom"
		}
		if v.Mode != expected || v.CustomRulesText != routeText(n) {
			t.Fatal("legacy policy changed", v)
		}
	}
}

func TestRoutingInactiveBankValidatedBeforeUse(t *testing.T) {
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Inactive", "Manual")
	store := managementStore(t, Document{Profiles: []Profile{p}})
	doc, e := store.Load()
	if e != nil {
		t.Fatal(e)
	}
	doc.RoutingProfiles = map[string]RoutingPreferences{p.ID: {Mode: "none", CustomRulesText: "invalid inactive draft"}}
	overwriteEncryptedDocument(t, store, doc)
	loaded, e := store.Load()
	if e != nil || loaded.Profiles[0].Network != nil {
		t.Fatal("inactive bank affected ordinary runtime metadata", e)
	}
	app := &Application{Store: store}
	if _, e = app.networkPreferencesView(p.ID); e == nil {
		t.Fatal("invalid inactive bank reached editor")
	}
	if e = store.Save(doc); e == nil {
		t.Fatal("invalid inactive bank accepted by save")
	}
	raw, _ := json.Marshal(doc)
	if _, e = decodeBackupDocument(raw); e == nil {
		t.Fatal("invalid inactive bank accepted by backup")
	}
}
