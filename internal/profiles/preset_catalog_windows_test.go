package profiles

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestPresetCatalogConfigurationAndProcessRules(t *testing.T) {
	input := &NetworkInput{Mode: "default"}
	for _, category := range []string{"", "google@@cn", "geoip:"} {
		_, e := importRuleDraft(context.Background(), input, &RuleImportInput{Format: "geosite", Category: category, Name: "test", Action: "proxy", Path: `C:\missing-file.dat`})
		if e == nil || !strings.Contains(e.Error(), "Укажите категорию") || strings.Contains(e.Error(), "rule_import_category") {
			t.Fatal("category was not validated before file read", e)
		}
	}
	for _, bad := range []RuleImportInput{{Format: "geosite", Action: "proxy"}, {Format: "geoip", Category: "ru@cn", Action: "proxy"}, {Format: "clash-domain", Category: "../../secret", Action: "proxy"}} {
		if _, e := configurePresetDraft(input, &bad, false); e == nil {
			t.Fatal("invalid source accepted")
		}
	}
	configured, e := configurePresetDraft(input, &RuleImportInput{Format: "geosite", Category: "geosite:youtube", Action: "proxy"}, false)
	if e != nil {
		t.Fatal(e)
	}
	if len(configured.PresetRows) != 1 || !configured.PresetRows[0].Pending || configured.PresetRows[0].Category != "youtube" || configured.RulesText != "" {
		t.Fatal("configuration fetched or applied rules")
	}
	input.PresetConfigText = configured.PresetConfigText
	selected := configured.PresetRows[0]
	if _, e = configurePresetDraft(input, &RuleImportInput{Format: selected.Format, Category: selected.Category, Name: selected.Name, Action: "direct"}, false); e == nil {
		t.Fatal("silent overwrite")
	}
	changed, e := configurePresetDraft(input, &RuleImportInput{Format: selected.Format, Category: selected.Category, Name: selected.Name, Action: "reject", Replace: true}, false)
	if e != nil || changed.PresetRows[0].Action != "reject" {
		t.Fatal("source edit", e)
	}
	selectedInput := NetworkInput{Mode: "default", RoutingMode: "preset", PresetConfigText: changed.PresetConfigText}
	if _, e = selectedInput.Parse(); e == nil {
		t.Fatal("pending preset saved as active")
	}
	selectedInput.RoutingMode = "none"
	selectedInput.AllowLAN = true
	n, e := selectedInput.Parse()
	if e != nil || n != nil {
		t.Fatal("none applied pending rules or LAN", e)
	}
	removed, e := configurePresetDraft(input, &RuleImportInput{Name: selected.Name}, true)
	if e != nil || removed.PresetConfigText != "" {
		t.Fatal("remove source", e)
	}
	for _, r := range []protocol.NetworkRule{
		{Kind: "domain", Value: "example.org", Action: "direct", Port: "443", Network: "tcp", Process: `C:\Program Files\Browser\browser.exe`},
		{Kind: "process", Value: `C:\Windows\System32\notepad.exe`, Action: "reject"},
		{Kind: "cidr", Value: "2001:db8::/32", Action: "proxy"},
		{Kind: "port", Value: "8000-9000", Action: "direct"},
		{Kind: "network", Value: "udp", Action: "reject"},
	} {
		result, e := appendRuleDraft(input, &r)
		if e != nil {
			t.Fatal(e)
		}
		input.RulesText = result.RulesText
	}
	result, e := appendRuleDraft(input, &protocol.NetworkRule{Kind: "domain", Value: "not valid", Action: "proxy"})
	if e == nil || result.RulesText != "" {
		t.Fatal("invalid rule changed draft")
	}
	parsed, e := input.Parse()
	if e != nil || len(parsed.Rules) != 5 || parsed.Rules[1].Value != `c:\windows\system32\notepad.exe` {
		t.Fatal("process path/conditions", e)
	}
}

func TestPresetCatalogLiveRefreshAndPersistence(t *testing.T) {
	if os.Getenv("ONETUNNEL_LOYAL_LIVE") != "1" {
		t.Skip("explicit VM network acceptance")
	}
	input := &NetworkInput{Mode: "default"}
	for _, source := range []RuleImportInput{{Format: "geosite", Category: "youtube", Action: "proxy"}, {Format: "geoip", Category: "telegram", Action: "proxy"}, {Format: "clash-domain", Category: "reject", Action: "reject"}} {
		r, e := configurePresetDraft(input, &source, false)
		if e != nil {
			t.Fatal(e)
		}
		input.RulesText = r.RulesText
		input.PresetConfigText = r.PresetConfigText
	}
	first, e := refreshPresetDraft(context.Background(), input)
	if e != nil {
		t.Fatal(e)
	}
	if first.Count < 100000 || len(first.PresetRows) != 3 {
		t.Fatal("incomplete refresh")
	}
	input.RulesText = first.RulesText
	input.PresetConfigText = first.PresetConfigText
	second, e := refreshPresetDraft(context.Background(), input)
	if e != nil {
		t.Fatal(e)
	}
	if second.PresetConfigText != first.PresetConfigText || len(second.PresetRows) != 3 {
		t.Fatal("refresh forgot configured sources")
	}
	n, e := input.Parse()
	if e != nil || len(n.RuleSets) != 3 {
		t.Fatal(e)
	}
	for _, r := range second.PresetRows {
		if r.Pending {
			t.Fatal("refresh left pending source")
		}
	}
	profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Catalog", "Manual")
	store := managementStore(t, Document{Profiles: []Profile{profile}})
	app := &Application{Store: store}
	v, _ := app.networkPreferencesView(profile.ID)
	save := &NetworkInput{Mode: "default", RoutingMode: "preset", PresetRulesText: second.RulesText, PresetConfigText: second.PresetConfigText}
	if _, e = app.saveNetworkPreferences(Request{ID: profile.ID, Token: v.Token, NetworkInput: save}); e != nil {
		t.Fatal(e)
	}
	view, e := app.networkPreferencesView(profile.ID)
	if e != nil || view.PresetConfigText != second.PresetConfigText {
		t.Fatal("sources not persisted", e)
	}
	bad, e := configurePresetDraft(input, &RuleImportInput{Format: "geosite", Category: "onetunnel-missing-category-20261028", Action: "reject"}, false)
	if e != nil {
		t.Fatal(e)
	}
	input.RulesText = bad.RulesText
	input.PresetConfigText = bad.PresetConfigText
	before := *input
	if _, e = refreshPresetDraft(context.Background(), input); e == nil || !strings.Contains(e.Error(), "категор") && !strings.Contains(e.Error(), "Категор") {
		t.Fatal("missing category accepted", e)
	}
	if *input != before {
		t.Fatal("partial refresh changed caller draft")
	}
	t.Logf("presets=%d records=%d repeat refresh passed", len(first.PresetRows), first.Count)
}
