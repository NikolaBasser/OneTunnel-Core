package profiles

import (
	"context"
	"encoding/json"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyStoreEditorAnalysisAndBackup(t *testing.T) {
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Policy", "Manual")
	store := managementStore(t, Document{Profiles: []Profile{p}})
	app := &Application{Store: store}
	view, err := app.networkPreferencesView(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	input := &NetworkInput{Mode: "default", RulesText: `{"Targets":[{"Name":"work","Protocol":3,"Source":"socks5://user:POLICY-SECRET@127.0.0.1:18080"}],"RuleSets":[{"Name":"sites","Members":[{"Kind":"domain-suffix","Value":"example.com"}]}],"Rules":[{"Kind":"rule-set","Value":"sites","Action":"proxy","Outbound":"work","Network":"tcp","Port":"443"}]}`}
	metadata, err := app.saveNetworkPreferences(Request{ID: p.ID, Token: view.Token, NetworkInput: input})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(metadata)
	if strings.Contains(string(b), "POLICY-SECRET") {
		t.Fatal("list response leaked policy credentials")
	}
	original, err := store.Load()
	if err != nil || !strings.Contains(original.Profiles[0].Network.Targets[0].Source, "POLICY-SECRET") {
		t.Fatal("encrypted store lost target", err)
	}
	encrypted, err := os.ReadFile(filepath.Join(store.Root, "profiles.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encrypted), "POLICY-SECRET") {
		t.Fatal("plaintext policy on disk")
	}
	view, err = app.networkPreferencesView(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := (NetworkInput{Mode: view.Mode, RulesText: view.RulesText}).Parse()
	if err != nil || !protocol.NetworkOptionsEquivalent(parsed, original.Profiles[0].Network) {
		t.Fatal("editor lost advanced policy", err)
	}
	value, err := app.Handle(context.Background(), Request{Version: 1, Command: "network.explain", ID: p.ID, PolicyQuery: &protocol.RouteQuery{Domain: "api.example.com", Network: "tcp", Port: 443}})
	if err != nil || value.(protocol.RoutePrediction).Outbound != "work" {
		t.Fatal("host prediction", err)
	}
	if _, err = app.Handle(context.Background(), Request{Version: 1, Command: "network.analyze", ID: p.ID}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.otbackup")
	if _, err = app.exportBackup(path, "Synthetic-policy-password"); err != nil {
		t.Fatal(err)
	}
	target := managementStore(t, Document{})
	restore := &Application{Store: target}
	preview, err := restore.previewBackupRestore(path, "Synthetic-policy-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restore.applyBackupRestore(preview.Token, false); err != nil {
		t.Fatal(err)
	}
	loaded, err := target.Load()
	if err != nil || !protocol.NetworkOptionsEquivalent(loaded.Profiles[0].Network, original.Profiles[0].Network) {
		t.Fatal("backup lost policy", err)
	}
}

func TestPolicyAdvancedEditorRoundTrip(t *testing.T) {
	raw := `{"Targets":[{"Name":"work","Protocol":3,"Source":"socks5://127.0.0.1:18080"}],"RuleSets":[{"Name":"sites","Members":[{"Kind":"domain-suffix","Value":"example.com"}]}],"Rules":[{"Kind":"rule-set","Value":"sites","Action":"proxy","Outbound":"work","Network":"tcp","Port":"443","Process":"C:\\Apps\\Browser.exe"}]}`
	options, err := (NetworkInput{Mode: "default", RulesText: raw}).Parse()
	if err != nil {
		t.Fatal(err)
	}
	if options.Rules[0].Outbound != "work" || options.Rules[0].Process != `c:\apps\browser.exe` {
		t.Fatal("lost compound policy")
	}
	data, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	var copy protocol.NetworkOptions
	if json.Unmarshal(data, &copy) != nil || !protocol.NetworkOptionsEquivalent(options, &copy) {
		t.Fatal("policy wire roundtrip")
	}
	for _, bad := range []string{raw + `{}`, strings.Replace(raw, `"Targets":`, `"Unexpected":`, 1), strings.Replace(raw, `"443"`, `"99999"`, 1)} {
		if _, err := (NetworkInput{Mode: "default", RulesText: bad}).Parse(); err == nil {
			t.Fatal("accepted malformed advanced input")
		}
	}
}
