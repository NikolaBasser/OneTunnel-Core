package profiles

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestNetworkInputParseAndPreferencesSave(t *testing.T) {
	parsed, err := (NetworkInput{Mode: "https", ServerIP: "1.1.1.1", ServerName: "DNS.Example", RulesText: "domain-suffix | direct | example.com\ncidr | reject | 192.0.2.4"}).Parse()
	if err != nil || parsed.DNS.Port != 443 || parsed.DNS.Path != "/dns-query" || parsed.Rules[1].Value != "192.0.2.4/32" {
		t.Fatalf("parse/defaults: %+v %v", parsed, err)
	}
	if _, err := (NetworkInput{Mode: "tls", ServerIP: "8.8.8.8", ServerName: "dns.example", Path: "/dns-query"}).Parse(); err == nil {
		t.Fatal("DoT accepted a DoH path")
	}
	if _, err := (NetworkInput{Mode: "default", ServerIP: "1.1.1.1"}).Parse(); err == nil {
		t.Fatal("default mode accepted hidden custom DNS")
	}

	profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Profile", "Manual")
	profile.Source = vless + "#SOURCE-SECRET-SENTINEL"
	store := managementStore(t, Document{Profiles: []Profile{profile}, FavoriteIDs: []string{profile.ID}})
	app := &Application{Store: store, ServiceCall: func(context.Context, control.Request) (control.Response, int64, error) {
		t.Fatal("network preferences called service")
		return control.Response{}, 0, nil
	}, Downloader: func(context.Context, string) (ImportResult, error) {
		t.Fatal("network preferences called downloader")
		return ImportResult{}, nil
	}}
	viewValue, err := app.Handle(context.Background(), Request{Version: 1, Command: "ui.network.preferences.view", ID: profile.ID})
	if err != nil {
		t.Fatal(err)
	}
	view := viewValue.(NetworkPreferencesView)
	if !view.Supported || !view.CanSave || view.Mode != "default" || view.Token == "" {
		t.Fatalf("view: %+v", view)
	}
	viewJSON, _ := json.Marshal(view)
	if strings.Contains(string(viewJSON), "SOURCE-SECRET-SENTINEL") {
		t.Fatal("metadata view disclosed source")
	}
	var viewObject map[string]any
	if err := json.Unmarshal(viewJSON, &viewObject); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, viewObject, "ID", "Token", "Message", "Mode", "ServerIP", "ServerName", "Port", "Path", "RulesText", "Supported", "CanSave")
	input := &NetworkInput{Mode: "tls", ServerIP: "8.8.8.8", ServerName: "dns.example", RulesText: "process | direct | C:\\Synthetic\\allowed.exe"}
	resultValue, err := app.Handle(context.Background(), Request{Version: 1, Command: "ui.network.preferences.save", ID: profile.ID, Token: view.Token, NetworkInput: input})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(Document)
	if len(result.Profiles) != 1 || result.Profiles[0].Source != "" || result.Profiles[0].Network == nil || result.Profiles[0].Network.DNS.Port != 853 || result.Profiles[0].Network.Rules[0].Value != `c:\synthetic\allowed.exe` || len(result.FavoriteIDs) != 1 {
		t.Fatalf("save response: %+v", result)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "SOURCE-SECRET-SENTINEL") {
		t.Fatal("save response disclosed source")
	}
	newToken := fmtHex(store.revision[:])
	before := store.revision
	noOp, err := app.saveNetworkPreferences(Request{ID: profile.ID, Token: newToken, NetworkInput: input})
	if err != nil || store.revision != before || noOp.Profiles[0].Network == nil {
		t.Fatal("equivalent save rewrote store", err)
	}
	if _, err := app.saveNetworkPreferences(Request{ID: profile.ID, Token: view.Token, NetworkInput: input}); err == nil {
		t.Fatal("stale token accepted")
	}
	if _, err := app.saveNetworkPreferences(Request{ID: profile.ID, Token: newToken, NetworkInput: &NetworkInput{Mode: "https", ServerIP: "not-an-ip", ServerName: "dns.example"}}); err == nil {
		t.Fatal("invalid preferences saved")
	}
}

func TestNetworkPolicyPreservedThroughMergeAndCopy(t *testing.T) {
	first := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Profile", "Provider")
	first.Network = &protocol.NetworkOptions{DNS: &protocol.DNSOptions{Transport: "https", ServerIP: "1.1.1.1", ServerName: "dns.example"}, Rules: []protocol.NetworkRule{{Kind: "domain", Action: "proxy", Value: "example.com"}}}
	fresh := first
	fresh.Name = "Renamed"
	merged, err := Merge([]Profile{first}, []Profile{fresh}, first.Group)
	if err != nil || merged.Profiles[0].Network == nil {
		t.Fatalf("merge did not preserve network policy: %+v %v", merged, err)
	}
	cloned := cloneOrganizationProfile(first)
	if cloned.Network == first.Network || cloned.Network.DNS == first.Network.DNS || &cloned.Network.Rules[0] == &first.Network.Rules[0] {
		t.Fatal("network policy copy shares mutable state")
	}
	cloned.Network.Rules[0].Value = "changed.example"
	if first.Network.Rules[0].Value != "example.com" {
		t.Fatal("copy mutated original profile")
	}
}

func TestEditorSavePreservesExistingNetworkPreferences(t *testing.T) {
	profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Profile", "Manual")
	profile.Network = &protocol.NetworkOptions{Rules: []protocol.NetworkRule{{Kind: "domain", Action: "reject", Value: "blocked.example"}}}
	store := managementStore(t, Document{Profiles: []Profile{profile}})
	app := &Application{Store: store}
	if _, err := app.SaveEditor(context.Background(), Request{ID: profile.ID, Name: "Renamed", Group: profile.Group, Source: profile.Source}); err != nil {
		t.Fatal(err)
	}
	doc, err := store.Load()
	if err != nil || len(doc.Profiles) != 1 || !protocol.NetworkOptionsEquivalent(doc.Profiles[0].Network, profile.Network) {
		t.Fatalf("editor lost network preferences: %+v %v", doc, err)
	}
}
