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
	advanced, e := (NetworkInput{Mode: "h3", ServerIP: "1.1.1.1", ServerName: "dns.example", FakeIP: true, CacheMode: "bounded", CacheCapacity: "512", ResolversText: "quic | 8.8.8.8 | dns.example | |"}).Parse()
	if e != nil || !advanced.FakeIP || advanced.DNSCache == nil || advanced.DNSCache.Capacity != 512 || advanced.DNS.Path != "/dns-query" || advanced.Resolvers[0].Port != 853 {
		t.Fatal("advanced DNS preferences lost", e)
	}
	for _, input := range []NetworkInput{{Mode: "default", CacheMode: "bounded", CacheCapacity: "invalid"}, {Mode: "default", CacheMode: "default", CacheCapacity: "512"}, {Mode: "default", CacheMode: "unknown"}} {
		if _, e := input.Parse(); e == nil {
			t.Fatal("invalid cache input accepted")
		}
	}
	parsed, err := (NetworkInput{Mode: "https", ServerIP: "1.1.1.1", ServerName: "DNS.Example", RulesText: "domain-suffix | direct | example.com\ncidr | reject | 192.0.2.4", ResolversText: "https | 8.8.8.8 | dns.google |  |\ntls | 2001:4860:4860::8888 | dns.google | 853 |", DNSRulesText: "domain | example.com | 2\ndomain-suffix | sub.example.com | 1", AllowLAN: true}).Parse()
	if err != nil || parsed.DNS.Port != 443 || parsed.DNS.Path != "/dns-query" || parsed.Rules[1].Value != "192.0.2.4/32" {
		t.Fatalf("parse/defaults: %+v %v", parsed, err)
	}
	if len(parsed.Resolvers) != 2 || parsed.Resolvers[0].Path != "/dns-query" || parsed.Resolvers[1].Port != 853 || parsed.DNSRules[0].ResolverIndex != 1 || !parsed.AllowLAN {
		t.Fatalf("additional DNS fields: %+v", parsed)
	}
	if _, err := (NetworkInput{Mode: "tls", ServerIP: "8.8.8.8", ServerName: "dns.example", Path: "/dns-query"}).Parse(); err == nil {
		t.Fatal("DoT accepted a DoH path")
	}
	if _, err := (NetworkInput{Mode: "default", ServerIP: "1.1.1.1"}).Parse(); err == nil {
		t.Fatal("default mode accepted hidden custom DNS")
	}
	for _, input := range []NetworkInput{
		{ResolversText: "https|8.8.8.8|dns.google|443"},
		{ResolversText: "https|8.8.8.8|dns.google|bad|/dns-query"},
		{ResolversText: "https|8.8.8.8|dns.google||", DNSRulesText: "domain|example.com|0"},
	} {
		if _, err := input.Parse(); err == nil {
			t.Errorf("accepted malformed DNS input: %+v", input)
		}
	}

	profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Profile", "Manual")
	profile.Source = vless + "#SOURCE-SECRET-SENTINEL"
	profile.Network = &protocol.NetworkOptions{Resolvers: []protocol.DNSOptions{{Transport: "https", ServerIP: "1.1.1.1", ServerName: "dns.example"}}, DNSRules: []protocol.DNSRule{{Kind: "domain-suffix", Value: "example.com", ResolverIndex: 0}}, AllowLAN: true}
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
	assertJSONKeys(t, viewObject, "ID", "Token", "Message", "Mode", "ServerIP", "ServerName", "Port", "Path", "RulesText", "ResolversText", "DNSRulesText", "AllowLAN", "Supported", "CanSave", "FakeIP", "CacheMode", "CacheCapacity", "RoutingMode", "CustomRulesText", "PresetRulesText", "PresetConfigText", "PresetRows", "PresetSummary")
	if view.ResolversText != "https | 1.1.1.1 | dns.example | 443 | /dns-query\n" || view.DNSRulesText != "domain-suffix | example.com | 1\n" || !view.AllowLAN {
		t.Fatalf("DNS preferences view: %+v", view)
	}
	input := &NetworkInput{Mode: "tls", ServerIP: "8.8.8.8", ServerName: "dns.example", RulesText: "process | direct | C:\\Synthetic\\allowed.exe", ResolversText: "https | 1.1.1.1 | dns.example | |", DNSRulesText: "domain | example.com | 1", AllowLAN: true}
	resultValue, err := app.Handle(context.Background(), Request{Version: 1, Command: "ui.network.preferences.save", ID: profile.ID, Token: view.Token, NetworkInput: input})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(Document)
	if len(result.Profiles) != 1 || result.Profiles[0].Source != "" || result.Profiles[0].Network == nil || result.Profiles[0].Network.DNS.Port != 853 || result.Profiles[0].Network.Rules[0].Value != `c:\synthetic\allowed.exe` || len(result.Profiles[0].Network.Resolvers) != 1 || result.Profiles[0].Network.DNSRules[0].ResolverIndex != 0 || !result.Profiles[0].Network.AllowLAN || len(result.FavoriteIDs) != 1 {
		t.Fatalf("save response: %+v", result)
	}
	reloaded, err := store.Load()
	if err != nil || !protocol.NetworkOptionsEquivalent(reloaded.Profiles[0].Network, result.Profiles[0].Network) {
		t.Fatalf("saved DNS policy did not reload: %+v %v", reloaded, err)
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
	first.Network = &protocol.NetworkOptions{DNS: &protocol.DNSOptions{Transport: "https", ServerIP: "1.1.1.1", ServerName: "dns.example"}, Rules: []protocol.NetworkRule{{Kind: "domain", Action: "proxy", Value: "example.com"}}, Resolvers: []protocol.DNSOptions{{Transport: "tls", ServerIP: "8.8.8.8", ServerName: "dns.google"}}, DNSRules: []protocol.DNSRule{{Kind: "domain", Value: "example.com", ResolverIndex: 0}}, AllowLAN: true}
	fresh := first
	fresh.Name = "Renamed"
	fresh.Network = nil
	merged, err := Merge([]Profile{first}, []Profile{fresh}, first.Group)
	if err != nil || !protocol.NetworkOptionsEquivalent(merged.Profiles[0].Network, first.Network) {
		t.Fatalf("merge did not preserve network policy: %+v %v", merged, err)
	}
	cloned := cloneOrganizationProfile(first)
	if cloned.Network == first.Network || cloned.Network.DNS == first.Network.DNS || &cloned.Network.Rules[0] == &first.Network.Rules[0] || &cloned.Network.Resolvers[0] == &first.Network.Resolvers[0] || &cloned.Network.DNSRules[0] == &first.Network.DNSRules[0] {
		t.Fatal("network policy copy shares mutable state")
	}
	cloned.Network.Rules[0].Value = "changed.example"
	cloned.Network.Resolvers[0].ServerIP = "9.9.9.9"
	cloned.Network.DNSRules[0].Value = "changed.example"
	if first.Network.Rules[0].Value != "example.com" || first.Network.Resolvers[0].ServerIP != "8.8.8.8" || first.Network.DNSRules[0].Value != "example.com" {
		t.Fatal("copy mutated original profile")
	}
}

func TestEditorSavePreservesExistingNetworkPreferences(t *testing.T) {
	profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Profile", "Manual")
	profile.Network = &protocol.NetworkOptions{Rules: []protocol.NetworkRule{{Kind: "domain", Action: "reject", Value: "blocked.example"}}, Resolvers: []protocol.DNSOptions{{Transport: "https", ServerIP: "1.1.1.1", ServerName: "dns.example"}}, DNSRules: []protocol.DNSRule{{Kind: "domain", Value: "blocked.example", ResolverIndex: 0}}, AllowLAN: true}
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

func TestAdvancedMuxEditorPreservesDNSPreferences(t *testing.T) {
	profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Mux", "Manual")
	profile.Protocol = 5
	profile.Source = "ss://chacha20-ietf-poly1305:fixture@127.0.0.1:18080"
	profile.Network = &protocol.NetworkOptions{FakeIP: true, DNS: &protocol.DNSOptions{Transport: "h3", ServerIP: "1.1.1.1", ServerName: "dns.example"}, DNSCache: &protocol.DNSCacheOptions{Capacity: 512}}
	store := managementStore(t, Document{Profiles: []Profile{profile}})
	app := &Application{Store: store}
	input := &TransportInput{FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20", Mux: true, MuxConcurrency: "8", MuxProtocol: "yamux", MuxMaxConnections: "2", MuxMinStreams: "1", MuxPadding: true}
	if _, err := app.SaveEditor(context.Background(), Request{ID: profile.ID, Name: profile.Name, Group: profile.Group, Source: profile.Source, TransportInput: input}); err != nil {
		t.Fatal(err)
	}
	document, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	saved := document.Profiles[0]
	if saved.Transport == nil || saved.Transport.MuxProtocol != "yamux" || saved.Transport.MuxMaxConnections != 2 || saved.Transport.MuxMinStreams != 1 || !saved.Transport.MuxPadding || !protocol.NetworkOptionsEquivalent(saved.Network, profile.Network) {
		t.Fatal("advanced transport/DNS preferences lost")
	}
	view, err := app.networkPreferencesView(profile.ID)
	if err != nil || !view.FakeIP || view.CacheMode != "bounded" || view.CacheCapacity != "512" || view.Mode != "h3" {
		t.Fatal("advanced network metadata lost", err)
	}
}
