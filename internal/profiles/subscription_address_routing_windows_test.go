package profiles

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestSubscriptionAddressRoutingUnionAndExclusions(t *testing.T) {
	raw := []byte(`[{"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],"routing":{"rules":[{"type":"field","network":"udp","port":"443","outboundTag":"block"},{"type":"field","domain":["domain:a.example"],"outboundTag":"direct"},{"type":"field","domain":["domain:limited.example"],"port":"80","outboundTag":"direct"},{"type":"field","balancerTag":"auto","network":"tcp,udp"}]}},{"outbounds":[{"tag":"direct2","protocol":"freedom"}],"routing":{"rules":[{"type":"field","domain":["domain:a.example","domain:b.example"],"outboundTag":"direct2"},{"type":"field","protocol":["bittorrent"],"outboundTag":"direct2"}]}}]`)
	clean, e := subscriptionAddressRouting(raw)
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{`"port"`, `"network"`, `"balancerTag"`, `bittorrent`, `limited.example`} {
		if strings.Contains(string(clean), field) {
			t.Fatal("excluded condition survived", field)
		}
	}
	list, _ := parseProviderRouting(context.Background(), clean, ProviderRoutingInput{Index: -1}, nil)
	result, e := parseProviderRouting(context.Background(), clean, ProviderRoutingInput{Index: 0, SHA256: list.SHA256}, nil)
	if e != nil || result.Draft.Count != 1 {
		t.Fatal("deduplicated union", e)
	}
	n, e := (NetworkInput{Mode: "default", RulesText: result.Draft.RulesText}).Parse()
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ domain, decision string }{{"a.example", "direct"}, {"b.example", "direct"}, {"outside.example", "proxy"}, {"limited.example", "proxy"}} {
		got, e := protocol.ExplainRoute(n, protocol.RouteQuery{Domain: tc.domain, Network: "udp", Port: 443})
		if e != nil || got.Decision != tc.decision {
			t.Fatal(tc, got, e)
		}
	}
}
func TestProviderAddressMigrationRemovesSavedPortRule(t *testing.T) {
	list, _ := parseProviderRouting(context.Background(), []byte(providerFixture), ProviderRoutingInput{Index: -1}, nil)
	r, e := parseProviderRouting(context.Background(), []byte(providerFixture), ProviderRoutingInput{URL: "https://provider.example/sub", Index: 0, SHA256: list.SHA256}, func(string, string) (*protocol.RuleSetData, error) {
		return &protocol.RuleSetData{DomainSuffix: []string{"ru.example"}}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	n, _ := (NetworkInput{Mode: "default", RulesText: r.Draft.RulesText}).Parse()
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Old", "Provider")
	p.Network = n
	store := managementStore(t, Document{Profiles: []Profile{p}, RoutingProfiles: map[string]RoutingPreferences{p.ID: {Mode: "preset", PresetRulesText: r.Draft.RulesText, PresetConfigText: r.Draft.PresetConfigText}}})
	doc, e := store.Load()
	if e != nil {
		t.Fatal(e)
	}
	got, e := protocol.ExplainRoute(doc.Profiles[0].Network, protocol.RouteQuery{Domain: "outside.example", Network: "udp", Port: 443})
	if e != nil || got.Decision != "proxy" {
		t.Fatal("old port block survived", got, e)
	}
	if !strings.Contains(doc.RoutingProfiles[p.ID].PresetConfigText, `"Scope":"addresses-legacy"`) {
		t.Fatal("migration marker lost")
	}
}
func TestSubscriptionAddressRoutingSanitizedProvider(t *testing.T) {
	path := os.Getenv("ONETUNNEL_PROVIDER_FIXTURE")
	if path == "" {
		t.Skip("sanitized VM fixture required")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	clean, e := subscriptionAddressRouting(raw)
	if e != nil {
		t.Fatal(e)
	}
	var configs []providerConfig
	json.Unmarshal(clean, &configs)
	if len(configs) != 1 || len(configs[0].Routing.Rules) != 1 {
		t.Fatal("expected one address scheme", len(configs), string(clean))
	}
}
