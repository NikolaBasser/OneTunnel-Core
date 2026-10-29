package profiles

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestProviderRoutingHTTPSFetch(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"remarks":"HTTPS policy","outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","domain":["domain:test.example"],"outboundTag":"direct"}]}}`))
	}))
	defer server.Close()
	previous := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = previous }()
	input := &ProviderRoutingInput{URL: server.URL, Index: -1}
	list, e := providerRoutingDraft(context.Background(), input)
	if e != nil || len(list.Profiles) != 1 {
		t.Fatal("HTTPS list", e)
	}
	input.Index = 0
	input.SHA256 = list.SHA256
	result, e := providerRoutingDraft(context.Background(), input)
	if e != nil || result.Draft == nil || result.Draft.Count != 1 {
		t.Fatal("HTTPS preview", e)
	}
}

const providerFixture = `[{"remarks":"Fixture A","outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"},{"tag":"proxy","protocol":"vless","settings":{"credential":"must-not-escape"}}],"routing":{"rules":[{"type":"field","network":"udp","port":"443","outboundTag":"block"},{"type":"field","domain":["geosite:category-ru","domain:local.example","full:exact.example"],"outboundTag":"direct"},{"type":"field","protocol":["bittorrent"],"outboundTag":"direct"},{"type":"field","network":"tcp,udp","balancerTag":"auto"}]}},{"remarks":"Fixture B","outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","ip":["198.51.100.0/24"],"outboundTag":"direct"}]}}]`

func TestProviderRoutingPreviewAndPolicy(t *testing.T) {
	ctx := context.Background()
	input := ProviderRoutingInput{URL: "https://provider.example/subscription/secret", Index: -1}
	geo := func(format, category string) (*protocol.RuleSetData, error) {
		return &protocol.RuleSetData{DomainSuffix: []string{"ru.example"}}, nil
	}
	list, e := parseProviderRouting(ctx, []byte(providerFixture), input, geo)
	if e != nil || len(list.Profiles) != 2 || list.Draft != nil {
		t.Fatal("list", e)
	}
	input.Index = 0
	input.SHA256 = list.SHA256
	result, e := parseProviderRouting(ctx, []byte(providerFixture), input, geo)
	if e != nil {
		t.Fatal(e)
	}
	if result.Draft.Count != 2 || len(result.Warnings) != 3 {
		t.Fatal("warnings/rules", result.Draft.Count, result.Warnings)
	}
	wire, _ := json.Marshal(result)
	if strings.Contains(string(wire), "must-not-escape") {
		t.Fatal("credentials leaked")
	}
	n, e := (NetworkInput{Mode: "default", RulesText: result.Draft.RulesText}).Parse()
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		domain, network string
		port            int
		action          string
	}{{"ru.example", "tcp", 443, "direct"}, {"local.example", "tcp", 80, "direct"}, {"other.example", "udp", 443, "reject"}, {"other.example", "tcp", 443, "proxy"}} {
		got, e := protocol.ExplainRoute(n, protocol.RouteQuery{Domain: tc.domain, Network: tc.network, Port: uint16(tc.port)})
		if e != nil || got.Decision != tc.action {
			t.Fatal(tc, got, e)
		}
	}
	state := RoutingPreferences{Mode: "preset", PresetRulesText: result.Draft.RulesText, PresetConfigText: result.Draft.PresetConfigText, CustomRulesText: "domain | reject | custom.example"}
	normalized, e := state.normalized()
	if e != nil || normalized.Mode != "preset" {
		t.Fatal("provider bank", e)
	}
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Provider", "Manual")
	p.Network = n
	store := managementStore(t, Document{Profiles: []Profile{p}, RoutingProfiles: map[string]RoutingPreferences{p.ID: state}})
	doc, e := store.Load()
	if e != nil || doc.RoutingProfiles[p.ID].Mode != "preset" {
		t.Fatal("encrypted roundtrip", e)
	}
	app := &Application{Store: store}
	view, e := app.networkPreferencesView(p.ID)
	if e != nil || !strings.Contains(view.PresetConfigText, "provider-xray") {
		t.Fatal("view", e)
	}
	input.SHA256 = "stale"
	if _, e = parseProviderRouting(ctx, []byte(providerFixture), input, geo); e == nil {
		t.Fatal("stale source accepted")
	}
	input.SHA256 = list.SHA256
	input.Index = 1
	r, e := parseProviderRouting(ctx, []byte(providerFixture), input, geo)
	if e != nil || r.Draft.Count != 1 {
		t.Fatal("second config", e)
	}
}
func TestProviderRoutingNeverBroadensUnknownConditions(t *testing.T) {
	for _, field := range []string{`"protocol":["bittorrent"]`, `"source":["10.0.0.0/8"]`, `"inboundTag":["local"]`, `"user":["a"]`} {
		raw := `{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","domain":["domain:test.example"],"outboundTag":"direct",` + field + `}]}}`
		list, e := parseProviderRouting(context.Background(), []byte(raw), ProviderRoutingInput{Index: -1}, nil)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = parseProviderRouting(context.Background(), []byte(raw), ProviderRoutingInput{Index: 0, SHA256: list.SHA256}, nil); e == nil {
			t.Fatal("broadened unsupported condition", field)
		}
	}
	for _, raw := range []string{"http://provider.example/a", "https://user:pass@provider.example/a", "file:///C:/secret"} {
		if validProviderURL(raw) {
			t.Fatal("unsafe URL")
		}
	}
}
func TestProviderRoutingLiveSubscription(t *testing.T) {
	path := os.Getenv("ONETUNNEL_PROVIDER_FIXTURE")
	if path == "" {
		t.Skip("live provider fixture not supplied")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	input := ProviderRoutingInput{URL: "https://provider.example/test", Index: -1}
	list, e := parseProviderRouting(context.Background(), b, input, nil)
	if e != nil {
		t.Fatal(e)
	}
	geo := func(format, category string) (*protocol.RuleSetData, error) {
		raw, e := downloadLoyal(context.Background(), format, category)
		if e != nil {
			return nil, e
		}
		return protocol.ImportLoyalsoldier(format, category, raw)
	}
	for i := range list.Profiles {
		input.Index = i
		input.SHA256 = list.SHA256
		r, e := parseProviderRouting(context.Background(), b, input, geo)
		if e != nil {
			t.Fatal("config", i, e)
		}
		if r.Draft == nil || r.Draft.Count == 0 {
			t.Fatal("empty policy")
		}
		t.Logf("configuration %d: %d compatible rules, %d notices", i, r.Draft.Count, len(r.Warnings))
	}
}
