package profiles

import (
	"context"
	"encoding/json"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"os"
	"testing"
)

func TestImportedProviderGeoLive(t *testing.T) {
	path := os.Getenv("ONETUNNEL_PROVIDER_FIXTURE")
	if path == "" {
		t.Skip("explicit sanitized VM fixture required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store := managementStore(t, Document{Profiles: []Profile{managementProfile(t, "11111111-1111-4111-8111-111111111111", "Fixture", "Liberty")}, ImportedRouting: map[string]json.RawMessage{"Liberty": raw}, SubscriptionSources: map[string]string{"Liberty": "https://provider.example/sub"}})
	app := &Application{Store: store}
	sources, err := app.importedRoutingSources()
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 {
		t.Fatal("stored source missing")
	}
	result, err := app.selectImportedRouting(context.Background(), "Liberty", &ProviderRoutingInput{Index: 0, SHA256: sources[0].SHA256})
	if err != nil {
		t.Fatal(err)
	}
	if result.Draft == nil || result.Draft.Count == 0 {
		t.Fatal("empty imported policy")
	}
	t.Log("imported provider category resolved; compatible rules:", result.Draft.Count)
	for _, entry := range []struct{ format, category string }{{"geosite", "category-ru"}, {"geoip", "ru"}} {
		data, err := downloadLoyalURL(context.Background(), entry.format, "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/"+entry.format+".dat")
		if err != nil {
			t.Fatal("official release asset", entry.format, err)
		}
		if _, err = protocol.ImportLoyalsoldier(entry.format, entry.category, data); err != nil {
			t.Fatal("release data", err)
		}
		t.Log("official fallback asset decoded:", entry.format, len(data))
	}
}
