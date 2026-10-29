package profiles

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func subscriptionRoutingFixture(t *testing.T, domain string) string {
	t.Helper()
	out, e := protocol.Outbound(vless, 2)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal([]any{map[string]any{"remarks": "Imported policy", "outbounds": []any{out, map[string]any{"tag": "direct", "protocol": "freedom"}}, "routing": map[string]any{"rules": []any{map[string]any{"type": "field", "domain": []string{"domain:" + domain}, "outboundTag": "direct"}, map[string]any{"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "direct"}}}}})
	return string(b)
}
func TestImportedRoutingSubscriptionLifecycle(t *testing.T) {
	ctx := context.Background()
	payload := subscriptionRoutingFixture(t, "imported.example")
	batch, e := ParseSubscription(payload)
	if e != nil || len(batch.Profiles) != 1 || len(batch.ImportedRouting) == 0 {
		t.Fatal("automatic capture", e)
	}
	if strings.Contains(string(batch.ImportedRouting), "6d7a9bdf") || strings.Contains(string(batch.ImportedRouting), "settings") {
		t.Fatal("routing snapshot contains server credentials")
	}
	store := managementStore(t, Document{})
	app := &Application{Store: store, Downloader: func(context.Context, string) (ImportResult, error) { return batch, nil }}
	if _, e = app.SaveEditor(ctx, Request{Source: "https://provider.example/sub", Group: "Provider"}); e != nil {
		t.Fatal(e)
	}
	sources, e := app.importedRoutingSources()
	if e != nil || len(sources) != 1 || len(sources[0].Profiles) != 1 {
		t.Fatal("imported choices", e)
	}
	result, e := app.selectImportedRouting(ctx, "Provider", &ProviderRoutingInput{Index: 0, SHA256: sources[0].SHA256})
	if e != nil || result.Draft.Count != 1 {
		t.Fatal("select without subscription download", e)
	}
	if !strings.Contains(result.Draft.PresetConfigText, `"Group":"Provider"`) || !strings.Contains(strings.Join(result.Warnings, " "), "исключены") {
		t.Fatal("source/limitations lost")
	}
	doc, _ := store.Load()
	id := doc.Profiles[0].ID
	if doc.Profiles[0].Network != nil {
		t.Fatal("import silently activated policy")
	}
	view, _ := app.networkPreferencesView(id)
	_, e = app.saveNetworkPreferences(Request{ID: id, Token: view.Token, NetworkInput: &NetworkInput{Mode: "default", RoutingMode: "preset", PresetRulesText: result.Draft.RulesText, PresetConfigText: result.Draft.PresetConfigText}})
	if e != nil {
		t.Fatal("save selected policy", e)
	}
	backup := filepath.Join(t.TempDir(), "imported.otbackup")
	if _, e = app.exportBackup(backup, "imported-routing-test-password"); e != nil {
		t.Fatal(e)
	}
	target := &Application{Store: managementStore(t, Document{})}
	preview, e := target.previewBackupRestore(backup, "imported-routing-test-password")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = target.applyBackupRestore(preview.Token, false); e != nil {
		t.Fatal(e)
	}
	restored, e := target.importedRoutingSources()
	if e != nil || len(restored) != 1 {
		t.Fatal("backup lost imported policies", e)
	}
	groups, _ := app.groupList()
	if _, e = app.renameGroup("Provider", "Renamed", groups[0].Token); e != nil {
		t.Fatal(e)
	}
	sources, e = app.importedRoutingSources()
	if e != nil || sources[0].Group != "Renamed" {
		t.Fatal("rename lost routing", e)
	}
	batch, e = ParseSubscription(subscriptionRoutingFixture(t, "updated.example"))
	if e != nil {
		t.Fatal(e)
	}
	previewUpdate, e := app.refreshPreview(ctx, "Renamed")
	if e != nil {
		t.Fatal(e)
	}
	before, _ := app.importedRoutingSources()
	if before[0].SHA256 != sources[0].SHA256 {
		t.Fatal("preview wrote rules early")
	}
	if _, e = app.applyRefresh(previewUpdate.Token); e != nil {
		t.Fatal(e)
	}
	updated, _ := app.importedRoutingSources()
	if updated[0].SHA256 == sources[0].SHA256 {
		t.Fatal("refresh did not import new routing")
	}
	if _, e = app.selectImportedRouting(ctx, "Renamed", &ProviderRoutingInput{Index: 0, SHA256: sources[0].SHA256}); e == nil {
		t.Fatal("stale choice accepted")
	}
	groups, _ = app.groupList()
	if _, e = app.deleteGroup("Renamed", groups[0].Token); e != nil {
		t.Fatal(e)
	}
	sources, e = app.importedRoutingSources()
	if e != nil || len(sources) != 0 {
		t.Fatal("deleted source retained", e)
	}
}
