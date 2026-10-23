package profiles

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

func managementProfile(t *testing.T, id, name, group string) Profile {
	t.Helper()
	p := fixture(t, name, vless)
	p.ID, p.Group = id, group
	return p
}

func managementStore(t *testing.T, doc Document) *Store {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	if doc.CollapsedGroups == nil {
		doc.CollapsedGroups = []string{}
	}
	if doc.SubscriptionSources == nil {
		doc.SubscriptionSources = map[string]string{}
	}
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	return store
}

func managementToken(t *testing.T, app *Application) string {
	t.Helper()
	groups, err := app.groupList()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) == 0 {
		t.Fatal("expected a group summary")
	}
	return groups[0].Token
}

func storeBytes(t *testing.T, store *Store) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(store.Root, "profiles.bin"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func overwriteEncryptedDocument(t *testing.T, store *Store, doc Document) {
	t.Helper()
	plain, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := Protect(plain, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Root, "profiles.bin"), encrypted, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestGroupListIsOrderedCredentialFreeSnapshot(t *testing.T) {
	const source = "https://example.invalid/refresh-secret"
	doc := Document{
		Profiles: []Profile{
			managementProfile(t, "11111111-1111-4111-8111-111111111111", "One", "First"),
			managementProfile(t, "22222222-2222-4222-8222-222222222222", "Two", "Second"),
			managementProfile(t, "33333333-3333-4333-8333-333333333333", "Three", "First"),
		},
		SubscriptionSources:  map[string]string{"First": source},
		SubscriptionMetadata: map[string]SubscriptionMetadata{"First": {UpdatedAt: "private-metadata"}},
	}
	store := managementStore(t, doc)
	app := &Application{Store: store}
	value, err := app.Handle(context.Background(), Request{Version: 1, Command: "ui.group.list"})
	if err != nil {
		t.Fatal(err)
	}
	groups, ok := value.([]GroupSummary)
	if !ok || len(groups) != 2 {
		t.Fatalf("group list result %T %#v", value, value)
	}
	if groups[0].Name != "First" || groups[0].ProfileCount != 2 || !groups[0].IsSubscription || groups[1].Name != "Second" || groups[1].ProfileCount != 1 || groups[1].IsSubscription {
		t.Fatalf("wrong ordered summaries: %+v", groups)
	}
	token := fmtHex(store.revision[:])
	if groups[0].Token != token || groups[1].Token != token || len(token) != 64 {
		t.Fatalf("snapshot token mismatch: %+v", groups)
	}
	encoded, err := json.Marshal(groups)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"11111111", "refresh-secret", "private-metadata", source} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("group summary exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestGroupRenameMovesMetadataAndKeepsProfileState(t *testing.T) {
	first := managementProfile(t, "11111111-1111-4111-8111-111111111111", "First member", "Old")
	second := managementProfile(t, "22222222-2222-4222-8222-222222222222", "Second member", "Old")
	other := managementProfile(t, "33333333-3333-4333-8333-333333333333", "Other", "Other")
	doc := Document{
		Profiles:             []Profile{first, other, second},
		FavoriteIDs:          []string{second.ID},
		CollapsedGroups:      []string{"Old", "Renamed", "Other"},
		SubscriptionSources:  map[string]string{"Old": "https://example.invalid/old", "Other": "https://example.invalid/other"},
		SubscriptionMetadata: map[string]SubscriptionMetadata{"Old": {UpdatedAt: "old-metadata"}, "Other": {UpdatedAt: "other-metadata"}},
	}
	store := managementStore(t, doc)
	app := &Application{Store: store}
	token := managementToken(t, app)
	app.pendingPreview = &pendingSubscriptionPreview{token: "preview", baseline: store.revision, expires: time.Now().Add(time.Minute), candidate: doc}
	value, err := app.Handle(context.Background(), Request{Version: 1, Command: "ui.group.rename", Group: "Old", Name: "  Renamed  ", Token: token})
	if err != nil {
		t.Fatal(err)
	}
	if view, ok := value.(Document); !ok || view.Profiles[0].Source != "" || len(view.SubscriptionSources) != 0 {
		t.Fatalf("rename response was not presentation-safe: %#v", value)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Profiles[0].ID != first.ID || loaded.Profiles[1].ID != other.ID || loaded.Profiles[2].ID != second.ID || loaded.Profiles[0].Group != "Renamed" || loaded.Profiles[2].Group != "Renamed" {
		t.Fatalf("rename changed profile identity or order: %+v", loaded.Profiles)
	}
	if loaded.Profiles[0].Source != first.Source || loaded.Profiles[2].Source != second.Source || !reflect.DeepEqual(loaded.FavoriteIDs, []string{second.ID}) {
		t.Fatal("rename changed profile source or favorites")
	}
	if loaded.SubscriptionSources["Renamed"] != "https://example.invalid/old" || loaded.SubscriptionSources["Other"] != "https://example.invalid/other" || loaded.SubscriptionMetadata["Renamed"].UpdatedAt != "old-metadata" || loaded.SubscriptionMetadata["Other"].UpdatedAt != "other-metadata" {
		t.Fatalf("rename lost subscription metadata: %+v %+v", loaded.SubscriptionSources, loaded.SubscriptionMetadata)
	}
	if !reflect.DeepEqual(loaded.CollapsedGroups, []string{"Other", "Renamed"}) {
		t.Fatalf("rename lost collapsed state: %v", loaded.CollapsedGroups)
	}
	if app.pendingPreview == nil || app.pendingPreview.candidate.SubscriptionSources["Old"] != "https://example.invalid/old" || doc.SubscriptionSources["Old"] != "https://example.invalid/old" {
		t.Fatal("rename mutated an aliased subscription snapshot")
	}
}

func TestGroupRenameNoOpAndRejectedRequestsDoNotWrite(t *testing.T) {
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "One", "Group")
	store := managementStore(t, Document{Profiles: []Profile{p}, SubscriptionSources: map[string]string{"Group": "https://example.invalid/feed"}})
	app := &Application{Store: store}
	token := managementToken(t, app)
	before := storeBytes(t, store)
	app.pendingPreview = &pendingSubscriptionPreview{token: "preview", baseline: store.revision, expires: time.Now().Add(time.Minute)}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.rename", Group: "Group", Name: " Group ", Token: token}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, storeBytes(t, store)) || app.pendingPreview.baseline != store.revision {
		t.Fatal("unchanged rename wrote the store or invalidated preview")
	}
	badNames := []string{" ", "bad\nname", strings.Repeat("x", 101)}
	for _, name := range badNames {
		if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.rename", Group: "Group", Name: name, Token: token}); err == nil {
			t.Fatalf("accepted invalid name %q", name)
		}
	}
	if !reflect.DeepEqual(before, storeBytes(t, store)) {
		t.Fatal("invalid rename changed store")
	}
	for _, name := range []string{"Occupied", "Remote"} {
		if name == "Occupied" {
			p2 := managementProfile(t, "22222222-2222-4222-8222-222222222222", "Two", name)
			doc, _ := store.Load()
			doc.Profiles = append(doc.Profiles, p2)
			if err := store.Save(doc); err != nil {
				t.Fatal(err)
			}
		} else {
			doc, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			doc.SubscriptionSources[name] = "https://example.invalid/source"
			overwriteEncryptedDocument(t, store, doc)
			if _, err := store.Load(); err != nil {
				t.Fatal(err)
			}
		}
		currentToken := managementToken(t, app)
		collisionBefore := storeBytes(t, store)
		if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.rename", Group: "Group", Name: name, Token: currentToken}); err == nil {
			t.Fatalf("accepted target collision %q", name)
		}
		if !reflect.DeepEqual(collisionBefore, storeBytes(t, store)) {
			t.Fatal("collision request changed store")
		}
	}
}

func TestGroupDeleteRemovesSubscriptionAndPrunesFavorites(t *testing.T) {
	deleted := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Delete", "Subscription")
	kept := managementProfile(t, "22222222-2222-4222-8222-222222222222", "Keep", "Other")
	doc := Document{
		Profiles:             []Profile{deleted, kept},
		FavoriteIDs:          []string{deleted.ID, kept.ID},
		CollapsedGroups:      []string{"Subscription", "Other", "stale"},
		SubscriptionSources:  map[string]string{"Subscription": "https://example.invalid/private-source", "Other": "https://example.invalid/keep"},
		SubscriptionMetadata: map[string]SubscriptionMetadata{"Subscription": {UpdatedAt: "delete"}, "Other": {UpdatedAt: "keep"}},
	}
	store := managementStore(t, doc)
	app := &Application{Store: store}
	token := managementToken(t, app)
	value, err := app.Handle(context.Background(), Request{Version: 1, Command: "ui.group.delete", Group: "Subscription", Token: token})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := value.(Document); !ok {
		t.Fatalf("delete returned %T", value)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Profiles) != 1 || loaded.Profiles[0].ID != kept.ID || !reflect.DeepEqual(loaded.FavoriteIDs, []string{kept.ID}) {
		t.Fatalf("delete profile/favorite result: %+v", loaded)
	}
	if _, ok := loaded.SubscriptionSources["Subscription"]; ok {
		t.Fatal("deleted subscription source could reimport the group")
	}
	if _, ok := loaded.SubscriptionMetadata["Subscription"]; ok {
		t.Fatal("deleted subscription metadata remains")
	}
	if !reflect.DeepEqual(loaded.CollapsedGroups, []string{"Other", "stale"}) || loaded.SubscriptionSources["Other"] != doc.SubscriptionSources["Other"] || loaded.SubscriptionMetadata["Other"].UpdatedAt != "keep" {
		t.Fatal("delete damaged unrelated group state")
	}
	otherToken := managementToken(t, app)
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.delete", Group: "Other", Token: otherToken}); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.Load()
	if err != nil || len(loaded.Profiles) != 0 || len(loaded.FavoriteIDs) != 0 || len(loaded.SubscriptionSources) != 0 || len(loaded.SubscriptionMetadata) != 0 {
		t.Fatalf("ordinary group deletion left state behind: %+v %v", loaded, err)
	}
	if summaries, err := app.groupList(); err != nil || len(summaries) != 0 {
		t.Fatalf("empty group list: %v %v", summaries, err)
	}
	emptyBefore := storeBytes(t, store)
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.delete", Group: "Missing", Token: fmtHex(store.revision[:])}); err == nil {
		t.Fatal("empty-store group deletion succeeded")
	}
	if !reflect.DeepEqual(emptyBefore, storeBytes(t, store)) {
		t.Fatal("empty-store group deletion wrote data")
	}
}

func TestGroupMutationsRejectStaleAndWriteFailures(t *testing.T) {
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "One", "Group")
	store := managementStore(t, Document{Profiles: []Profile{p}})
	app := &Application{Store: store}
	oldToken := managementToken(t, app)
	doc, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	doc.CollapsedGroups = []string{"Group"}
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	before := storeBytes(t, store)
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.delete", Group: "Group", Token: oldToken}); err == nil {
		t.Fatal("stale delete was accepted")
	}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.rename", Group: "Group", Name: "Renamed", Token: oldToken}); err == nil {
		t.Fatal("stale rename was accepted")
	}
	if !reflect.DeepEqual(before, storeBytes(t, store)) {
		t.Fatal("stale mutation changed store")
	}

	failingStore := managementStore(t, Document{Profiles: []Profile{p}})
	if err := os.Mkdir(filepath.Join(failingStore.Root, "profiles.bin.new"), 0700); err != nil {
		t.Fatal(err)
	}
	failingApp := &Application{Store: failingStore}
	writeBefore := storeBytes(t, failingStore)
	if _, err := failingApp.Handle(context.Background(), Request{Version: 1, Command: "group.rename", Group: "Group", Name: "Renamed", Token: managementToken(t, failingApp)}); err == nil {
		t.Fatal("rename write failure was accepted")
	}
	if !reflect.DeepEqual(writeBefore, storeBytes(t, failingStore)) {
		t.Fatal("failed rename changed encrypted source file")
	}
}

func TestExpandCollapseAllUsesAllDistinctStoredGroupsAndSkipsNoOps(t *testing.T) {
	profiles := []Profile{
		managementProfile(t, "11111111-1111-4111-8111-111111111111", "One", "First"),
		managementProfile(t, "22222222-2222-4222-8222-222222222222", "Two", "Second"),
		managementProfile(t, "33333333-3333-4333-8333-333333333333", "Three", "First"),
	}
	doc := Document{Profiles: profiles, FavoriteIDs: []string{profiles[0].ID}, CollapsedGroups: []string{"stale", "First", "First", "Second"}}
	store := managementStore(t, doc)
	app := &Application{Store: store}
	before := storeBytes(t, store)
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.expansion.all", Expanded: false}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || !reflect.DeepEqual(loaded.CollapsedGroups, []string{"First", "Second"}) {
		t.Fatalf("collapse-all state %v err=%v", loaded.CollapsedGroups, err)
	}
	collapsedBytes := storeBytes(t, store)
	if reflect.DeepEqual(before, collapsedBytes) {
		t.Fatal("collapse-all failed to remove stale/duplicate entries")
	}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.expansion.all", Expanded: false}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(collapsedBytes, storeBytes(t, store)) {
		t.Fatal("repeated collapse-all wrote the store")
	}
	loaded.CollapsedGroups = []string{"Second", "First"}
	if err := store.Save(loaded); err != nil {
		t.Fatal(err)
	}
	reorderedBytes := storeBytes(t, store)
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.expansion.all", Expanded: false}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reorderedBytes, storeBytes(t, store)) {
		t.Fatal("collapse-all rewrote an equivalent collapsed-group set")
	}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.expansion.all", Expanded: true}); err != nil {
		t.Fatal(err)
	}
	expandedBytes := storeBytes(t, store)
	loaded, err = store.Load()
	if err != nil || len(loaded.CollapsedGroups) != 0 {
		t.Fatalf("expand-all state %v err=%v", loaded.CollapsedGroups, err)
	}
	if !reflect.DeepEqual(loaded.Profiles, profiles) || !reflect.DeepEqual(loaded.FavoriteIDs, []string{profiles[0].ID}) {
		t.Fatal("expand/collapse reordered profiles or changed favorites")
	}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.expansion.all", Expanded: true}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expandedBytes, storeBytes(t, store)) {
		t.Fatal("repeated expand-all wrote the store")
	}
}

func TestGroupMutationsRespectRetainedStateAndNeverCallServiceOrDownloader(t *testing.T) {
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "One", "Group")
	store := managementStore(t, Document{Profiles: []Profile{p}})
	app := &Application{Store: store, ServiceCall: func(context.Context, control.Request) (control.Response, int64, error) {
		t.Fatal("group operation called service")
		return control.Response{}, 0, nil
	}, Downloader: func(context.Context, string) (ImportResult, error) {
		t.Fatal("group operation called downloader")
		return ImportResult{}, nil
	}}
	mutations := []Request{
		{Version: 1, Command: "group.rename", Group: "Group", Name: "Renamed"},
		{Version: 1, Command: "group.delete", Group: "Group"},
		{Version: 1, Command: "group.expansion", Group: "Group", Expanded: false},
		{Version: 1, Command: "group.expansion.all", Expanded: false},
	}
	for _, state := range []string{"active", "reconnecting", "recovery", "locked", "legacy"} {
		app.desktopContext = DesktopContext{}
		app.desktopState.Response.State = control.State{}
		switch state {
		case "active":
			app.desktopState.Response.State.Active = true
		case "reconnecting":
			app.desktopState.Response.State.Reconnecting = true
		case "recovery":
			app.desktopState.Response.State.NeedsRecovery = true
		case "locked":
			app.desktopState.Response.State.TrafficLocked = true
		case "legacy":
			if err := os.WriteFile(filepath.Join(store.Root, "session.json"), []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		before := storeBytes(t, store)
		for _, request := range mutations {
			request.Token = managementToken(t, app)
			if _, err := app.Handle(context.Background(), request); err == nil {
				t.Fatalf("%s state allowed %s", state, request.Command)
			}
		}
		if !reflect.DeepEqual(before, storeBytes(t, store)) {
			t.Fatalf("%s state changed group store", state)
		}
		if state == "legacy" {
			if err := os.Remove(filepath.Join(store.Root, "session.json")); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestGroupExpansionNoOpPreservesPreviewAndReportOmitsGroupData(t *testing.T) {
	const groupSecret = "SYNTHETIC-GROUP-SECRET"
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "One", groupSecret)
	doc := Document{Profiles: []Profile{p}, CollapsedGroups: []string{groupSecret}, SubscriptionSources: map[string]string{groupSecret: "https://example.invalid/SOURCE-SECRET"}}
	store := managementStore(t, doc)
	app := &Application{Store: store}
	app.pendingPreview = &pendingSubscriptionPreview{token: "preview", baseline: store.revision, expires: time.Now().Add(time.Minute)}
	before := storeBytes(t, store)
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.expansion", Group: groupSecret, Expanded: false}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, storeBytes(t, store)) || app.pendingPreview.baseline != store.revision {
		t.Fatal("no-op group expansion wrote store or invalidated preview")
	}
	report, err := formatDiagnosticsReport(doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(report, groupSecret) || strings.Contains(report, "SOURCE-SECRET") {
		t.Fatal("diagnostics exposed group name or source")
	}
}
