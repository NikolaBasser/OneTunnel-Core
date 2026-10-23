package profiles

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func libraryProfile(t *testing.T, id, name string, kind int) Profile {
	t.Helper()
	p := fixture(t, name, vless)
	p.ID, p.Protocol, p.Group = id, kind, "library"
	return p
}

func libraryStore(t *testing.T, profiles ...Profile) (*Store, Document) {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	doc.Profiles = profiles
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	doc, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return store, doc
}

func TestFavoriteIDsLegacyNormalizationAndPersistence(t *testing.T) {
	p := libraryProfile(t, "11111111-1111-4111-8111-111111111111", "One", 2)
	legacy := Document{Version: 1, Profiles: []Profile{p}, CollapsedGroups: []string{}, SubscriptionSources: map[string]string{}}
	plain, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "FavoriteIDs") {
		t.Fatal("empty favorite field was added to legacy document")
	}
	encrypted, err := Protect(plain, true)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Root, "profiles.bin")
	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := store.Load()
	if err != nil || len(doc.FavoriteIDs) != 0 {
		t.Fatalf("legacy load favorites=%v err=%v", doc.FavoriteIDs, err)
	}
	afterLoad, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(before, afterLoad) {
		t.Fatal("legacy load rewrote encrypted file")
	}
	doc.FavoriteIDs = []string{p.ID, p.ID, "stale"}
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || !reflect.DeepEqual(loaded.FavoriteIDs, []string{p.ID}) {
		t.Fatalf("normalized persisted favorites=%v err=%v", loaded.FavoriteIDs, err)
	}
}

func TestFavoriteSetIdempotenceValidationAndWriteFailure(t *testing.T) {
	p := libraryProfile(t, "11111111-1111-4111-8111-111111111111", "One", 2)
	store, _ := libraryStore(t, p)
	app := &Application{Store: store}
	path := filepath.Join(store.Root, "profiles.bin")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	baseline := store.revision
	view, err := app.Handle(context.Background(), Request{Version: 1, Command: "ui.favorite.set", ID: p.ID, Favorite: false})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := view.(Document); !ok {
		t.Fatalf("favorite command returned %T", view)
	}
	if store.revision != baseline {
		t.Fatal("idempotent favorite command changed the store revision")
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("idempotent favorite command rewrote the store")
	}
	for _, id := range []string{"invalid", "22222222-2222-4222-8222-222222222222"} {
		if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "favorite.set", ID: id, Favorite: true}); err == nil {
			t.Fatalf("accepted invalid or missing profile ID %q", id)
		}
	}
	after, err = os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("rejected favorite command wrote the store")
	}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "favorite.set", ID: p.ID, Favorite: true}); err != nil {
		t.Fatal(err)
	}
	doc, err := store.Load()
	if err != nil || !reflect.DeepEqual(doc.FavoriteIDs, []string{p.ID}) {
		t.Fatalf("favorite was not saved: %v %v", doc.FavoriteIDs, err)
	}

	failedStore, _ := libraryStore(t, p)
	failedApp := &Application{Store: failedStore}
	if err := os.Mkdir(filepath.Join(failedStore.Root, "profiles.bin.new"), 0700); err != nil {
		t.Fatal(err)
	}
	failedPath := filepath.Join(failedStore.Root, "profiles.bin")
	failedBefore, err := os.ReadFile(failedPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failedApp.Handle(context.Background(), Request{Version: 1, Command: "favorite.set", ID: p.ID, Favorite: true}); err == nil {
		t.Fatal("write failure was accepted")
	}
	failedAfter, err := os.ReadFile(failedPath)
	if err != nil || !reflect.DeepEqual(failedBefore, failedAfter) {
		t.Fatal("failed favorite write changed the store")
	}

	corruptStore, _ := libraryStore(t, p)
	corruptPath := filepath.Join(corruptStore.Root, "profiles.bin")
	if err := os.WriteFile(corruptPath, []byte("synthetic corruption"), 0600); err != nil {
		t.Fatal(err)
	}
	corruptBefore, err := os.ReadFile(corruptPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Application{Store: corruptStore}).Handle(context.Background(), Request{Version: 1, Command: "favorite.set", ID: p.ID, Favorite: true}); err == nil {
		t.Fatal("corrupt store accepted favorite mutation")
	}
	corruptAfter, err := os.ReadFile(corruptPath)
	if err != nil || !reflect.DeepEqual(corruptBefore, corruptAfter) {
		t.Fatal("corrupt favorite mutation changed the store")
	}
}

func TestLibraryViewSortFilterAndReadOnly(t *testing.T) {
	doc := Document{Profiles: []Profile{
		{ID: "a", Name: "zulu", Protocol: 4},
		{ID: "b", Name: "Ärger", Protocol: 2},
		{ID: "c", Name: "ärger", Protocol: 2},
		{ID: "d", Name: "😀", Protocol: -1},
		{ID: "e", Name: "alpha", Protocol: 80},
	}, FavoriteIDs: []string{"c", "e"}}
	stored := projectLibraryView(doc, "stored", false).IDs
	if want := []string{"a", "b", "c", "d", "e"}; !reflect.DeepEqual(stored, want) {
		t.Fatalf("stored order %v", stored)
	}
	byName := projectLibraryView(doc, "name", false).IDs
	if want := []string{"e", "a", "b", "c", "d"}; !reflect.DeepEqual(byName, want) {
		t.Fatalf("name order %v, want %v", byName, want)
	}
	byProtocol := projectLibraryView(doc, "protocol", false).IDs
	if want := []string{"d", "b", "c", "a", "e"}; !reflect.DeepEqual(byProtocol, want) {
		t.Fatalf("protocol order %v, want %v", byProtocol, want)
	}
	filtered := projectLibraryView(doc, "stored", true).IDs
	if want := []string{"c", "e"}; !reflect.DeepEqual(filtered, want) {
		t.Fatalf("favorites filter %v", filtered)
	}
	if want := []string{"e", "c"}; !reflect.DeepEqual(projectLibraryView(doc, "name", true).IDs, want) {
		t.Fatal("name sort did not compose with favorites filter")
	}
	if !reflect.DeepEqual(doc.Profiles[0].ID, "a") || !reflect.DeepEqual(doc.FavoriteIDs, []string{"c", "e"}) {
		t.Fatal("projection mutated stored document")
	}
	if got := projectLibraryView(Document{}, "protocol", true).IDs; got == nil || len(got) != 0 {
		t.Fatal("empty projection should return an empty ID list")
	}
}

func TestLibraryViewCommandRejectsModeAndDoesNotWrite(t *testing.T) {
	p := libraryProfile(t, "11111111-1111-4111-8111-111111111111", "One", 2)
	store, _ := libraryStore(t, p)
	before, err := os.ReadFile(filepath.Join(store.Root, "profiles.bin"))
	if err != nil {
		t.Fatal(err)
	}
	app := &Application{Store: store}
	for _, mode := range []string{"invalid", "NAME", "protocols"} {
		if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "library.view", Sort: mode}); err == nil {
			t.Fatalf("accepted invalid mode %q", mode)
		}
	}
	value, err := app.Handle(context.Background(), Request{Version: 1, Command: "ui.library.view", FavoritesOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	view, ok := value.(LibraryView)
	if !ok || view.IDs == nil || len(view.IDs) != 0 {
		t.Fatalf("empty view: %#v", value)
	}
	after, err := os.ReadFile(filepath.Join(store.Root, "profiles.bin"))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("library projection wrote to the store")
	}
}

func TestFavoritesSurviveEditorAndSubscriptionMergeThenPruneOnDelete(t *testing.T) {
	p := libraryProfile(t, "11111111-1111-4111-8111-111111111111", "Saved", 2)
	store, _ := libraryStore(t, p)
	app := &Application{Store: store}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "favorite.set", ID: p.ID, Favorite: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.SaveEditor(context.Background(), Request{ID: p.ID, Name: "Renamed", Group: "library", Source: p.Source}); err != nil {
		t.Fatal(err)
	}
	current, err := store.Load()
	if err != nil || !reflect.DeepEqual(current.FavoriteIDs, []string{p.ID}) {
		t.Fatalf("editor lost favorite: %v %v", current.FavoriteIDs, err)
	}
	updated := current.Profiles[0]
	updated.Name = "From subscription"
	merged, err := Merge(current.Profiles, []Profile{updated}, "library")
	if err != nil || len(merged.Profiles) != 1 || merged.Profiles[0].ID != p.ID {
		t.Fatalf("subscription merge lost stable identity: %+v %v", merged, err)
	}
	current.Profiles = merged.Profiles
	if err := store.Save(current); err != nil {
		t.Fatal(err)
	}
	current, err = store.Load()
	if err != nil || !reflect.DeepEqual(current.FavoriteIDs, []string{p.ID}) {
		t.Fatalf("subscription merge lost favorite: %v %v", current.FavoriteIDs, err)
	}
	deleted, err := app.Handle(context.Background(), Request{Version: 1, Command: "ui.delete", ID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	if presented, ok := deleted.(Document); !ok || len(presented.FavoriteIDs) != 0 {
		t.Fatalf("delete response retained stale favorite: %#v", deleted)
	}
	current, err = store.Load()
	if err != nil || len(current.FavoriteIDs) != 0 || len(current.Profiles) != 0 {
		t.Fatalf("delete did not prune favorite: %+v %v", current, err)
	}
}

func TestSubscriptionRetirementPrunesOnlyRetiredFavorite(t *testing.T) {
	retired := libraryProfile(t, "11111111-1111-4111-8111-111111111111", "Retired", 2)
	retired.Group = "subscription"
	other := libraryProfile(t, "22222222-2222-4222-8222-222222222222", "Other", 2)
	other.Group = "other"
	store, doc := libraryStore(t, retired, other)
	doc.FavoriteIDs = []string{retired.ID, other.ID}
	doc.SubscriptionSources = map[string]string{"subscription": "https://example.invalid/feed"}
	doc.SubscriptionMetadata = map[string]SubscriptionMetadata{"subscription": {UpdatedAt: "synthetic-time"}}
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	fresh := libraryProfile(t, "33333333-3333-4333-8333-333333333333", "Replacement", 2)
	fresh.Group = "subscription"
	fresh.Source = strings.Replace(vless, ":443", ":444", 1)
	merged, err := Merge(doc.Profiles, []Profile{fresh}, "subscription")
	if err != nil || len(merged.Profiles) != 2 || merged.Removed != 1 {
		t.Fatalf("subscription retirement merge: %+v %v", merged, err)
	}
	doc.Profiles = merged.Profiles
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.FavoriteIDs, []string{other.ID}) || loaded.SubscriptionSources["subscription"] != "https://example.invalid/feed" || loaded.SubscriptionMetadata["subscription"].UpdatedAt != "synthetic-time" {
		t.Fatalf("retirement damaged unrelated metadata: %+v", loaded)
	}
}

func TestFavoriteNoOpPreservesRefreshPreviewButChangeConflicts(t *testing.T) {
	p := libraryProfile(t, "11111111-1111-4111-8111-111111111111", "Saved", 2)
	store, doc := libraryStore(t, p)
	doc.FavoriteIDs = []string{p.ID}
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	app := &Application{Store: store}
	app.pendingPreview = &pendingSubscriptionPreview{token: "preview", baseline: store.revision, expires: time.Now().Add(time.Minute), candidate: doc}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "favorite.set", ID: p.ID, Favorite: true}); err != nil {
		t.Fatal(err)
	}
	if app.pendingPreview == nil || app.pendingPreview.baseline != store.revision {
		t.Fatal("idempotent favorite operation invalidated preview")
	}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "favorite.set", ID: p.ID, Favorite: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.applyRefresh("preview"); err == nil {
		t.Fatal("favorite mutation did not invalidate preview")
	}
}

func TestDiagnosticsReportStillExcludesFavoriteMetadata(t *testing.T) {
	const favorite = "11111111-1111-4111-8111-111111111111"
	text, err := formatDiagnosticsReport(Document{FavoriteIDs: []string{favorite}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, favorite) || strings.Contains(text, "favorite") {
		t.Fatal("diagnostics exposed favorite metadata")
	}
}

func BenchmarkLibraryView2000(b *testing.B) {
	profiles := make([]Profile, 2000)
	favorites := make([]string, 0, 1000)
	for i := range profiles {
		profiles[i] = Profile{ID: fmt.Sprintf("synthetic-%04d", i), Name: strings.Repeat("N", 5) + string(rune('a'+i%26)) + string(rune('A'+(i/26)%26)), Protocol: (i * 7) % 13}
		if i%2 == 0 {
			favorites = append(favorites, profiles[i].ID)
		}
	}
	doc := Document{Profiles: profiles, FavoriteIDs: favorites}
	for _, mode := range []string{"stored", "name", "protocol"} {
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = projectLibraryView(doc, mode, false)
			}
		})
	}
}
