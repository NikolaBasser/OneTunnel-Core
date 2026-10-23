package profiles

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func organizationStore(t *testing.T, doc Document) *Store {
	t.Helper()
	return managementStore(t, doc)
}

func organizationToken(t *testing.T, store *Store) string {
	t.Helper()
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	return fmtHex(store.revision[:])
}

func organizationApp(store *Store, selectedID string) *Application {
	return &Application{Store: store, desktopContext: DesktopContext{StorageReady: true, SelectedID: selectedID}}
}

func TestProfileOrganizationMetadataIsAllowlistedAndSuggestsManualTargets(t *testing.T) {
	const secret = "ORGANIZATION-SECRET-SENTINEL"
	manual := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Manual", "Personal")
	managed := managementProfile(t, "22222222-2222-4222-8222-222222222222", "Managed", "Provider")
	doc := Document{Version: 1, Profiles: []Profile{manual, managed, managementProfile(t, "33333333-3333-4333-8333-333333333333", "Other", "Personal")}, FavoriteIDs: []string{manual.ID},
		SubscriptionSources: map[string]string{"Provider": "https://example.invalid/" + secret}, SubscriptionMetadata: map[string]SubscriptionMetadata{"Provider": {UpdatedAt: secret}}, CollapsedGroups: []string{"Personal"}}
	store := organizationStore(t, doc)
	app := organizationApp(store, managed.ID)
	view, err := app.profileOrganization(managed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if view.ID != managed.ID || view.Name != "Managed" || view.Group != "Provider" || view.SuggestedGroup != "Local copies" || view.SuggestedName != "Managed (copy)" || view.Token == "" || !reflect.DeepEqual(view.ManualTargets, []string{"Personal"}) {
		t.Fatalf("unexpected organization view: %+v", view)
	}
	if !view.CanDuplicate || view.CanMove {
		t.Fatalf("managed profile actions were not constrained: %+v", view)
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, object, "ID", "Name", "Group", "SuggestedName", "SuggestedGroup", "Token", "ManualTargets", "CanDuplicate", "CanMove")
	if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "Source") || strings.Contains(string(encoded), "Transport") || strings.Contains(string(encoded), "Reliability") {
		t.Fatal("organization metadata exposed profile or provider data")
	}
	app.desktopContext.SelectedID = manual.ID
	manualView, err := app.profileOrganization(manual.ID)
	if err != nil || !manualView.CanMove || manualView.SuggestedGroup != "Personal" {
		t.Fatalf("manual profile actions/suggestion: %+v, %v", manualView, err)
	}
	app.desktopContext.Busy = true // Availability ignores the command's own Busy context.
	busyView, err := app.profileOrganization(manual.ID)
	if err != nil || !busyView.CanDuplicate {
		t.Fatalf("own busy state disabled metadata actions: %+v, %v", busyView, err)
	}
	app.desktopState.Response.State.TrafficLocked = true
	locked, err := app.profileOrganization(manual.ID)
	if err != nil || locked.CanDuplicate || locked.CanMove {
		t.Fatalf("locked retained state allowed organization actions: %+v, %v", locked, err)
	}
	if _, err := app.profileOrganization("missing-id"); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("missing profile did not return a safe error")
	}
}

func TestDuplicateProfileCopiesEveryProtocolPayloadAndDeepOptions(t *testing.T) {
	corpus, err := os.ReadFile(filepath.Join("..", "protocol", "testdata", "parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Kind   int
		Source string
	}
	if err := json.Unmarshal(corpus, &cases); err != nil {
		t.Fatal(err)
	}
	profiles := make([]Profile, 0, protocol.MaxKind+1)
	seen := make(map[int]bool)
	for _, item := range cases {
		if item.Kind < 0 || item.Kind > protocol.MaxKind || seen[item.Kind] {
			continue
		}
		kind := item.Kind
		p, parseErr := Parse("Protocol copy", item.Source, &kind)
		if parseErr != nil {
			continue
		}
		p.ID, p.Group = newID(), "Manual"
		p.Reliability = &control.ReliabilityOptions{AutoReconnect: true, UseFallbacks: true}
		p.Transport = &protocol.TransportOptions{FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20", MuxConcurrency: 8}
		if Validate(p) != nil {
			continue
		}
		seen[kind] = true
		profiles = append(profiles, p)
	}
	for _, link := range []string{
		"http://user:password@proxy.example:8080#HTTP",
		"trojan://secret@proxy.example:443?sni=proxy.example#Trojan",
		"tuic://11111111-1111-4111-8111-111111111111:secret@proxy.example:443?congestion_control=bbr&udp_relay_mode=quic#TUIC",
		"anytls://secret@proxy.example:443#AnyTLS",
		"naive+https://user:secret@proxy.example:443#Naive",
	} {
		p, parseErr := Parse("Protocol copy", link, nil)
		if parseErr != nil {
			t.Fatalf("parse protocol fixture %q: %v", link, parseErr)
		}
		if !seen[p.Protocol] {
			p.ID, p.Group = newID(), "Manual"
			p.Reliability = &control.ReliabilityOptions{AutoReconnect: true, UseFallbacks: true}
			p.Transport = &protocol.TransportOptions{FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20", MuxConcurrency: 8}
			if Validate(p) != nil {
				t.Fatalf("invalid protocol fixture for kind %d", p.Protocol)
			}
			seen[p.Protocol] = true
			profiles = append(profiles, p)
		}
	}
	if len(seen) != protocol.MaxKind+1 {
		t.Fatalf("parity corpus did not supply all protocol fixtures: got %d of %d", len(seen), protocol.MaxKind+1)
	}
	provider := managementProfile(t, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Provider", "Provider")
	profiles = append(profiles, provider)
	doc := Document{Version: 1, Profiles: profiles, FavoriteIDs: []string{profiles[0].ID}, CollapsedGroups: []string{"Manual", "Unrelated"}, SubscriptionSources: map[string]string{"Provider": "https://example.invalid/feed"}, SubscriptionMetadata: map[string]SubscriptionMetadata{"Provider": {UpdatedAt: "retained"}}}
	store := organizationStore(t, doc)
	app := organizationApp(store, profiles[0].ID)
	initialOrder := make([]string, len(profiles))
	for i := range profiles {
		initialOrder[i] = profiles[i].ID
	}
	for _, original := range profiles[:protocol.MaxKind+1] {
		result, err := app.duplicateProfile(original.ID, "Copy "+original.Name, "Copies", organizationToken(t, store))
		if err != nil {
			t.Fatalf("duplicate protocol %d: %v", original.Protocol, err)
		}
		if result.Added != 1 || result.Selected == nil || result.Selected.ID == original.ID || result.Selected.Protocol != original.Protocol || result.Selected.Source != original.Source || result.Selected.Name != "Copy "+original.Name || result.Selected.Group != "Copies" {
			t.Fatalf("protocol %d copy payload changed: %+v", original.Protocol, result.Selected)
		}
		if result.Selected.Transport == nil || result.Selected.Reliability == nil || result.Selected.Transport == original.Transport || result.Selected.Reliability == original.Reliability || *result.Selected.Transport != *original.Transport || *result.Selected.Reliability != *original.Reliability {
			t.Fatalf("protocol %d copy did not independently preserve options: got=%+v/%+v want=%+v/%+v", original.Protocol, result.Selected.Transport, result.Selected.Reliability, original.Transport, original.Reliability)
		}
		result.Selected.Transport.MuxConcurrency++
		result.Selected.Reliability.AutoReconnect = false
		if original.Transport.MuxConcurrency != 8 || !original.Reliability.AutoReconnect {
			t.Fatalf("protocol %d copy options alias the source", original.Protocol)
		}
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Profiles) != len(profiles)+protocol.MaxKind+1 || !reflect.DeepEqual(saved.FavoriteIDs, []string{profiles[0].ID}) || !reflect.DeepEqual(saved.CollapsedGroups, doc.CollapsedGroups) || !reflect.DeepEqual(saved.SubscriptionSources, doc.SubscriptionSources) || !reflect.DeepEqual(saved.SubscriptionMetadata, doc.SubscriptionMetadata) {
		t.Fatalf("duplicate changed unrelated document metadata: profiles=%d favorites=%v collapse=%v sources=%v metadata=%v", len(saved.Profiles), saved.FavoriteIDs, saved.CollapsedGroups, saved.SubscriptionSources, saved.SubscriptionMetadata)
	}
	for i, id := range initialOrder {
		if saved.Profiles[i].ID != id {
			t.Fatal("duplicate reordered existing profiles")
		}
		if !reflect.DeepEqual(saved.Profiles[i], profiles[i]) {
			t.Fatalf("duplicate changed source profile at stored index %d", i)
		}
	}
}

func TestMoveProfilePreservesIndexFavoriteAndMetadataWithNoOpBytes(t *testing.T) {
	first := managementProfile(t, "11111111-1111-4111-8111-111111111111", "First", "Old")
	first.Transport = &protocol.TransportOptions{FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20", MuxConcurrency: 8}
	first.Reliability = &control.ReliabilityOptions{AutoReconnect: true, UseFallbacks: true}
	last := managementProfile(t, "22222222-2222-4222-8222-222222222222", "Last", "Other")
	doc := Document{Version: 1, Profiles: []Profile{first, last}, FavoriteIDs: []string{first.ID}, CollapsedGroups: []string{"Old", "Other", "Unused"}, SubscriptionSources: map[string]string{"Other": "https://example.invalid/feed"}, SubscriptionMetadata: map[string]SubscriptionMetadata{"Other": {UpdatedAt: "keep"}}}
	store := organizationStore(t, doc)
	app := organizationApp(store, first.ID)
	before, err := os.ReadFile(filepath.Join(store.Root, "profiles.bin"))
	if err != nil {
		t.Fatal(err)
	}
	noop, err := app.moveProfile(first.ID, " Old ", organizationToken(t, store))
	if err != nil || noop.Selected == nil || noop.Selected.Group != "Old" {
		t.Fatalf("same-group move: %+v, %v", noop, err)
	}
	afterNoop, err := os.ReadFile(filepath.Join(store.Root, "profiles.bin"))
	if err != nil || !bytes.Equal(before, afterNoop) {
		t.Fatal("same-group move rewrote store", err)
	}
	result, err := app.moveProfile(first.ID, "Target", organizationToken(t, store))
	if err != nil {
		t.Fatal(err)
	}
	if result.Selected == nil || result.Selected.Group != "Target" || len(result.Document.Profiles) != 2 || result.Document.Profiles[0].ID != first.ID || result.Document.Profiles[1].ID != last.ID {
		t.Fatalf("move changed stored order or selection: %+v", result)
	}
	if !reflect.DeepEqual(result.Document.FavoriteIDs, []string{first.ID}) || !reflect.DeepEqual(result.Document.SubscriptionSources, doc.SubscriptionSources) || !reflect.DeepEqual(result.Document.SubscriptionMetadata, doc.SubscriptionMetadata) || !reflect.DeepEqual(result.Document.CollapsedGroups, []string{"Other", "Unused"}) {
		t.Fatal("move changed favorites or unrelated group metadata")
	}
	if result.Document.Profiles[0].Transport == nil || result.Document.Profiles[0].Reliability == nil || *result.Document.Profiles[0].Transport != *first.Transport || *result.Document.Profiles[0].Reliability != *first.Reliability {
		t.Fatal("move changed profile options")
	}
}

func TestProfileOrganizationRejectsManagedTargetsStaleIDsNamesAndUnsafeState(t *testing.T) {
	manual := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Manual", "Source")
	managed := managementProfile(t, "22222222-2222-4222-8222-222222222222", "Managed", "Provider")
	doc := Document{Version: 1, Profiles: []Profile{manual, managed}, CollapsedGroups: []string{}, SubscriptionSources: map[string]string{"Provider": "https://example.invalid/feed", "MetadataOnly": "https://example.invalid/another"}, SubscriptionMetadata: map[string]SubscriptionMetadata{"Provider": {UpdatedAt: "retained"}}}
	store := organizationStore(t, doc)
	app := organizationApp(store, manual.ID)
	token := organizationToken(t, store)
	before := storeBytes(t, store)
	for _, request := range []struct{ id, name, group, token string }{
		{manual.ID, " ", "Target", token},
		{manual.ID, strings.Repeat("x", 101), "Target", token},
		{manual.ID, "Copy", "Provider", token},
		{manual.ID, "Copy", "Provider", token},
		{manual.ID, "Copy", "Target", "stale-token"},
		{"missing", "Copy", "Target", token},
	} {
		if _, err := app.duplicateProfile(request.id, request.name, request.group, request.token); err == nil {
			t.Fatalf("duplicate accepted invalid request %+v", request)
		}
	}
	if _, err := app.moveProfile(managed.ID, "Target", token); err == nil {
		t.Fatal("subscription profile was moved")
	}
	if _, err := app.moveProfile(manual.ID, "Provider", token); err == nil {
		t.Fatal("move accepted managed destination")
	}
	if !isManagedGroup(Document{SubscriptionMetadata: map[string]SubscriptionMetadata{"MetadataOnly": {}}}, "MetadataOnly") {
		t.Fatal("metadata-only group was not classified as managed")
	}
	app.desktopState.Response.State = control.State{Active: true}
	if _, err := app.duplicateProfile(manual.ID, "Copy", "Target", token); err == nil {
		t.Fatal("duplicate allowed while active")
	}
	app.desktopState.Response.State = control.State{Reconnecting: true}
	if _, err := app.moveProfile(manual.ID, "Target", token); err == nil {
		t.Fatal("move allowed while reconnecting")
	}
	app.desktopState.Response.State = control.State{NeedsRecovery: true}
	if _, err := app.duplicateProfile(manual.ID, "Copy", "Target", token); err == nil {
		t.Fatal("duplicate allowed during recovery")
	}
	app.desktopState.Response.State = control.State{TrafficLocked: true}
	if _, err := app.moveProfile(manual.ID, "Target", token); err == nil {
		t.Fatal("move allowed while traffic locked")
	}
	if !bytes.Equal(before, storeBytes(t, store)) {
		t.Fatal("rejected organization request changed the store")
	}
	stale := organizationToken(t, store)
	changed, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	changed.Profiles[0].Label = "external edit"
	if err := store.Save(changed); err != nil {
		t.Fatal(err)
	}
	staleBytes := storeBytes(t, store)
	if _, err := app.duplicateProfile(manual.ID, "Copy", "Target", stale); err == nil {
		t.Fatal("duplicate accepted a stale store revision")
	}
	if !bytes.Equal(staleBytes, storeBytes(t, store)) {
		t.Fatal("stale duplicate changed the store")
	}
}

func TestProfileOrganizationCorruptAndWriteFailureAreSafe(t *testing.T) {
	profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Profile", "Manual")
	store := organizationStore(t, Document{Version: 1, Profiles: []Profile{profile}, SubscriptionSources: map[string]string{}})
	app := organizationApp(store, profile.ID)
	if _, err := app.profileOrganization("missing"); err == nil {
		t.Fatal("missing profile was accepted")
	}
	before := storeBytes(t, store)
	if err := os.Mkdir(filepath.Join(store.Root, "profiles.bin.new"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := app.duplicateProfile(profile.ID, "Copy", "Copies", organizationToken(t, store)); err == nil {
		t.Fatal("expected save failure")
	}
	if !bytes.Equal(before, storeBytes(t, store)) {
		t.Fatal("write failure modified original store")
	}
	corrupt, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := corrupt.Load(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corrupt.Root, "profiles.bin"), []byte("corrupt synthetic bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Application{Store: corrupt}).profileOrganization(profile.ID); err == nil || strings.Contains(err.Error(), "corrupt synthetic") {
		t.Fatal("corrupt store did not produce safe metadata error")
	}
}

func TestProfileOrganizationUsesNoNetworkAndRunHostSanitizesResponses(t *testing.T) {
	const secret = "PROFILE-ORGANIZATION-CREDENTIAL-SENTINEL"
	profile := fixture(t, "Safe name", "socks5://"+secret+"@example.invalid:1080")
	profile.ID, profile.Group = "11111111-1111-4111-8111-111111111111", "Manual"
	store := organizationStore(t, Document{Version: 1, Profiles: []Profile{profile}, SubscriptionSources: map[string]string{}})
	app := organizationApp(store, profile.ID)
	app.ServiceCall = func(context.Context, control.Request) (control.Response, int64, error) {
		t.Fatal("organization command called service")
		return control.Response{}, 0, nil
	}
	app.Downloader = func(context.Context, string) (ImportResult, error) {
		t.Fatal("organization command called downloader")
		return ImportResult{}, nil
	}
	token := organizationToken(t, store)
	requests := []Request{
		{Version: 1, Command: "ui.profile.organization", ID: profile.ID, Context: &DesktopContext{StorageReady: true, SelectedID: profile.ID}},
		{Version: 1, Command: "ui.profile.duplicate", ID: profile.ID, Name: "Safe name copy", Group: "Copies", Token: token, Context: &DesktopContext{Busy: true, StorageReady: true, SelectedID: profile.ID}},
	}
	var input bytes.Buffer
	for _, request := range requests {
		frame, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var header [4]byte
		binary.LittleEndian.PutUint32(header[:], uint32(len(frame)))
		input.Write(header[:])
		input.Write(frame)
	}
	var output bytes.Buffer
	if err := RunHost(context.Background(), &input, &output, app); err != nil {
		t.Fatal(err)
	}
	wire := output.String()
	if strings.Contains(wire, secret) || strings.Contains(wire, profile.Source) {
		t.Fatal("framed organization response exposed credentials")
	}
	reader := bytes.NewReader(output.Bytes())
	for i := 0; i < len(requests); i++ {
		var header [4]byte
		if _, err := reader.Read(header[:]); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, binary.LittleEndian.Uint32(header[:]))
		if _, err := reader.Read(payload); err != nil {
			t.Fatal(err)
		}
		var reply struct {
			Value any
			Error *string
		}
		if err := json.Unmarshal(payload, &reply); err != nil || reply.Error != nil {
			t.Fatalf("invalid framed response %d: %v / %v", i, err, reply.Error)
		}
		if i == 0 {
			view := reply.Value.(map[string]any)
			assertJSONKeys(t, view, "ID", "Name", "Group", "SuggestedName", "SuggestedGroup", "Token", "ManualTargets", "CanDuplicate", "CanMove")
		} else {
			applied := reply.Value.(map[string]any)
			selected := applied["Selected"].(map[string]any)
			if selected["Source"] != "" {
				t.Fatalf("selected profile source was not sanitized: %+v", selected)
			}
		}
	}
	saved, err := store.Load()
	if err != nil || len(saved.Profiles) != 2 {
		t.Fatalf("framed duplicate was not applied: %d, %v", len(saved.Profiles), err)
	}
}
