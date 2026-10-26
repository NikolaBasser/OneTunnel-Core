package profiles

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

type refreshHostReply struct {
	Value json.RawMessage
	Error *string
}

func runRefreshHostRequest(t *testing.T, app *Application, request Request) ([]byte, refreshHostReply) {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(data)))
	input.Write(length[:])
	input.Write(data)
	var output bytes.Buffer
	if err := RunHost(context.Background(), &input, &output, app); err != nil {
		t.Fatal(err)
	}
	if output.Len() < 4 {
		t.Fatal("RunHost returned no framed response")
	}
	if _, err := output.Read(length[:]); err != nil {
		t.Fatal(err)
	}
	responseLength := binary.LittleEndian.Uint32(length[:])
	if int(responseLength) != output.Len() {
		t.Fatalf("response frame size %d does not match %d bytes", responseLength, output.Len())
	}
	responseBytes := make([]byte, responseLength)
	if _, err := output.Read(responseBytes); err != nil {
		t.Fatal(err)
	}
	var reply refreshHostReply
	if err := json.Unmarshal(responseBytes, &reply); err != nil {
		t.Fatal(err)
	}
	return responseBytes, reply
}

func newRefreshTestApp(t *testing.T, source string, downloader func(context.Context, string) (ImportResult, error)) (*Application, Profile) {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	profile := fixture(t, "Saved node", vless)
	profile.Group = "saved group"
	doc.Profiles = []Profile{profile}
	doc.SubscriptionSources = map[string]string{"saved group": source}
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	return &Application{Store: store, Downloader: downloader}, profile
}

func refreshFileBytes(t *testing.T, app *Application) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(app.Store.Root, "profiles.bin"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSubscriptionRefreshPreviewCancelApplyAndCAS(t *testing.T) {
	updatedSource := vless
	oldSource := strings.Replace(vless, "6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a", "7d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a", 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=200; download=300; total=1000; expire=1900000000")
		_, _ = w.Write([]byte(updatedSource))
	}))
	defer server.Close()

	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	fresh := fixture(t, "", updatedSource)
	old := fixture(t, fresh.Name, oldSource)
	old.Group = "saved group"
	old.Transport = &protocol.TransportOptions{Fragment: true, FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20", MuxConcurrency: 8}
	other := fixture(t, "Other group node", vless)
	other.Group = "other group"
	doc.Profiles = []Profile{old, other}
	doc.SubscriptionSources = map[string]string{"saved group": server.URL, "other group": "https://subscription.example/other"}
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}

	app := &Application{Store: store, Downloader: func(ctx context.Context, source string) (ImportResult, error) {
		return downloadWithClient(ctx, source, server.Client())
	}}
	app.desktopContext.Busy = true
	groups, err := app.subscriptionList()
	if err != nil || len(groups) != 2 || !groups[0].CanRefresh {
		t.Fatalf("refresh capability should be Go-owned and independent of the request's Busy flag: %+v, %v", groups, err)
	}
	listJSON, err := json.Marshal(groups)
	if err != nil || strings.Contains(string(listJSON), server.URL) || strings.Contains(string(listJSON), "Source") {
		t.Fatalf("subscription list leaked private data: %s, %v", listJSON, err)
	}
	path := filepath.Join(store.Root, "profiles.bin")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := app.refreshPreview(context.Background(), "saved group")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Added != 0 || preview.Removed != 0 || preview.Updated != 1 || len(preview.Changes) != 1 || !preview.CanApply {
		t.Fatalf("wrong preview: %+v", preview)
	}
	encoded, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), server.URL) || strings.Contains(string(encoded), "Source") || strings.Contains(string(encoded), "6d7a9bdf") {
		t.Fatalf("preview leaked private profile data: %s", encoded)
	}
	afterPreview, err := os.ReadFile(path)
	if err != nil || string(before) != string(afterPreview) {
		t.Fatal("preview wrote the encrypted store", err)
	}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "ui.subscription.refresh.cancel", Token: preview.Token}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.applyRefresh(preview.Token); err == nil {
		t.Fatal("cancelled token was accepted")
	}
	unchanged, _ := os.ReadFile(path)
	if string(before) != string(unchanged) {
		t.Fatal("cancel wrote the encrypted store")
	}

	preview, err = app.refreshPreview(context.Background(), "saved group")
	if err != nil {
		t.Fatal(err)
	}
	result, err := app.applyRefresh(preview.Token)
	if err != nil {
		t.Fatal(err)
	}
	if result.Updated != 1 || result.Added != 0 || result.Removed != 0 || len(result.Document.Profiles) != 2 || result.Document.Profiles[0].Group != "saved group" || result.Document.Profiles[0].ID != old.ID || result.Document.Profiles[0].Transport == nil {
		t.Fatalf("apply did not preserve merge scope/options: %+v", result)
	}
	if result.Document.SubscriptionMetadata["saved group"].Upload == nil || result.Document.SubscriptionMetadata["saved group"].UpdatedAt == "" {
		t.Fatal("provider metadata was not stored on apply")
	}
	viewJSON, err := json.Marshal(presentationValue(result))
	if err != nil || strings.Contains(string(viewJSON), server.URL) || strings.Contains(string(viewJSON), `"Source":"https`) {
		t.Fatalf("applied presentation leaked private data: %s, %v", viewJSON, err)
	}
	if _, err := app.applyRefresh(preview.Token); err == nil {
		t.Fatal("replayed token was accepted")
	}
}

func TestSubscriptionPreviewConflictRequiresFreshReview(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(vless)) }))
	defer server.Close()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	p := fixture(t, "Saved node", vless)
	p.Group = "saved group"
	doc.Profiles = []Profile{p}
	doc.SubscriptionSources = map[string]string{"saved group": server.URL}
	stale := uint64(900)
	doc.SubscriptionMetadata = map[string]SubscriptionMetadata{"saved group": {Upload: &stale, Download: &stale, Total: &stale, UpdatedAt: "old"}}
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	app := &Application{Store: store, Downloader: func(ctx context.Context, source string) (ImportResult, error) {
		return downloadWithClient(ctx, source, server.Client())
	}}
	preview, err := app.refreshPreview(context.Background(), "saved group")
	if err != nil {
		t.Fatal(err)
	}
	current, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	intervening := fixture(t, "New local node", "trojan://synthetic@node.example:443")
	intervening.Group = "local"
	current.Profiles = append(current.Profiles, intervening)
	if err := store.Save(current); err != nil {
		t.Fatal(err)
	}
	if _, err := app.applyRefresh(preview.Token); err == nil {
		t.Fatal("stale reviewed candidate was accepted")
	}
	if app.pendingPreview != nil {
		t.Fatal("conflict retained a usable preview")
	}
	preview, err = app.refreshPreview(context.Background(), "saved group")
	if err != nil {
		t.Fatal(err)
	}
	result, err := app.applyRefresh(preview.Token)
	if err != nil {
		t.Fatal(err)
	}
	metadata := result.Document.SubscriptionMetadata["saved group"]
	if metadata.Upload != nil || metadata.Download != nil || metadata.Total != nil || metadata.UpdatedAt == "" || metadata.UpdatedAt == "old" {
		t.Fatal("successful response without metadata did not clear stale provider values")
	}
}

func TestProviderMetadataDisplayHandlesPartialOverflowAndExpiry(t *testing.T) {
	max := ^uint64(0)
	one, quota := uint64(1), uint64(10)
	upload, download, expire := uint64(20), uint64(30), uint64(1900000000)
	usage, expiry := metadataDisplay(SubscriptionMetadata{Upload: &upload, Download: &download, Total: &quota, Expire: &expire})
	if !strings.Contains(usage, "50 B used") || !strings.Contains(usage, "0 B remaining") || !strings.Contains(expiry, "reported by provider") {
		t.Fatalf("quota clamp or future expiry display failed: %q / %q", usage, expiry)
	}
	usage, expiry = metadataDisplay(SubscriptionMetadata{Upload: &max, Download: &one, Total: &quota})
	if !strings.Contains(usage, "upload") || !strings.Contains(usage, "download") || !strings.Contains(usage, "quota") || !strings.Contains(expiry, "Unknown") {
		t.Fatalf("overflow/zero expiry should remain partial and unknown: %q / %q", usage, expiry)
	}
	expired := uint64(1)
	_, expiry = metadataDisplay(SubscriptionMetadata{Expire: &expired})
	if !strings.Contains(expiry, "1970") {
		t.Fatalf("expired provider date not displayed: %q", expiry)
	}
}

func TestSubscriptionRefreshFramedHostPreviewWrongTokenAndApply(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=12; download=34; total=100; expire=1900000000")
		_, _ = w.Write([]byte(vless))
	}))
	defer server.Close()
	app, _ := newRefreshTestApp(t, server.URL, func(ctx context.Context, source string) (ImportResult, error) {
		return downloadWithClient(ctx, source, server.Client())
	})
	oldUpdatedAt := "2000-01-01T00:00:00Z"
	loaded, err := app.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	loaded.SubscriptionMetadata = map[string]SubscriptionMetadata{"saved group": {UpdatedAt: oldUpdatedAt}}
	if err := app.Store.Save(loaded); err != nil {
		t.Fatal(err)
	}
	before := refreshFileBytes(t, app)
	started := time.Now().UTC()
	previewBytes, previewReply := runRefreshHostRequest(t, app, Request{Version: 1, Command: "ui.subscription.refresh.preview", Group: "saved group"})
	if previewReply.Error != nil {
		t.Fatal(*previewReply.Error)
	}
	var preview SubscriptionPreview
	if err := json.Unmarshal(previewReply.Value, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Token == "" || !preview.CanApply {
		t.Fatalf("incomplete framed preview: %+v", preview)
	}
	if bytes.Contains(previewBytes, []byte(server.URL)) || bytes.Contains(previewBytes, []byte("SubscriptionSources")) || bytes.Contains(previewBytes, []byte(vless)) {
		t.Fatalf("framed preview exposed saved URL or configuration: %s", previewBytes)
	}
	afterPreview := refreshFileBytes(t, app)
	if !bytes.Equal(before, afterPreview) {
		t.Fatal("framed preview changed encrypted storage")
	}
	current, err := app.Store.Load()
	if err != nil || current.SubscriptionMetadata["saved group"].UpdatedAt != oldUpdatedAt {
		t.Fatalf("unapplied preview changed LastUpdated: %+v, %v", current.SubscriptionMetadata, err)
	}
	_, wrongToken := runRefreshHostRequest(t, app, Request{Version: 1, Command: "ui.subscription.refresh.apply", Token: "not-the-preview-token"})
	if wrongToken.Error == nil || app.pendingPreview == nil || app.pendingPreview.token != preview.Token {
		t.Fatal("wrong token either applied or invalidated the valid preview")
	}
	applyBytes, applyReply := runRefreshHostRequest(t, app, Request{Version: 1, Command: "ui.subscription.refresh.apply", Token: preview.Token})
	if applyReply.Error != nil {
		t.Fatal(*applyReply.Error)
	}
	if bytes.Contains(applyBytes, []byte(server.URL)) || bytes.Contains(applyBytes, []byte(`"Source":"https`)) || bytes.Contains(applyBytes, []byte(vless)) {
		t.Fatalf("framed apply exposed saved URL or profile configuration: %s", applyBytes)
	}
	var applied Applied
	if err := json.Unmarshal(applyReply.Value, &applied); err != nil {
		t.Fatal(err)
	}
	updatedAt, err := time.Parse(time.RFC3339, applied.Document.SubscriptionMetadata["saved group"].UpdatedAt)
	if err != nil || updatedAt.Before(started.Add(-time.Second)) || updatedAt.After(time.Now().UTC().Add(time.Second)) {
		t.Fatalf("LastUpdated did not describe the applied network result: %q (%v)", applied.Document.SubscriptionMetadata["saved group"].UpdatedAt, err)
	}
}

func TestSubscriptionRefreshPreviewExpirationRestartAndReplacement(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(vless)) }))
	defer server.Close()
	app, _ := newRefreshTestApp(t, server.URL, func(ctx context.Context, source string) (ImportResult, error) {
		return downloadWithClient(ctx, source, server.Client())
	})
	before := refreshFileBytes(t, app)
	first, err := app.refreshPreview(context.Background(), "saved group")
	if err != nil {
		t.Fatal(err)
	}
	newHost := &Application{Store: app.Store, Downloader: app.Downloader}
	if _, err := newHost.applyRefresh(first.Token); err == nil {
		t.Fatal("new host applied a token from the previous host")
	}
	if app.pendingPreview == nil {
		t.Fatal("new host disturbed the original host's private preview")
	}
	app.pendingPreview.expires = time.Now().Add(-time.Second)
	if _, err := app.applyRefresh(first.Token); err == nil {
		t.Fatal("expired preview was applied")
	}
	if app.pendingPreview != nil {
		t.Fatal("expired preview remained pending")
	}
	second, err := app.refreshPreview(context.Background(), "saved group")
	if err != nil {
		t.Fatal(err)
	}
	third, err := app.refreshPreview(context.Background(), "saved group")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.applyRefresh(second.Token); err == nil {
		t.Fatal("replaced preview token was applied")
	}
	if app.pendingPreview == nil || app.pendingPreview.token != third.Token {
		t.Fatal("replaced-token attempt invalidated the latest preview")
	}
	if !bytes.Equal(before, refreshFileBytes(t, app)) {
		t.Fatal("expired/replaced/new-host token attempts changed storage")
	}
	if _, err := app.applyRefresh(third.Token); err != nil {
		t.Fatal(err)
	}
}

func TestSubscriptionRefreshPolicyAndDownloadFailuresDoNotWrite(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(vless)) }))
	defer server.Close()
	app, _ := newRefreshTestApp(t, server.URL, func(ctx context.Context, source string) (ImportResult, error) {
		return downloadWithClient(ctx, source, server.Client())
	})
	before := refreshFileBytes(t, app)
	for _, state := range []struct {
		name  string
		value struct{ Active, TrafficLocked, Reconnecting bool }
	}{{name: "active", value: struct{ Active, TrafficLocked, Reconnecting bool }{Active: true}}, {name: "locked", value: struct{ Active, TrafficLocked, Reconnecting bool }{TrafficLocked: true}}, {name: "reconnecting", value: struct{ Active, TrafficLocked, Reconnecting bool }{Reconnecting: true}}} {
		t.Run(state.name, func(t *testing.T) {
			app.desktopState.Response.State.Active = state.value.Active
			app.desktopState.Response.State.TrafficLocked = state.value.TrafficLocked
			app.desktopState.Response.State.Reconnecting = state.value.Reconnecting
			if _, err := app.refreshPreview(context.Background(), "saved group"); err == nil {
				t.Fatal("preview passed active/locked/reconnecting policy")
			}
			app.desktopState.Response.State.Active = false
			app.desktopState.Response.State.TrafficLocked = false
			app.desktopState.Response.State.Reconnecting = false
			preview, err := app.refreshPreview(context.Background(), "saved group")
			if err != nil {
				t.Fatal(err)
			}
			app.desktopState.Response.State.Active = state.value.Active
			app.desktopState.Response.State.TrafficLocked = state.value.TrafficLocked
			app.desktopState.Response.State.Reconnecting = state.value.Reconnecting
			if _, err := app.applyRefresh(preview.Token); err == nil {
				t.Fatal("apply passed active/locked/reconnecting policy")
			}
			if !bytes.Equal(before, refreshFileBytes(t, app)) {
				t.Fatal("policy denial changed storage")
			}
		})
	}
	for _, tc := range []struct {
		name     string
		download func(context.Context, string) (ImportResult, error)
	}{
		{name: "failed", download: func(context.Context, string) (ImportResult, error) {
			return ImportResult{}, errors.New("synthetic download failure")
		}},
		{name: "cancelled", download: func(ctx context.Context, _ string) (ImportResult, error) {
			<-ctx.Done()
			return ImportResult{}, ctx.Err()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app.Downloader = tc.download
			ctx := context.Background()
			if tc.name == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if _, err := app.refreshPreview(ctx, "saved group"); err == nil {
				t.Fatal("failed/cancelled download returned a preview")
			}
			if app.pendingPreview != nil {
				t.Fatal("failed/cancelled download left a pending preview")
			}
			if !bytes.Equal(before, refreshFileBytes(t, app)) {
				t.Fatal("failed/cancelled download changed storage")
			}
		})
	}
}

func TestSubscriptionRefreshInterveningEditorAndGroupChangesRejectCandidate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(vless)) }))
	defer server.Close()
	for _, command := range []string{"editor.save", "group.expansion"} {
		t.Run(command, func(t *testing.T) {
			app, _ := newRefreshTestApp(t, server.URL, func(ctx context.Context, source string) (ImportResult, error) {
				return downloadWithClient(ctx, source, server.Client())
			})
			preview, err := app.refreshPreview(context.Background(), "saved group")
			if err != nil {
				t.Fatal(err)
			}
			var request Request
			if command == "editor.save" {
				request = Request{Version: 1, Command: command, Source: "trojan://synthetic@node.example:443", Name: "Local editor addition", Group: "local"}
			} else {
				request = Request{Version: 1, Command: command, Group: "saved group", Expanded: false}
			}
			if _, err := app.Handle(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			conflictedBytes := refreshFileBytes(t, app)
			if _, err := app.applyRefresh(preview.Token); err == nil {
				t.Fatal("intervening editor/group change did not invalidate candidate")
			}
			if !bytes.Equal(conflictedBytes, refreshFileBytes(t, app)) {
				t.Fatal("stale apply changed intervening user data")
			}
		})
	}
}

func TestSubscriptionRefreshRejectsCandidateAboveStoreLimitBeforePending(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(vless)) }))
	defer server.Close()
	app, target := newRefreshTestApp(t, server.URL, func(context.Context, string) (ImportResult, error) {
		fresh := fixture(t, "New target node", strings.Replace(vless, "6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a", "8d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a", 1))
		return ImportResult{Profiles: []Profile{fresh}}, nil
	})
	doc, err := app.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	doc.Profiles = []Profile{}
	filler := fixture(t, "Local filler", vless)
	filler.Group = "local"
	for i := 0; i < 1999; i++ {
		clone := filler
		clone.ID = fmt.Sprintf("00000000-0000-4000-8000-%012x", i+20000)
		doc.Profiles = append(doc.Profiles, clone)
	}
	target = fixture(t, "Retained Trojan node", "trojan://synthetic@node.example:443")
	target.Group = "saved group"
	doc.Profiles = append([]Profile{target}, doc.Profiles...)
	if err := app.Store.Save(doc); err != nil {
		t.Fatal(err)
	}
	before := refreshFileBytes(t, app)
	if _, err := app.refreshPreview(context.Background(), "saved group"); err == nil {
		t.Fatal("candidate above 2000 profiles was accepted")
	}
	if app.pendingPreview != nil {
		t.Fatal("oversized candidate became pending")
	}
	if !bytes.Equal(before, refreshFileBytes(t, app)) {
		t.Fatal("oversized candidate changed storage")
	}
}

func TestSubscriptionRefreshPreviewReturnsAllFourThousandChanges(t *testing.T) {
	const profileCount = 2000
	oldProfiles := make([]Profile, 0, profileCount)
	newProfiles := make([]Profile, 0, profileCount)
	for i := 0; i < profileCount; i++ {
		oldUUID := fmt.Sprintf("00000000-0000-4000-8000-%012x", i+1)
		newUUID := fmt.Sprintf("00000000-0000-4000-8000-%012x", i+10001)
		old, err := Parse(fmt.Sprintf("old-%04d", i), strings.Replace(vless, "6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a", oldUUID, 1), nil)
		if err != nil {
			t.Fatal(err)
		}
		old.Group = "saved group"
		oldProfiles = append(oldProfiles, old)
		fresh, err := Parse(fmt.Sprintf("new-%04d", i), strings.Replace(vless, "6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a", newUUID, 1), nil)
		if err != nil {
			t.Fatal(err)
		}
		newProfiles = append(newProfiles, fresh)
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	doc.Profiles = oldProfiles
	doc.SubscriptionSources = map[string]string{"saved group": "https://subscription.example/synthetic"}
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	app := &Application{Store: store, Downloader: func(context.Context, string) (ImportResult, error) { return ImportResult{Profiles: newProfiles}, nil }}
	preview, err := app.refreshPreview(context.Background(), "saved group")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Added != profileCount || preview.Removed != profileCount || len(preview.Changes) != profileCount*2 {
		t.Fatalf("preview truncated merge changes: counts=%d/%d rows=%d", preview.Added, preview.Removed, len(preview.Changes))
	}
}
