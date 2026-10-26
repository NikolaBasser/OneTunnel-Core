package profiles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestBackupSealAuthenticatesAndRandomizes(t *testing.T) {
	plain, password := []byte(`{"Version":1,"Profiles":[]}`), []byte("synthetic strong password")
	first, err := sealBackup(plain, password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealBackup(plain, password)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(first, second) {
		t.Fatal("backup encryption reused randomness")
	}
	opened, err := openBackup(first, password)
	if err != nil || string(opened) != string(plain) {
		t.Fatalf("open failed: %v", err)
	}
	clear(opened)
	if _, err := openBackup(first, []byte("wrong synthetic password")); err == nil {
		t.Fatal("wrong password accepted")
	}
	tampered := append([]byte(nil), first...)
	tampered[len(tampered)-1] ^= 1
	if _, err := openBackup(tampered, password); err == nil {
		t.Fatal("tampered envelope accepted")
	}
	if _, err := sealBackup(plain, []byte("short")); err == nil {
		t.Fatal("short password accepted")
	}
	if _, err := sealBackup(make([]byte, backupMaxPlain+1), password); err == nil {
		t.Fatal("oversized plaintext accepted")
	}
}

func TestBackupExportRestoreBindsRevisionAndConsumesToken(t *testing.T) {
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Synthetic", "Provider")
	p.Transport = &protocol.TransportOptions{Fragment: true, FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20", MuxConcurrency: 8}
	p.Reliability = &control.ReliabilityOptions{AutoReconnect: true, UseFallbacks: true}
	p.Network = &protocol.NetworkOptions{DNS: &protocol.DNSOptions{Transport: "https", ServerIP: "1.1.1.1", ServerName: "cloudflare-dns.com", Port: 443, Path: "/dns-query"}, Rules: []protocol.NetworkRule{{Kind: "domain", Value: "example.com", Action: "proxy"}}}
	doc := Document{Version: 1, Profiles: []Profile{p}, FavoriteIDs: []string{p.ID}, CollapsedGroups: []string{"Provider"},
		SubscriptionSources: map[string]string{"Provider": "https://example.invalid/feed"}, SubscriptionMetadata: map[string]SubscriptionMetadata{"Provider": {UpdatedAt: "synthetic"}},
		SubscriptionSchedules: map[string]SubscriptionSchedule{"Provider": {Enabled: true, IntervalMinutes: 60}}}
	store := managementStore(t, doc)
	app := &Application{Store: store}
	path := filepath.Join(t.TempDir(), "synthetic.otbackup")
	storeBefore := sha256.Sum256(storeBytes(t, store))
	if _, err := app.exportBackup(path, "synthetic portable password"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), p.Source) || strings.Contains(string(before), "synthetic portable password") {
		t.Fatal("backup contains plaintext profile data or password")
	}
	if after := sha256.Sum256(storeBytes(t, store)); after != storeBefore {
		t.Fatal("backup export changed the profile store")
	}
	if _, err := app.exportBackup(path, "synthetic portable password"); err == nil {
		t.Fatal("existing backup destination overwritten")
	}
	after, _ := os.ReadFile(path)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("existing backup destination changed")
	}
	preview, err := app.previewBackupRestore(path, "synthetic portable password")
	if err != nil {
		t.Fatal(err)
	}
	if !preview.CanApply || preview.CurrentProfiles != 1 || preview.ReplacementProfiles != 1 || app.backupPreview == nil {
		t.Fatalf("bad preview: %+v", preview)
	}
	if _, err := app.applyBackupRestore("wrong-token", false); err == nil {
		t.Fatal("wrong token applied")
	}
	if preview.EnabledSchedules != 1 {
		t.Fatalf("enabled schedule count missing from preview: %+v", preview)
	}
	result, err := app.applyBackupRestore(preview.Token, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Profiles) != 1 || !reflect.DeepEqual(result.FavoriteIDs, []string{p.ID}) || result.SubscriptionSchedules["Provider"].IntervalMinutes != 60 || result.SubscriptionSchedules["Provider"].Enabled {
		t.Fatalf("restored document lost metadata: %+v", result)
	}
	if result.Profiles[0].Network == nil || !reflect.DeepEqual(result.Profiles[0].Network.Rules, p.Network.Rules) || !reflect.DeepEqual(result.Profiles[0].Transport, p.Transport) || !reflect.DeepEqual(result.Profiles[0].Reliability, p.Reliability) {
		t.Fatal("restore lost saved profile settings")
	}
	if _, err := app.applyBackupRestore(preview.Token, false); err == nil {
		t.Fatal("restore token was reusable")
	}
	preview, err = app.previewBackupRestore(path, "synthetic portable password")
	if err != nil {
		t.Fatal(err)
	}
	result, err = app.applyBackupRestore(preview.Token, true)
	if err != nil || !result.SubscriptionSchedules["Provider"].Enabled {
		t.Fatalf("explicit schedule restore failed: %+v %v", result.SubscriptionSchedules, err)
	}
}

func TestBackupRestoreRejectsWrongPasswordStaleAndExpired(t *testing.T) {
	store := managementStore(t, Document{})
	app := &Application{Store: store, Now: func() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) }}
	path := filepath.Join(t.TempDir(), "candidate.otbackup")
	if _, err := app.exportBackup(path, "synthetic portable password"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.previewBackupRestore(path, "other portable password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	preview, err := app.previewBackupRestore(path, "synthetic portable password")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(Document{Version: 1, Profiles: []Profile{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.applyBackupRestore(preview.Token, false); err == nil {
		t.Fatal("stale preview applied")
	}
	preview, err = app.previewBackupRestore(path, "synthetic portable password")
	if err != nil {
		t.Fatal(err)
	}
	app.Now = func() time.Time { return time.Date(2026, 10, 23, 12, 11, 0, 0, time.UTC) }
	if _, err := app.applyBackupRestore(preview.Token, false); err == nil {
		t.Fatal("expired preview applied")
	}
}

func TestBackupRestoreWriteFailureLeavesProfileFileUnchanged(t *testing.T) {
	store := managementStore(t, Document{})
	app := &Application{Store: store}
	path := filepath.Join(t.TempDir(), "write-failure.otbackup")
	if _, err := app.exportBackup(path, "synthetic portable password"); err != nil {
		t.Fatal(err)
	}
	preview, err := app.previewBackupRestore(path, "synthetic portable password")
	if err != nil {
		t.Fatal(err)
	}
	before := storeBytes(t, store)
	if err := os.Mkdir(filepath.Join(store.Root, "profiles.bin.new"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := app.applyBackupRestore(preview.Token, false); err == nil {
		t.Fatal("restore succeeded despite blocked atomic write")
	}
	if after := storeBytes(t, store); !reflect.DeepEqual(before, after) {
		t.Fatal("failed restore changed original profile file")
	}
	if app.backupPreview != nil {
		t.Fatal("failed apply retained decrypted candidate")
	}
}

func TestBackupPreviewRequiresIdleAndCancelClearsCandidate(t *testing.T) {
	store := managementStore(t, Document{})
	app := &Application{Store: store}
	path := filepath.Join(t.TempDir(), "idle.otbackup")
	if _, err := app.exportBackup(path, "synthetic portable password"); err != nil {
		t.Fatal(err)
	}
	app.desktopState.Response.State.Active = true
	if _, err := app.previewBackupRestore(path, "synthetic portable password"); err == nil {
		t.Fatal("restore preview allowed while connected")
	}
	app.desktopState.Response.State.Active = false
	preview, err := app.previewBackupRestore(path, "synthetic portable password")
	if err != nil {
		t.Fatal(err)
	}
	app.clearBackupRestore(preview.Token)
	if app.backupPreview != nil {
		t.Fatal("cancel retained decrypted candidate")
	}
}

func TestBackupCandidateClearedByLazyExpiryAndHostExit(t *testing.T) {
	store := managementStore(t, Document{})
	base := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	now := base
	newApp := func() (*Application, []Profile, map[string]string, []protocol.NetworkRule) {
		profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Synthetic", "Provider")
		profile.Source = strings.Replace(vless, "6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 1)
		profile.Network = &protocol.NetworkOptions{Rules: []protocol.NetworkRule{{Kind: "domain", Value: "private.synthetic", Action: "proxy"}}}
		candidate := Document{Version: 1, Profiles: []Profile{profile}, SubscriptionSources: map[string]string{"Provider": "https://example.invalid/secret-source"}}
		app := &Application{Store: store, Now: func() time.Time { return now }, backupPreview: &pendingBackupRestore{token: "synthetic-token", candidate: candidate, expires: base.Add(10 * time.Minute)}}
		return app, app.backupPreview.candidate.Profiles, app.backupPreview.candidate.SubscriptionSources, profile.Network.Rules
	}
	app, profiles, sources, rules := newApp()
	now = base.Add(10 * time.Minute)
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "tray.profiles.view"}); err != nil {
		t.Fatal(err)
	}
	if app.backupPreview != nil || profiles[0].ID != "" || profiles[0].Source != "" || len(sources) != 0 || rules[0] != (protocol.NetworkRule{}) {
		t.Fatal("lazy expiry did not clear candidate contents")
	}
	for _, testCase := range []struct {
		input     *strings.Reader
		wantError bool
	}{{strings.NewReader(""), false}, {strings.NewReader("x"), true}} {
		now = base
		host, profiles, sources, rules := newApp()
		err := RunHost(context.Background(), testCase.input, &bytes.Buffer{}, host)
		if (err != nil) != testCase.wantError {
			t.Fatalf("host exit error = %v, wantError %v", err, testCase.wantError)
		}
		if host.backupPreview != nil || profiles[0].ID != "" || profiles[0].Source != "" || len(sources) != 0 || rules[0] != (protocol.NetworkRule{}) {
			t.Fatal("host exit did not clear candidate contents")
		}
	}
}

func TestBackupMalformedDocumentFailsBeforePreview(t *testing.T) {
	plain := []byte(`{"Version":1,"Profiles":[{"ID":"bad"}]}`)
	envelope, err := sealBackup(plain, []byte("synthetic portable password"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bad.otbackup")
	if err := os.WriteFile(path, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	app := &Application{Store: managementStore(t, Document{})}
	if _, err := app.previewBackupRestore(path, "synthetic portable password"); err == nil || app.backupPreview != nil {
		t.Fatal("malformed document previewed")
	}
}

func TestBackupPathRejectsTraversalAndSymlink(t *testing.T) {
	if _, err := backupPath(t.TempDir() + "\\..\\outside.backup"); err == nil {
		t.Fatal("traversal accepted")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err == nil {
		if _, err := backupPath(link); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}

func TestScheduleTickUsesFakeClockAndNeverApplies(t *testing.T) {
	profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Synthetic", "Provider")
	store := managementStore(t, Document{Version: 1, Profiles: []Profile{profile}, SubscriptionSources: map[string]string{"Provider": "https://example.invalid/feed"}, SubscriptionSchedules: map[string]SubscriptionSchedule{"Provider": {Enabled: true, IntervalMinutes: 15}}})
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	calls := 0
	app := &Application{Store: store, Now: func() time.Time { return now }, Downloader: func(context.Context, string) (ImportResult, error) {
		calls++
		return ImportResult{Profiles: []Profile{profile}}, nil
	}}
	view, err := app.scheduleView("Provider")
	if err != nil {
		t.Fatal(err)
	}
	if view.NextCheckAt != now.Add(15*time.Minute).Format(time.RFC3339) {
		t.Fatalf("first due not delayed: %+v", view)
	}
	result, err := app.scheduleTick(context.Background())
	if err != nil || calls != 0 || result.Preview != nil {
		t.Fatalf("scheduled early: %+v calls=%d err=%v", result, calls, err)
	}
	now = now.Add(15 * time.Minute)
	result, err = app.scheduleTick(context.Background())
	if err != nil || calls != 1 || result.Preview == nil {
		t.Fatalf("due tick failed: %+v calls=%d err=%v", result, calls, err)
	}
	if !result.Preview.CanApply {
		t.Fatal("scheduled operation did not create review preview")
	}
	loaded, err := store.Load()
	if err != nil || len(loaded.Profiles) != 1 {
		t.Fatalf("tick applied or damaged profiles: %v", err)
	}
	if _, err := app.scheduleTick(context.Background()); err != nil || calls != 1 {
		t.Fatalf("pending preview overwritten: calls=%d err=%v", calls, err)
	}
}

func TestSchedulePersistenceAndManualPreviewProtection(t *testing.T) {
	profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Synthetic", "Provider")
	store := managementStore(t, Document{Version: 1, Profiles: []Profile{profile}, SubscriptionSources: map[string]string{"Provider": "https://example.invalid/feed"}, SubscriptionSchedules: map[string]SubscriptionSchedule{"Provider": {Enabled: true, IntervalMinutes: 15}}})
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	calls := 0
	app := &Application{Store: store, Now: func() time.Time { return now }, Downloader: func(context.Context, string) (ImportResult, error) {
		calls++
		return ImportResult{Profiles: []Profile{profile}}, nil
	}}
	view, err := app.scheduleView("Provider")
	if err != nil {
		t.Fatal(err)
	}
	saved, err := app.saveSchedule("Provider", view.Token, SubscriptionSchedule{Enabled: true, IntervalMinutes: 60})
	if err != nil {
		t.Fatal(err)
	}
	before := sha256.Sum256(storeBytes(t, store))
	view, err = app.scheduleView("Provider")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.saveSchedule("Provider", view.Token, SubscriptionSchedule{Enabled: true, IntervalMinutes: 60}); err != nil {
		t.Fatal(err)
	}
	if after := sha256.Sum256(storeBytes(t, store)); before != after {
		t.Fatal("idempotent schedule save rewrote store")
	}
	if saved.SubscriptionSchedules["Provider"].IntervalMinutes != 60 {
		t.Fatal("schedule save failed")
	}
	token := managementToken(t, app)
	if _, err := app.renameGroup("Provider", "Renamed", token); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || loaded.SubscriptionSchedules["Renamed"].IntervalMinutes != 60 {
		t.Fatalf("rename lost schedule: %v %+v", err, loaded.SubscriptionSchedules)
	}
	view, err = app.scheduleView("Renamed")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(60 * time.Minute)
	if _, err := app.refreshPreview(context.Background(), "Renamed"); err != nil {
		t.Fatal(err)
	}
	result, err := app.scheduleTick(context.Background())
	if err != nil || calls != 1 || result.Preview != nil {
		t.Fatalf("tick replaced manual review: calls=%d result=%+v err=%v", calls, result, err)
	}
	token = managementToken(t, app)
	if _, err := app.deleteGroup("Renamed", token); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.SubscriptionSchedules) != 0 {
		t.Fatalf("delete kept orphan schedule: %+v", loaded.SubscriptionSchedules)
	}
}

func TestScheduleClockRollbackRebasesFirstDue(t *testing.T) {
	profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Synthetic", "Provider")
	store := managementStore(t, Document{Version: 1, Profiles: []Profile{profile}, SubscriptionSources: map[string]string{"Provider": "https://example.invalid/feed"}, SubscriptionSchedules: map[string]SubscriptionSchedule{"Provider": {Enabled: true, IntervalMinutes: 15}}})
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	calls := 0
	app := &Application{Store: store, Now: func() time.Time { return now }, Downloader: func(context.Context, string) (ImportResult, error) {
		calls++
		return ImportResult{Profiles: []Profile{profile}}, nil
	}}
	view, _ := app.scheduleView("Provider")
	if view.NextCheckAt != now.Add(15*time.Minute).Format(time.RFC3339) {
		t.Fatal(view.NextCheckAt)
	}
	now = now.Add(-5 * time.Minute)
	app.scheduleTick(context.Background())
	now = now.Add(10 * time.Minute)
	app.scheduleTick(context.Background())
	if calls != 0 {
		t.Fatal("clock rollback caused early request")
	}
	view, _ = app.scheduleView("Provider")
	if view.NextCheckAt != now.Add(5*time.Minute).Format(time.RFC3339) {
		t.Fatalf("rollback was not rebased: %+v", view)
	}
}

func TestScheduleMissingDefaultsOffAndDisabledSaveKeepsInterval(t *testing.T) {
	profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Synthetic", "Provider")
	store := managementStore(t, Document{Version: 1, Profiles: []Profile{profile}, SubscriptionSources: map[string]string{"Provider": "https://example.invalid/feed"}})
	app := &Application{Store: store}
	view, err := app.scheduleView("Provider")
	if err != nil || view.Enabled || view.IntervalMinutes != 1440 {
		t.Fatalf("missing default: %+v %v", view, err)
	}
	before := sha256.Sum256(storeBytes(t, store))
	if _, err := app.saveSchedule("Provider", view.Token, SubscriptionSchedule{Enabled: false, IntervalMinutes: 1440}); err != nil {
		t.Fatal(err)
	}
	if after := sha256.Sum256(storeBytes(t, store)); before != after {
		t.Fatal("saving default disabled schedule wrote store")
	}
	if _, err := app.saveSchedule("Provider", view.Token, SubscriptionSchedule{Enabled: true, IntervalMinutes: 15}); err != nil {
		t.Fatal(err)
	}
	view, err = app.scheduleView("Provider")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.saveSchedule("Provider", view.Token, SubscriptionSchedule{Enabled: false, IntervalMinutes: 15}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SubscriptionSchedules["Provider"] != (SubscriptionSchedule{Enabled: false, IntervalMinutes: 15}) {
		t.Fatalf("disabled interval lost: %+v", loaded.SubscriptionSchedules)
	}
}

func TestTrayMetadataIsBoundedPrivateAndReadOnly(t *testing.T) {
	profiles := make([]Profile, trayProfileLimit+1)
	const secret = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	for i := range profiles {
		p := managementProfile(t, "20000000-0000-4000-8000-000000000000", "Name", "Group")
		p.ID = fmtTrayID(i)
		p.Source = strings.Replace(vless, "6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a", secret, 1)
		profiles[i] = p
	}
	store := managementStore(t, Document{Version: 1, Profiles: profiles})
	before := sha256.Sum256(storeBytes(t, store))
	app := &Application{Store: store, desktopContext: DesktopContext{SelectedID: profiles[3].ID, StorageReady: true}}
	view, err := app.trayProfilesView()
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Profiles) != trayProfileLimit || !view.Truncated || view.SelectedID != profiles[3].ID {
		t.Fatalf("bad tray projection: %+v", view)
	}
	serialized, err := json.Marshal(view)
	if err != nil || strings.Contains(string(serialized), secret) {
		t.Fatal("tray JSON exposed profile credentials")
	}
	if strings.Contains(strings.ToLower(strings.Join([]string{view.Profiles[0].Name, view.Profiles[0].Group}, " ")), "secret") {
		t.Fatal("tray metadata leaked credential")
	}
	if _, err := app.traySelect(profiles[3].ID, view.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := app.traySelect(profiles[3].ID, "stale"); err == nil {
		t.Fatal("stale selection accepted")
	}
	after := sha256.Sum256(storeBytes(t, store))
	if before != after {
		t.Fatal("tray selection wrote the store")
	}
	app.desktopState.Response.State.Active = true
	if activeView, err := app.trayProfilesView(); err != nil || activeView.CanSelect {
		t.Fatalf("active profile selection was enabled: %+v %v", activeView, err)
	}
	if _, err := app.traySelect(profiles[3].ID, view.Token); err == nil {
		t.Fatal("selection allowed while connected")
	}
	app.desktopState.Response.State.Active = false
	app.desktopContext.Busy = true
	if busyView, err := app.trayProfilesView(); err != nil || busyView.CanSelect {
		t.Fatalf("selection enabled while busy: %+v %v", busyView, err)
	}
	if _, err := app.traySelect(profiles[3].ID, view.Token); err == nil {
		t.Fatal("selection allowed while busy")
	}
	app.desktopContext.Busy, app.desktopContext.StorageReady = false, false
	if unavailableView, err := app.trayProfilesView(); err != nil || unavailableView.CanSelect {
		t.Fatalf("selection enabled without ready store: %+v %v", unavailableView, err)
	}
}

func TestPhase1ReadCommandsThroughRunHostArePrivateAndOffline(t *testing.T) {
	profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Synthetic", "Provider")
	const secret = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	profile.Source = strings.Replace(vless, "6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a", secret, 1)
	store := managementStore(t, Document{Version: 1, Profiles: []Profile{profile}, SubscriptionSources: map[string]string{"Provider": "https://example.invalid/private-feed"}, SubscriptionSchedules: map[string]SubscriptionSchedule{"Provider": {Enabled: true, IntervalMinutes: 15}}})
	before := sha256.Sum256(storeBytes(t, store))
	calls := 0
	app := &Application{Store: store, Now: func() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) }, Downloader: func(context.Context, string) (ImportResult, error) { calls++; return ImportResult{}, nil }}
	ctx := &DesktopContext{StorageReady: true}
	trayBytes, tray := runRefreshHostRequest(t, app, Request{Version: 1, Command: "ui.tray.profiles.view", Context: ctx})
	if tray.Error != nil || strings.Contains(string(trayBytes), secret) || strings.Contains(string(trayBytes), "private-feed") {
		t.Fatalf("tray IPC leaked private data: %s", trayBytes)
	}
	var trayView TrayProfilesView
	if err := json.Unmarshal(tray.Value, &trayView); err != nil {
		t.Fatal(err)
	}
	_, selected := runRefreshHostRequest(t, app, Request{Version: 1, Command: "tray.profiles.select", ID: profile.ID, Token: trayView.Token, Context: ctx})
	var selectedID string
	if selected.Error != nil || json.Unmarshal(selected.Value, &selectedID) != nil || selectedID != profile.ID {
		t.Fatalf("exact tray selection failed: %s", selected.Value)
	}
	_, schedule := runRefreshHostRequest(t, app, Request{Version: 1, Command: "subscription.schedule.view", Group: "Provider", Context: ctx})
	if schedule.Error != nil {
		t.Fatalf("schedule view failed: %v", schedule.Error)
	}
	_, tick := runRefreshHostRequest(t, app, Request{Version: 1, Command: "subscription.schedule.tick", Context: ctx})
	if tick.Error != nil || calls != 0 {
		t.Fatalf("not-due scheduler accessed provider: calls=%d err=%v", calls, tick.Error)
	}
	if after := sha256.Sum256(storeBytes(t, store)); before != after {
		t.Fatal("read commands modified stored data")
	}
}

func fmtTrayID(index int) string { return fmt.Sprintf("%08x-0000-4000-8000-%012x", index+1, index+1) }

func BenchmarkBackupKDF(b *testing.B) {
	password, salt := []byte("synthetic benchmark password"), make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, err := backupKey(password, salt)
		if err != nil {
			b.Fatal(err)
		}
		clear(key)
	}
}
