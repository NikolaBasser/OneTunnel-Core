package profiles

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/buildinfo"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestFormatDiagnosticsReportCountsAllowlistAndSecrets(t *testing.T) {
	const secret = "DIAGNOSTICS-SECRET-SYNTHETIC"
	doc := Document{Profiles: []Profile{
		{ID: secret, Name: secret, Source: "vless://" + secret + "@example.invalid", Group: secret, Protocol: -1},
		{ID: "other", Name: secret, Source: secret, Group: secret, Protocol: protocol.MaxKind + 1},
	}, SubscriptionSources: map[string]string{secret: "https://example.invalid/" + secret}, SubscriptionMetadata: map[string]SubscriptionMetadata{secret: {UpdatedAt: secret}}}
	for id := 0; id <= protocol.MaxKind; id++ {
		doc.Profiles = append(doc.Profiles, Profile{Protocol: id, Name: secret, Source: secret, Group: secret})
	}

	oldVersion, oldRevision, oldDirty := buildinfo.Version, buildinfo.Revision, buildinfo.Dirty
	buildinfo.Version, buildinfo.Revision, buildinfo.Dirty = "v0.2.0", "0123456789abcdef0123456789abcdef01234567", "true"
	t.Cleanup(func() { buildinfo.Version, buildinfo.Revision, buildinfo.Dirty = oldVersion, oldRevision, oldDirty })
	text, err := formatDiagnosticsReport(doc, map[string]bool{"amneziawg.exe": true, "xray.exe": false, "sing-box.exe": true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, secret) {
		t.Fatal("report contains synthetic profile or subscription data")
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, got, "schemaVersion", "profileHost", "runtime", "profiles", "packageAvailabilityHints")
	assertJSONKeys(t, got["profileHost"].(map[string]any), "version", "revision", "dirty")
	assertJSONKeys(t, got["runtime"].(map[string]any), "goos", "goarch", "goVersion")
	assertJSONKeys(t, got["profiles"].(map[string]any), "total", "unknownProtocolCount", "protocols")
	assertJSONKeys(t, got["packageAvailabilityHints"].(map[string]any), "awg", "xray", "singBox")
	profiles := got["profiles"].(map[string]any)
	if int(profiles["total"].(float64)) != len(doc.Profiles) || int(profiles["unknownProtocolCount"].(float64)) != 2 {
		t.Fatalf("wrong total/unknown counts: %+v", profiles)
	}
	protocols := profiles["protocols"].([]any)
	if len(protocols) != protocol.MaxKind+1 {
		t.Fatalf("got %d protocols", len(protocols))
	}
	for id, value := range protocols {
		entry := value.(map[string]any)
		assertJSONKeys(t, entry, "id", "name", "count")
		if int(entry["id"].(float64)) != id || entry["name"] != protocol.Names[id] || int(entry["count"].(float64)) != 1 {
			t.Fatalf("protocol %d: %+v", id, entry)
		}
	}
	runtimeValue := got["runtime"].(map[string]any)
	if runtimeValue["goos"] != runtime.GOOS || runtimeValue["goarch"] != runtime.GOARCH || runtimeValue["goVersion"] != runtime.Version() {
		t.Fatalf("wrong runtime values: %+v", runtimeValue)
	}
	if !strings.Contains(text, "\n  ") || !strings.HasSuffix(text, "}") {
		t.Fatal("report is not indented JSON")
	}
}

func TestDiagnosticsReportOmitsInvalidBuildText(t *testing.T) {
	oldVersion, oldRevision, oldDirty := buildinfo.Version, buildinfo.Revision, buildinfo.Dirty
	buildinfo.Version, buildinfo.Revision, buildinfo.Dirty = "VERSION-SECRET-"+strings.Repeat("x", 200), "REVISION-SECRET", "unexpected"
	t.Cleanup(func() { buildinfo.Version, buildinfo.Revision, buildinfo.Dirty = oldVersion, oldRevision, oldDirty })
	text, err := formatDiagnosticsReport(Document{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "SECRET") || strings.Contains(text, "unexpected") {
		t.Fatalf("untrusted build text included: %s", text)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	build := got["profileHost"].(map[string]any)
	assertJSONKeys(t, build, "dirty")
	if build["dirty"] != true {
		t.Fatalf("malformed dirty value was not treated as dirty: %+v", build)
	}
}

func TestDiagnosticsReportReadsStoreWithoutServiceOrWrites(t *testing.T) {
	const secret = "DIAGNOSTICS-STORE-SECRET"
	root := t.TempDir()
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	doc := Document{Version: 1, Profiles: []Profile{{ID: "11111111-1111-4111-8111-111111111111", Name: secret, Protocol: 2, Source: vless, Group: secret}}, SubscriptionSources: map[string]string{secret: "https://example.invalid/" + secret}, SubscriptionMetadata: map[string]SubscriptionMetadata{secret: {UpdatedAt: secret}}}
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "profiles.bin")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	serviceCalled := false
	app := &Application{Store: store, Directory: filepath.Join(root, secret), ServiceCall: func(context.Context, control.Request) (control.Response, int64, error) {
		serviceCalled = true
		return control.Response{}, 0, nil
	}}
	value, err := app.Handle(context.Background(), Request{Version: 1, Command: "diagnostics.report"})
	if err != nil {
		t.Fatal(err)
	}
	text, ok := value.(string)
	if !ok || strings.Contains(text, secret) || serviceCalled {
		t.Fatalf("unsafe report or service call: type=%T serviceCalled=%v", value, serviceCalled)
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("diagnostics modified profile store")
	}
}

func TestDiagnosticsReportEmptyAndCorruptStoreErrorsAreSafe(t *testing.T) {
	const secret = "DIAGNOSTICS-PATH-ERROR-SECRET"
	root := t.TempDir()
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	app := &Application{Store: store, Directory: filepath.Join(root, secret), ServiceCall: func(context.Context, control.Request) (control.Response, int64, error) {
		t.Fatal("diagnostics called the service")
		return control.Response{}, 0, nil
	}}
	value, err := app.Handle(context.Background(), Request{Version: 1, Command: "diagnostics.report"})
	if err != nil {
		t.Fatal(err)
	}
	if text, ok := value.(string); !ok || !strings.Contains(text, `"total": 0`) || strings.Contains(text, secret) {
		t.Fatalf("unexpected empty-store report: %v", value)
	}

	path := filepath.Join(root, "profiles.bin")
	if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	value, err = app.Handle(context.Background(), Request{Version: 1, Command: "diagnostics.report"})
	if err == nil || value != nil || err.Error() != errDiagnosticsUnavailable.Error() || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe corrupt-store error: value=%v err=%v", value, err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed diagnostics modified profile store")
	}
}

func assertJSONKeys(t *testing.T, object map[string]any, keys ...string) {
	t.Helper()
	want := append([]string(nil), keys...)
	got := make([]string, 0, len(object))
	for key := range object {
		got = append(got, key)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("JSON keys %v, want %v", got, want)
	}
}
