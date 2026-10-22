package profiles

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func testApp(t *testing.T) *Application {
	t.Helper()
	store, e := NewStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = store.Load(); e != nil {
		t.Fatal(e)
	}
	return &Application{Store: store, Directory: t.TempDir(), Downloader: Download}
}
func TestGoStoreDPAPIRoundtripConflictAndCorruption(t *testing.T) {
	a := testApp(t)
	p := fixture(t, "🇩🇪 Fixture", vless)
	d := Document{Version: 1, Profiles: []Profile{p}, CollapsedGroups: []string{"🇩🇪 Group"}, SubscriptionSources: map[string]string{}}
	if e := a.Store.Save(d); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(a.Store.Root, "profiles.bin"))
	if e != nil || bytes.Contains(raw, []byte(p.Source)) {
		t.Fatal("plaintext storage")
	}
	loaded, e := a.Store.Load()
	if e != nil || !reflect.DeepEqual(loaded, d) {
		t.Fatal("roundtrip", e)
	}
	other, e := NewStore(a.Store.Root)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = other.Load(); e != nil {
		t.Fatal(e)
	}
	d.Profiles[0].Name = "Other writer"
	if e = other.Save(d); e != nil {
		t.Fatal(e)
	}
	if e = a.Store.Save(loaded); e == nil {
		t.Fatal("stale overwrite allowed")
	}
	backup, e := os.ReadFile(filepath.Join(a.Store.Root, "profiles.bin.before-go.bak"))
	if e != nil || !bytes.Equal(backup, raw) {
		t.Fatal("encrypted original backup missing")
	}
	corrupt := append([]byte(nil), raw...)
	corrupt[len(corrupt)/2] ^= 0xff
	os.WriteFile(filepath.Join(a.Store.Root, "profiles.bin"), corrupt, 0600)
	if _, e = a.Store.Load(); e == nil {
		t.Fatal("corrupted data accepted")
	}
	after, _ := os.ReadFile(filepath.Join(a.Store.Root, "profiles.bin"))
	if !bytes.Equal(corrupt, after) {
		t.Fatal("load modified corrupt input")
	}
}
func TestCSharpEncryptedStorageCompatibility(t *testing.T) {
	source := os.Getenv("ONETUNNEL_PROFILE_FIXTURES")
	if source == "" {
		t.Skip("export synthetic C# DPAPI fixtures first")
	}
	for _, name := range []string{"array", "v1", "future"} {
		t.Run(name, func(t *testing.T) {
			a := testApp(t)
			raw, e := os.ReadFile(filepath.Join(source, name+".bin"))
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(a.Store.Root, "profiles.bin")
			os.WriteFile(path, raw, 0600)
			d, e := a.Store.Load()
			if name == "future" {
				if e == nil {
					t.Fatal("future version accepted")
				}
				after, _ := os.ReadFile(path)
				if !bytes.Equal(after, raw) {
					t.Fatal("future file overwritten")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if name == "array" {
				if len(d.Profiles) != 1 || d.Profiles[0].Group != "Без группы" {
					t.Fatal("array migration")
				}
			} else {
				var expected Document
				b, e := os.ReadFile(filepath.Join(source, "expected.json"))
				if e != nil || json.Unmarshal(b, &expected) != nil {
					t.Fatal("expected data")
				}
				if !reflect.DeepEqual(d, expected) {
					t.Fatal("C# settings lost")
				}
			}
			if e = a.Store.Save(d); e != nil {
				t.Fatal(e)
			}
			if name == "v1" {
				rewritten, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(source, "v1-go.bin"), rewritten, 0600); e != nil {
					t.Fatal(e)
				}
			}
			again, e := a.Store.Load()
			if e != nil || !reflect.DeepEqual(d, again) {
				t.Fatal("Go rewrite changed settings")
			}
			backup, _ := os.ReadFile(path + ".before-go.bak")
			if !bytes.Equal(backup, raw) {
				t.Fatal("migration backup differs")
			}
		})
	}
}
func TestRealStoreCopyMigrationLeavesOriginalUntouched(t *testing.T) {
	path := os.Getenv("ONETUNNEL_REAL_PROFILE_FILE")
	if path == "" {
		t.Skip("optional read-only user-store migration")
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("cannot read user store")
	}
	a := testApp(t)
	if e = os.WriteFile(filepath.Join(a.Store.Root, "profiles.bin"), before, 0600); e != nil {
		t.Fatal(e)
	}
	d, e := a.Store.Load()
	if e != nil {
		t.Fatal("existing user store unreadable")
	}
	if e = a.Store.Save(d); e != nil {
		t.Fatal("copied user store cannot migrate")
	}
	after, e := a.Store.Load()
	if e != nil || !reflect.DeepEqual(d, after) {
		t.Fatal("migration loses user settings")
	}
	actual, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, actual) {
		t.Fatal("original user store changed")
	}
	t.Logf("read-only original; copied %d profiles and %d subscription origins without changes", len(d.Profiles), len(d.SubscriptionSources))
}
func TestLiveSubscriptionRefreshOnUserStoreCopy(t *testing.T) {
	path := os.Getenv("ONETUNNEL_REAL_PROFILE_FILE")
	if path == "" || os.Getenv("ONETUNNEL_LIVE_SUBSCRIPTION_CHECK") != "1" {
		t.Skip("explicit live subscription test on a private copy")
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("cannot read original")
	}
	a := testApp(t)
	os.WriteFile(filepath.Join(a.Store.Root, "profiles.bin"), before, 0600)
	old, e := a.Store.Load()
	if e != nil {
		t.Fatal("cannot read copied profiles")
	}
	tested := false
	for group, source := range old.SubscriptionSources {
		fresh, e := a.Downloader(context.Background(), source)
		if e != nil {
			t.Fatal(e)
		}
		applied, e := a.apply(fresh, source, group)
		if e != nil {
			t.Fatal("cannot apply refreshed subscription")
		}
		for _, p := range old.Profiles {
			for _, updated := range applied.Document.Profiles {
				if p.ID == updated.ID && !reflect.DeepEqual(p.Transport, updated.Transport) {
					t.Fatal("transport settings changed")
				}
			}
			if p.Protocol < 2 {
				found := false
				for _, updated := range applied.Document.Profiles {
					found = found || reflect.DeepEqual(p, updated)
				}
				if !found {
					t.Fatal("native profile changed")
				}
			}
		}
		t.Logf("downloaded %d valid profiles; refreshed private copy; native profiles and preferences retained", len(fresh.Profiles))
		tested = true
		break
	}
	if !tested {
		t.Fatal("no saved subscription origin")
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("original user store changed")
	}
}
func TestGoEditorAndSubscriptionLifecycle(t *testing.T) {
	a := testApp(t)
	r, e := a.SaveEditor(context.Background(), Request{Name: "🇩🇪 Node", Source: vless, Group: "subscription"})
	if e != nil || r.Selected == nil {
		t.Fatal(e)
	}
	original := *r.Selected
	d, _ := a.Store.Load()
	d.SubscriptionSources[original.Group] = "https://subscription.example/test"
	a.Store.Save(d)
	fresh := fixture(t, original.Name, vless+"&type=ws")
	a.Downloader = func(context.Context, string) (ImportResult, error) {
		return ImportResult{Profiles: []Profile{fresh}}, nil
	}
	prepared, e := a.Prepare(context.Background(), original.ID)
	if e != nil || prepared.Selected == nil || prepared.Selected.ID != original.ID || prepared.Selected.Source != fresh.Source {
		t.Fatal("prepare", e)
	}
	a.Downloader = func(context.Context, string) (ImportResult, error) { return ImportResult{}, errors.New("offline") }
	offline, e := a.Prepare(context.Background(), original.ID)
	if e != nil || !offline.Offline || offline.Selected.Source != fresh.Source {
		t.Fatal("cached fallback", e)
	}
	retired := fixture(t, "Different node", vless)
	a.Downloader = func(context.Context, string) (ImportResult, error) {
		return ImportResult{Profiles: []Profile{retired}}, nil
	}
	gone, e := a.Prepare(context.Background(), original.ID)
	if e != nil || !gone.Retired || gone.Selected != nil || len(gone.Document.Profiles) != 1 {
		t.Fatal("retired node must not start", e)
	}
}
func TestSubscriptionHTTPSBoundsAndRedirects(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "http://127.0.0.1/forbidden")
			w.WriteHeader(302)
			return
		}
		w.Write([]byte(vless))
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if !SecureURL(r.URL.String()) {
			return errors.New("insecure redirect")
		}
		return nil
	}
	if r, e := downloadWithClient(context.Background(), server.URL, client); e != nil || len(r.Profiles) != 1 {
		t.Fatal(e)
	}
	if _, e := downloadWithClient(context.Background(), server.URL+"/redirect", client); e == nil {
		t.Fatal("HTTP downgrade allowed")
	}
	if _, e := Download(context.Background(), server.URL); e == nil {
		t.Fatal("untrusted TLS accepted")
	}
}
func TestHostProtocolRejectsUnknownCommandsAndFields(t *testing.T) {
	for _, request := range []string{`{"Version":1,"Command":"hello","Executable":"bad.exe"}`, `{"Version":1,"Command":"unknown"}`} {
		var in, out bytes.Buffer
		binary.Write(&in, binary.LittleEndian, uint32(len(request)))
		in.WriteString(request)
		if e := RunHost(context.Background(), &in, &out, testApp(t)); e != nil {
			t.Fatal(e)
		}
		var length uint32
		binary.Read(&out, binary.LittleEndian, &length)
		var response struct{ Error *string }
		if json.Unmarshal(out.Bytes(), &response) != nil || response.Error == nil {
			t.Fatal("request accepted")
		}
	}
	var in bytes.Buffer
	binary.Write(&in, binary.LittleEndian, uint32(MaxFrame+1))
	if RunHost(context.Background(), &in, &bytes.Buffer{}, testApp(t)) == nil {
		t.Fatal("unbounded frame")
	}
}
func TestFileReadUsesGoAndSupportsUtf16(t *testing.T) {
	a := testApp(t)
	path := filepath.Join(t.TempDir(), "fixture.conf")
	units := []uint16{'[', 'I', 'n', 't', 'e', 'r', 'f', 'a', 'c', 'e', ']'}
	var encoded bytes.Buffer
	encoded.Write([]byte{0xff, 0xfe})
	for _, unit := range units {
		binary.Write(&encoded, binary.LittleEndian, unit)
	}
	os.WriteFile(path, encoded.Bytes(), 0600)
	value, e := a.Handle(context.Background(), Request{Version: 1, Command: "file.read", Path: path})
	if e != nil || value != "[Interface]" {
		t.Fatal("UTF16 file", e)
	}
}
