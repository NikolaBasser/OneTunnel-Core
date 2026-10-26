package profiles

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
)

type fakeUserProxy struct {
	enabled, disabled, reconciled int
	address                       string
	err                           error
	ownershipLost                 bool
	conflict                      bool
}

func (p *fakeUserProxy) Owns(string) (bool, error) { return !p.ownershipLost, nil }

func (p *fakeUserProxy) Enable(address string) (string, error) {
	p.enabled++
	p.address = address
	if p.err != nil {
		return "", p.err
	}
	return "fake-lease", nil
}
func (p *fakeUserProxy) Disable(string) (bool, error) { p.disabled++; return p.conflict, p.err }
func (p *fakeUserProxy) Reconcile() (bool, error)     { p.reconciled++; return p.conflict, p.err }

type fakeUserStartup struct {
	enabled, disabled int
	owner             string
	conflict          bool
}

func (s *fakeUserStartup) ProposedCommand(path string) (string, error) {
	return path + " --startup", nil
}
func (s *fakeUserStartup) Status(command string) (bool, error) { return s.owner == command, nil }

func (s *fakeUserStartup) Enable(path, old string) (string, error) {
	s.enabled++
	s.owner = path + " --startup"
	return s.owner, nil
}
func (s *fakeUserStartup) Disable(owner string) (bool, error) { s.disabled++; return s.conflict, nil }

func automationFixture(t *testing.T) (*Application, *fakeUserProxy, *fakeUserStartup, *time.Time, *string) {
	t.Helper()
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Synthetic", "Manual")
	store := managementStore(t, Document{Version: 1, Profiles: []Profile{p}, SubscriptionSources: map[string]string{}})
	proxy, startup := &fakeUserProxy{}, &fakeUserStartup{}
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	owner := ""
	a := &Application{Store: store, Directory: t.TempDir(), Now: func() time.Time { return now }, desktopContext: DesktopContext{StorageReady: true, SelectedID: p.ID}}
	a.UserAutomation = &UserAutomation{NetworkCategory: func() platform.UserNetworkCategory { return platform.UserNetworkPublic }, ProxyFactory: func() (userProxyLease, error) { return proxy, nil }, Startup: startup, ReadStartupOwner: func() (string, error) { return owner, nil }, WriteStartupOwner: func(value string) error { owner = value; return nil }}
	a.UserAutomation.Transaction = func(fn func() error) error { return fn() }
	a.UserAutomation.SessionIdentity = func() (string, error) { return "synthetic-ui-session", nil }
	a.ServiceCall = func(context.Context, control.Request) (control.Response, int64, error) {
		t.Fatal("unexpected service call")
		return control.Response{}, 0, nil
	}
	return a, proxy, startup, &now, &owner
}
func saveAutomation(t *testing.T, a *Application, p UserPreferences) {
	t.Helper()
	view, err := a.userSettingsView()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.saveUserSettings(view.Token, &p); err != nil {
		t.Fatal(err)
	}
}

func TestUserAutomationDisabledAndUnknownNetworkIsPublic(t *testing.T) {
	a, proxy, _, _, _ := automationFixture(t)
	view, err := a.userSettingsView()
	if err != nil || view.Preferences != (UserPreferences{}) || view.NetworkCategory != "public" {
		t.Fatalf("bad defaults: %+v %v", view, err)
	}
	a.UserAutomation.NetworkCategory = func() platform.UserNetworkCategory { return "unknown" }
	view, err = a.userSettingsView()
	if err != nil || view.NetworkCategory != "public" {
		t.Fatalf("unknown became trusted: %+v %v", view, err)
	}
	before := storeBytes(t, a.Store)
	if _, err = a.tickUserSettings(context.Background()); err != nil {
		t.Fatal(err)
	}
	if proxy.enabled != 0 || proxy.disabled != 0 || !reflect.DeepEqual(before, storeBytes(t, a.Store)) {
		t.Fatal("default tick caused effects")
	}
}
func TestUserAutomationDebouncePermissionAndManualInhibition(t *testing.T) {
	a, _, _, now, _ := automationFixture(t)
	saveAutomation(t, a, UserPreferences{AutoConnect: true, ProfileID: "11111111-1111-4111-8111-111111111111", AllowTrusted: true})
	_, _ = a.tickUserSettings(context.Background())
	*now = now.Add(6 * time.Second)
	if _, err := a.tickUserSettings(context.Background()); err != nil {
		t.Fatal(err)
	} // public not permitted
	prefs := UserPreferences{AutoConnect: true, ProfileID: "11111111-1111-4111-8111-111111111111", AllowPublic: true}
	paused := prefs
	paused.AutoConnect = false
	saveAutomation(t, a, paused)
	saveAutomation(t, a, prefs)
	calls := []string{}
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		calls = append(calls, r.Command)
		s := control.State{}
		if r.Command == "start" {
			s.Active = true
			s.LocalPort = 11080
		}
		return control.Response{Version: 1, Instance: "synthetic-instance", Revision: uint64(len(calls)), State: s}, 1, nil
	}
	_, _ = a.tickUserSettings(context.Background())
	if len(calls) != 0 {
		t.Fatal("started before debounce")
	}
	*now = now.Add(6 * time.Second)
	if _, err := a.tickUserSettings(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"status", "status", "start"}) {
		t.Fatalf("unexpected commands: %v", calls)
	}
	if err := a.inhibitUserAutoConnect(); err != nil {
		t.Fatal(err)
	}
	a.desktopState.Response.State = control.State{} // The explicit stop then confirms idle.
	count := len(calls)
	*now = now.Add(time.Hour)
	_, _ = a.tickUserSettings(context.Background())
	if len(calls) != count {
		t.Fatal("manual disconnect was undone")
	}
	// Saving unrelated permissions does not silently clear inhibition.
	prefs.AllowTrusted = true
	saveAutomation(t, a, prefs)
	if !a.UserAutomation.inhibited {
		t.Fatal("unrelated preference cleared inhibition")
	}
	prefs.AutoConnect = false
	saveAutomation(t, a, prefs)
	prefs.AutoConnect = true
	saveAutomation(t, a, prefs)
	if a.UserAutomation.inhibited {
		t.Fatal("explicit off/on did not re-enable automation")
	}
}
func TestUserAutomationNeverRecoversUnavailableOrProtectedService(t *testing.T) {
	for _, state := range []control.State{{Active: true}, {Reconnecting: true}, {TrafficLocked: true}, {NeedsRecovery: true}} {
		t.Run(state.Status, func(t *testing.T) {
			a, _, _, now, _ := automationFixture(t)
			saveAutomation(t, a, UserPreferences{AutoConnect: true, ProfileID: "11111111-1111-4111-8111-111111111111", AllowPublic: true})
			_, _ = a.tickUserSettings(context.Background())
			*now = now.Add(6 * time.Second)
			a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
				if r.Command != "status" {
					t.Fatalf("unsafe command %s", r.Command)
				}
				return control.Response{Version: 1, Instance: "test", Revision: 1, State: state}, 1, nil
			}
			if _, err := a.tickUserSettings(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
	a, _, _, now, _ := automationFixture(t)
	saveAutomation(t, a, UserPreferences{AutoConnect: true, ProfileID: "11111111-1111-4111-8111-111111111111", AllowPublic: true})
	_, _ = a.tickUserSettings(context.Background())
	*now = now.Add(6 * time.Second)
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		if r.Command != "status" {
			t.Fatal("attempted to start unavailable service")
		}
		return control.Response{}, 0, errors.New("private service detail")
	}
	if _, err := a.tickUserSettings(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestUserProxyAuthenticatesListenerAndReleasesBeforeManualStop(t *testing.T) {
	a, proxy, _, _, _ := automationFixture(t)
	saveAutomation(t, a, UserPreferences{UseSystemProxy: true})
	if err := a.initializeUserAutomation(); err != nil || proxy.reconciled != 1 {
		t.Fatal("reconcile not called", err)
	}
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		if r.Command != "status" {
			t.Fatal("proxy requested connection")
		}
		return control.Response{Version: 1, Instance: "test", Revision: 1, State: control.State{Active: true, LocalPort: 11080}}, 1, nil
	}
	view, _ := a.userSettingsView()
	if _, err := a.enableUserProxy(context.Background(), view.Token); err != nil {
		t.Fatal(err)
	}
	if proxy.address != "127.0.0.1:11080" || proxy.enabled != 1 {
		t.Fatalf("arbitrary endpoint: %s", proxy.address)
	}
	if err := a.inhibitUserAutoConnect(); err != nil || proxy.disabled != 1 || a.UserAutomation.lease != "" {
		t.Fatal("lease not released", err)
	}
}
func TestUserSettingsRejectStaleAndMissingTargetWithoutWrites(t *testing.T) {
	a, _, _, _, _ := automationFixture(t)
	before := storeBytes(t, a.Store)
	if _, err := a.saveUserSettings("stale", &UserPreferences{UseSystemProxy: true}); err == nil {
		t.Fatal("accepted stale token")
	}
	view, _ := a.userSettingsView()
	if _, err := a.saveUserSettings(view.Token, &UserPreferences{AutoConnect: true, ProfileID: "missing", AllowPublic: true}); err == nil {
		t.Fatal("accepted missing target")
	}
	if !reflect.DeepEqual(before, storeBytes(t, a.Store)) {
		t.Fatal("invalid settings wrote store")
	}
}
func TestStartupOwnershipIsMachineOnlyEncrypted(t *testing.T) {
	root := t.TempDir()
	if _, err := NewStore(root); err != nil {
		t.Fatal(err)
	}
	const command = `C:\OneTunnel\OneTunnel.exe --startup`
	if err := writeStartupOwner(root, command); err != nil {
		t.Fatal(err)
	}
	got, err := readStartupOwner(root)
	if err != nil || got != command {
		t.Fatalf("ownership roundtrip %q %v", got, err)
	}
	bytes, err := os.ReadFile(filepath.Join(root, "user-machine.bin"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+len(command) <= len(bytes); i++ {
		if string(bytes[i:i+len(command)]) == command {
			t.Fatal("plaintext ownership on disk")
		}
	}
}

func TestUserRegistryCommandsRejectStaleBeforeEffects(t *testing.T) {
	a, proxy, startup, _, _ := automationFixture(t)
	if _, err := a.enableUserProxy(context.Background(), "stale"); err == nil {
		t.Fatal("stale proxy enable accepted")
	}
	if _, err := a.disableUserProxy("stale"); err == nil {
		t.Fatal("stale proxy disable accepted")
	}
	if _, err := a.enableUserStartup(`C:\OneTunnel\OneTunnel.exe`, "stale"); err == nil {
		t.Fatal("stale startup enable accepted")
	}
	if _, err := a.disableUserStartup("stale"); err == nil {
		t.Fatal("stale startup disable accepted")
	}
	if proxy.enabled != 0 || proxy.disabled != 0 || startup.enabled != 0 || startup.disabled != 0 {
		t.Fatal("stale command produced registry effects")
	}
}

func TestProxyReconciliationFailureBlocksActivationAndLostOwnershipClearsView(t *testing.T) {
	a, proxy, _, _, _ := automationFixture(t)
	saveAutomation(t, a, UserPreferences{UseSystemProxy: true})
	proxy.err = errors.New("synthetic stale journal failure")
	if a.initializeUserAutomation() == nil {
		t.Fatal("initialization failure ignored")
	}
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		return control.Response{Version: 1, Instance: "test", Revision: 1, State: control.State{Active: true, LocalPort: 11080}}, 1, nil
	}
	view, _ := a.userSettingsView()
	if _, err := a.enableUserProxy(context.Background(), view.Token); err == nil || proxy.enabled != 0 {
		t.Fatal("failed initialization allowed proxy activation")
	}
	proxy.err = nil
	if _, err := a.disableUserProxy(view.Token); err != nil {
		t.Fatal(err)
	}
	view, _ = a.userSettingsView()
	if _, err := a.enableUserProxy(context.Background(), view.Token); err != nil {
		t.Fatal(err)
	}
	proxy.ownershipLost = true
	view, err := a.userSettingsView()
	if err != nil || view.ProxyEnabled || a.UserAutomation.lease != "" {
		t.Fatal("watchdog-cleared ownership remained active", err)
	}
}

func TestUserAutomationLeaseLossAndHostEOFCleanup(t *testing.T) {
	a, proxy, _, _, _ := automationFixture(t)
	a.UserAutomation.proxy = proxy
	a.UserAutomation.lease = "owned"
	a.UserAutomation.proxyAddress = "127.0.0.1:11080"
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		if r.Command != "status" {
			t.Fatal("unexpected command")
		}
		return control.Response{}, 0, errors.New("service gone")
	}
	if _, err := a.tickUserSettings(context.Background()); err != nil {
		t.Fatal(err)
	}
	if proxy.disabled != 1 || a.UserAutomation.lease != "" {
		t.Fatal("dead listener left system proxy enabled")
	}
	a.UserAutomation.lease = "owned-again"
	if err := RunHost(context.Background(), strings.NewReader(""), io.Discard, a); err != nil {
		t.Fatal(err)
	}
	if proxy.disabled != 2 || a.UserAutomation.lease != "" {
		t.Fatal("EOF failed to release owned proxy")
	}
}

func TestUserAutomationBackupRestoreDisablesActivation(t *testing.T) {
	a, _, _, _, _ := automationFixture(t)
	saveAutomation(t, a, UserPreferences{UseSystemProxy: true, AutoConnect: true, ProfileID: "11111111-1111-4111-8111-111111111111", AllowPublic: true})
	path := filepath.Join(t.TempDir(), "portable.otbackup")
	if _, err := a.exportBackup(path, "synthetic-password-123"); err != nil {
		t.Fatal(err)
	}
	preview, err := a.previewBackupRestore(path, "synthetic-password-123")
	if err != nil {
		t.Fatal(err)
	}
	restored, err := a.applyBackupRestore(preview.Token, true)
	if err != nil {
		t.Fatal(err)
	}
	if restored.UserSettings == nil || restored.UserSettings.AutoConnect || restored.UserSettings.UseSystemProxy || restored.UserSettings.ProfileID == "" {
		t.Fatal("portable restore activated automation or discarded target")
	}
	doc, err := a.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	doc.UserSettings.AutoConnect = true
	doc.Profiles = nil
	if err := a.Store.Save(doc); err != nil {
		t.Fatal(err)
	}
	doc, err = a.Store.Load()
	if err != nil || doc.UserSettings.AutoConnect {
		t.Fatal("deleting target did not disable automation", err)
	}
}

func TestUserAutomaticAttemptsAreBoundedUntilExplicitRearmOrCategoryChange(t *testing.T) {
	a, _, _, now, _ := automationFixture(t)
	category := platform.UserNetworkPublic
	a.UserAutomation.NetworkCategory = func() platform.UserNetworkCategory { return category }
	saveAutomation(t, a, UserPreferences{AutoConnect: true, ProfileID: "11111111-1111-4111-8111-111111111111", AllowPublic: true, AllowTrusted: true})
	starts := 0
	revision := uint64(0)
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		revision++
		response := control.Response{Version: 1, Instance: "test", Revision: revision}
		if r.Command == "start" {
			starts++
			code := "operation_failed"
			response.Error = &code
		} else if r.Command != "status" {
			t.Fatal("unexpected automatic command")
		}
		return response, 1, nil
	}
	_, _ = a.tickUserSettings(context.Background())
	for i := 0; i < 5; i++ {
		*now = now.Add(31 * time.Second)
		if _, err := a.tickUserSettings(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if starts != 3 {
		t.Fatalf("unbounded attempts: %d", starts)
	}
	category = platform.UserNetworkTrusted
	_, _ = a.tickUserSettings(context.Background())
	*now = now.Add(31 * time.Second)
	_, _ = a.tickUserSettings(context.Background())
	if starts != 4 {
		t.Fatal("new allowed category did not rearm")
	}
}

func TestUserAutoConnectRechecksNetworkBeforePreparationAndStart(t *testing.T) {
	for _, stage := range []string{"first status", "second status", "download"} {
		for _, policy := range []string{"public forbidden", "unknown forbidden", "both allowed"} {
			t.Run(stage+"/"+policy, func(t *testing.T) {
				a, _, _, now, _ := automationFixture(t)
				category := platform.UserNetworkTrusted
				a.UserAutomation.NetworkCategory = func() platform.UserNetworkCategory { return category }
				doc, err := a.Store.Load()
				if err != nil {
					t.Fatal(err)
				}
				doc.SubscriptionSources[doc.Profiles[0].Group] = "https://subscription.test/synthetic"
				if err = a.Store.Save(doc); err != nil {
					t.Fatal(err)
				}
				saveAutomation(t, a, UserPreferences{AutoConnect: true, ProfileID: doc.Profiles[0].ID, AllowTrusted: true, AllowPublic: policy == "both allowed"})
				before := storeBytes(t, a.Store)
				statuses, starts, downloads := 0, 0, 0
				changed := false
				change := func() {
					if changed {
						return
					}
					changed = true
					category = platform.UserNetworkPublic
					if policy == "unknown forbidden" {
						category = "unknown"
					}
					// Ensure the old retry cooldown cannot conceal a missing debounce.
					*now = now.Add(31 * time.Second)
				}
				a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
					if r.Command == "status" {
						statuses++
						if stage == "first status" && statuses == 1 || stage == "second status" && statuses == 2 {
							change()
						}
					} else if r.Command == "start" {
						starts++
					} else {
						t.Fatalf("unexpected command %s", r.Command)
					}
					return control.Response{Version: 1, Instance: "synthetic", Revision: uint64(statuses + starts + 1)}, 1, nil
				}
				a.Downloader = func(context.Context, string) (ImportResult, error) {
					downloads++
					if stage == "download" {
						change()
					}
					return ImportResult{}, errors.New("synthetic offline response")
				}
				if _, err = a.tickUserSettings(context.Background()); err != nil {
					t.Fatal(err)
				}
				*now = now.Add(6 * time.Second)
				if _, err = a.tickUserSettings(context.Background()); err != nil {
					t.Fatal(err)
				}
				if !changed {
					t.Fatal("transition injection did not run")
				}
				if starts != 0 {
					t.Fatalf("automatic start after category transition: %d", starts)
				}
				wantDownloads := 0
				if stage == "download" {
					wantDownloads = 1
				}
				if downloads != wantDownloads {
					t.Fatalf("downloads=%d want=%d", downloads, wantDownloads)
				}
				if !reflect.DeepEqual(before, storeBytes(t, a.Store)) {
					t.Fatal("aborted attempt changed storage")
				}
				*now = now.Add(4 * time.Second)
				if _, err = a.tickUserSettings(context.Background()); err != nil {
					t.Fatal(err)
				}
				if starts != 0 {
					t.Fatal("category stability delay bypassed")
				}
				*now = now.Add(2 * time.Second)
				if _, err = a.tickUserSettings(context.Background()); err != nil {
					t.Fatal(err)
				}
				wantStarts := 0
				if policy == "both allowed" {
					wantStarts = 1
				}
				if starts != wantStarts {
					t.Fatalf("stable-category starts=%d want=%d", starts, wantStarts)
				}
			})
		}
	}
}

func TestUnreconciledProxyBlocksPreferenceDisableAndBackupApply(t *testing.T) {
	a, proxy, _, _, _ := automationFixture(t)
	saveAutomation(t, a, UserPreferences{UseSystemProxy: true})
	path := filepath.Join(t.TempDir(), "copy.otbackup")
	if _, err := a.exportBackup(path, "synthetic-password-123"); err != nil {
		t.Fatal(err)
	}
	preview, err := a.previewBackupRestore(path, "synthetic-password-123")
	if err != nil {
		t.Fatal(err)
	}
	proxy.err = errors.New("unreconciled journal")
	if a.initializeUserAutomation() == nil {
		t.Fatal("initialization must fail")
	}
	before := storeBytes(t, a.Store)
	view, err := a.userSettingsView()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.saveUserSettings(view.Token, &UserPreferences{}); err == nil {
		t.Fatal("disabled preference without confirmed reconciliation")
	}
	if _, err := a.applyBackupRestore(preview.Token, false); err == nil {
		t.Fatal("restored while proxy ownership unresolved")
	}
	if !reflect.DeepEqual(before, storeBytes(t, a.Store)) {
		t.Fatal("unreconciled operation rewrote store")
	}
}

func TestBackupApplyReleasesOwnProxyAndFailurePreservesStore(t *testing.T) {
	a, proxy, _, _, _ := automationFixture(t)
	path := filepath.Join(t.TempDir(), "copy.otbackup")
	if _, err := a.exportBackup(path, "synthetic-password-123"); err != nil {
		t.Fatal(err)
	}
	preview, err := a.previewBackupRestore(path, "synthetic-password-123")
	if err != nil {
		t.Fatal(err)
	}
	a.UserAutomation.proxy = proxy
	a.UserAutomation.lease = "own"
	if _, err := a.applyBackupRestore(preview.Token, false); err != nil {
		t.Fatal(err)
	}
	if proxy.disabled != 1 || a.UserAutomation.lease != "" {
		t.Fatal("backup replacement retained owned proxy")
	}
	preview, err = a.previewBackupRestore(path, "synthetic-password-123")
	if err != nil {
		t.Fatal(err)
	}
	a.UserAutomation.lease = "own-again"
	proxy.err = errors.New("restore failed")
	before := storeBytes(t, a.Store)
	if _, err := a.applyBackupRestore(preview.Token, false); err == nil {
		t.Fatal("backup applied without confirmed proxy restore")
	}
	if !reflect.DeepEqual(before, storeBytes(t, a.Store)) || a.backupPreview == nil {
		t.Fatal("failed cleanup changed store or discarded valid preview")
	}
}

func TestExternalUserSettingsConflictsRetainOwnershipAndNotice(t *testing.T) {
	a, proxy, startup, _, owner := automationFixture(t)
	a.UserAutomation.proxy = proxy
	a.UserAutomation.lease = "owned"
	proxy.conflict = true
	view, err := a.userSettingsView()
	if err != nil {
		t.Fatal(err)
	}
	view, err = a.disableUserProxy(view.Token)
	if err != nil || view.ProxyEnabled || !strings.Contains(view.Message, "External proxy changes") {
		t.Fatal("proxy conflict not reported", err)
	}
	*owner = "recorded --startup"
	startup.owner = "external --startup"
	startup.conflict = true
	view, err = a.userSettingsView()
	if err != nil {
		t.Fatal(err)
	}
	view, err = a.disableUserStartup(view.Token)
	if err != nil || !view.StartupRecorded || view.StartupEnabled || *owner != "recorded --startup" || !strings.Contains(view.Message, "External startup changes") {
		t.Fatal("startup conflict erased ownership or hid warning", err)
	}
	view, err = a.userSettingsView()
	if err != nil || !strings.Contains(view.Message, "External startup changes") {
		t.Fatal("notice did not persist across reads", err)
	}
}

func TestStartupReReadsOwnershipInsideFullTransaction(t *testing.T) {
	a, _, startup, _, owner := automationFixture(t)
	view, err := a.userSettingsView()
	if err != nil {
		t.Fatal(err)
	}
	entered := false
	a.UserAutomation.Transaction = func(fn func() error) error {
		entered = true
		*owner = "new concurrent owner"
		defer func() { entered = false }()
		return fn()
	}
	a.UserAutomation.WriteStartupOwner = func(value string) error {
		if !entered {
			t.Fatal("machine ownership write outside transaction")
		}
		*owner = value
		return nil
	}
	if _, err := a.enableUserStartup(`C:\OneTunnel\OneTunnel.exe`, view.Token); err == nil {
		t.Fatal("startup used pre-lock stale owner")
	}
	if startup.enabled != 0 || *owner != "new concurrent owner" {
		t.Fatal("concurrent owner was overwritten")
	}
}
