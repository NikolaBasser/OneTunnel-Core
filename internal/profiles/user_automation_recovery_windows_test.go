package profiles

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"golang.org/x/sys/windows"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUserSafetyNewUISessionRestoresOptInAutomation(t *testing.T) {
	a, _, _, now, _ := automationFixture(t)
	saveAutomation(t, a, UserPreferences{AutoConnect: true, ProfileID: "11111111-1111-4111-8111-111111111111", AllowPublic: true})
	if err := a.inhibitUserAutoConnect(); err != nil {
		t.Fatal(err)
	}
	a.UserAutomation.initialized = false
	a.UserAutomation.SessionIdentity = func() (string, error) { return "different-ui-session", nil }
	if err := a.initializeUserAutomation(); err != nil {
		t.Fatal(err)
	}
	starts := 0
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		state := control.State{}
		if r.Command == "start" {
			starts++
			state.Active = true
			state.LocalPort = 11080
		}
		return control.Response{Version: 1, Instance: "synthetic-new-session", Revision: 1, State: state}, 1, nil
	}
	_, _ = a.tickUserSettings(context.Background())
	*now = now.Add(6 * time.Second)
	_, _ = a.tickUserSettings(context.Background())
	if starts != 1 {
		t.Fatalf("new UI session did not retain opt-in behavior: starts=%d", starts)
	}
}

func TestUserSafetyUnknownSessionOnlyInhibitsAutoConnect(t *testing.T) {
	a, proxy, _, _, _ := automationFixture(t)
	a.UserAutomation.SessionIdentity = func() (string, error) { return "", errors.New("unknown parent") }
	if err := a.initializeUserAutomation(); err != nil {
		t.Fatal(err)
	}
	if !a.UserAutomation.inhibited || a.UserAutomation.initializationErr != nil || proxy.reconciled != 1 {
		t.Fatal("unknown UI session affected proxy reconciliation or enabled auto-connect")
	}
	view, err := a.userSettingsView()
	if err != nil || !view.AutoConnectInhibited {
		t.Fatal("read-only settings were unavailable", err)
	}
}

func TestUserSafetyMachineOwnershipFieldsPreserved(t *testing.T) {
	a, _, _, _, _ := automationFixture(t)
	if err := writeStartupOwner(a.Store.Root, "synthetic-startup-command"); err != nil {
		t.Fatal(err)
	}
	if err := a.inhibitUserAutoConnect(); err != nil {
		t.Fatal(err)
	}
	state, err := readUserMachineOwnership(a.Store.Root)
	if err != nil || state.StartupCommand != "synthetic-startup-command" || state.InhibitedSession != "synthetic-ui-session" {
		t.Fatal("inhibition overwrote startup ownership", err)
	}
	if err := writeStartupOwner(a.Store.Root, "updated-startup-command"); err != nil {
		t.Fatal(err)
	}
	state, err = readUserMachineOwnership(a.Store.Root)
	if err != nil || state.StartupCommand != "updated-startup-command" || state.InhibitedSession != "synthetic-ui-session" {
		t.Fatal("startup overwrote inhibition", err)
	}
}

func TestUserSafetyRecoveryContinuesWhenProxyReleaseFails(t *testing.T) {
	a, proxy, _, _, _ := automationFixture(t)
	a.UserAutomation.proxy, a.UserAutomation.lease = proxy, "synthetic-lease"
	proxy.err = errors.New("synthetic release failure")
	recoveries := 0
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		if r.Command == "recover" {
			recoveries++
		}
		return control.Response{Version: 1, Instance: "synthetic-recovery", Revision: 1}, 1, nil
	}
	if _, err := a.desktop(context.Background(), Request{Version: 1, Command: "connection.recover"}); err != nil {
		t.Fatal(err)
	}
	if recoveries != 1 || !a.UserAutomation.inhibited {
		t.Fatal("proxy error prevented independent service recovery")
	}
}

func TestUserSafetyEnableFailureLeavesPreferencesUnchanged(t *testing.T) {
	for _, failure := range []string{"identity", "persistence"} {
		t.Run(failure, func(t *testing.T) {
			a, _, _, _, _ := automationFixture(t)
			view, err := a.userSettingsView()
			if err != nil {
				t.Fatal(err)
			}
			before := storeBytes(t, a.Store)
			if failure == "identity" {
				a.UserAutomation.SessionIdentity = func() (string, error) { return "", errors.New("synthetic identity failure") }
			} else {
				a.UserAutomation.WriteInhibitedSession = func(string) error { return errors.New("synthetic persistence failure") }
			}
			_, err = a.saveUserSettings(view.Token, &UserPreferences{AutoConnect: true, ProfileID: "11111111-1111-4111-8111-111111111111", AllowPublic: true})
			if err == nil {
				t.Fatal("enable unexpectedly succeeded")
			}
			doc, err := a.Store.Load()
			if err != nil || preferencesValue(doc.UserSettings).AutoConnect || fmtHex(a.Store.revision[:]) != view.Token || !reflect.DeepEqual(before, storeBytes(t, a.Store)) {
				t.Fatal("failed enable partially saved preferences", err)
			}
		})
	}
}

func TestUserSafetyStopStillRestoresProxyAfterInhibitionWriteFailure(t *testing.T) {
	a, proxy, _, _, _ := automationFixture(t)
	a.UserAutomation.proxy, a.UserAutomation.lease = proxy, "synthetic-lease"
	a.UserAutomation.WriteInhibitedSession = func(string) error { return errors.New("synthetic persistence failure") }
	stops := 0
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		if r.Command == "stop" {
			stops++
		}
		return control.Response{Version: 1, Instance: "synthetic-stop", Revision: 1}, 1, nil
	}
	if _, err := a.desktop(context.Background(), Request{Version: 1, Command: "connection.stop"}); err != nil {
		t.Fatal(err)
	}
	if stops != 1 || proxy.disabled != 1 || a.UserAutomation.lease != "" || !a.UserAutomation.inhibited {
		t.Fatal("machine write failure blocked stop or owned-proxy restoration")
	}
}

func TestUserSafetyAutomaticStartRejectsRevokedPreferences(t *testing.T) {
	a, _, _, now, _ := automationFixture(t)
	saveAutomation(t, a, UserPreferences{AutoConnect: true, ProfileID: "11111111-1111-4111-8111-111111111111", AllowPublic: true})
	starts := 0
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		if r.Command == "status" {
			doc, err := a.Store.Load()
			if err != nil {
				t.Fatal(err)
			}
			doc.UserSettings = nil
			if err := a.Store.Save(doc); err != nil {
				t.Fatal(err)
			}
		}
		if r.Command == "start" {
			starts++
		}
		return control.Response{Version: 1, Instance: "synthetic-revocation", Revision: 1}, 1, nil
	}
	_, _ = a.tickUserSettings(context.Background())
	*now = now.Add(6 * time.Second)
	_, _ = a.tickUserSettings(context.Background())
	if starts != 0 {
		t.Fatal("revoked automatic connection preferences still caused start")
	}
}

func TestUserSafetyManualStopSurvivesProfileHostRestart(t *testing.T) {
	a, _, _, now, _ := automationFixture(t)
	saveAutomation(t, a, UserPreferences{AutoConnect: true, ProfileID: "11111111-1111-4111-8111-111111111111", AllowPublic: true})
	if err := a.inhibitUserAutoConnect(); err != nil {
		t.Fatal(err)
	}
	old := a.UserAutomation
	restarted := *a
	restarted.UserAutomation = &UserAutomation{SessionIdentity: old.SessionIdentity, NetworkCategory: old.NetworkCategory, ProxyFactory: old.ProxyFactory, Startup: old.Startup, ReadStartupOwner: old.ReadStartupOwner, WriteStartupOwner: old.WriteStartupOwner, Transaction: old.Transaction}
	if err := restarted.initializeUserAutomation(); err != nil {
		t.Fatal(err)
	}
	starts := 0
	restarted.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		s := control.State{}
		if r.Command == "start" {
			starts++
			s.Active = true
			s.LocalPort = 11080
		}
		return control.Response{Version: 1, Instance: "audit-only", Revision: 1, State: s}, 1, nil
	}
	if _, err := restarted.tickUserSettings(context.Background()); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(6 * time.Second)
	if _, err := restarted.tickUserSettings(context.Background()); err != nil {
		t.Fatal(err)
	}
	if starts != 0 {
		t.Fatalf("manual stop undone after profile-host restart: %d synthetic start calls", starts)
	}
}
func TestUserSafetyManualRecoveryInhibitsAutomaticReconnect(t *testing.T) {
	a, _, _, now, _ := automationFixture(t)
	saveAutomation(t, a, UserPreferences{AutoConnect: true, ProfileID: "11111111-1111-4111-8111-111111111111", AllowPublic: true})
	starts := 0
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		s := control.State{}
		if r.Command == "start" {
			starts++
			s.Active = true
			s.LocalPort = 11080
		}
		return control.Response{Version: 1, Instance: "audit-only", Revision: 1, State: s}, 1, nil
	}
	if _, err := a.desktop(context.Background(), Request{Version: 1, Command: "connection.recover"}); err != nil {
		t.Fatal(err)
	}
	_, _ = a.tickUserSettings(context.Background())
	*now = now.Add(6 * time.Second)
	_, _ = a.tickUserSettings(context.Background())
	if starts != 0 {
		t.Fatalf("explicit recovery undone: %d synthetic start calls", starts)
	}
}
func TestUserSafetyProxyEnableRejectsPreferenceChangedDuringStatus(t *testing.T) {
	a, proxy, _, _, _ := automationFixture(t)
	saveAutomation(t, a, UserPreferences{UseSystemProxy: true})
	view, err := a.userSettingsView()
	if err != nil {
		t.Fatal(err)
	}
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		doc, e := a.Store.Load()
		if e != nil {
			t.Fatal(e)
		}
		doc.UserSettings = nil
		if e = a.Store.Save(doc); e != nil {
			t.Fatal(e)
		}
		return control.Response{Version: 1, Instance: "audit-only", Revision: 1, State: control.State{Active: true, LocalPort: 11080}}, 1, nil
	}
	_, _ = a.enableUserProxy(context.Background(), view.Token)
	if proxy.enabled != 0 {
		t.Fatalf("proxy enabled %d times after preference was revoked during status", proxy.enabled)
	}
}

func TestUserSafetyStoreMutexSurvivesGoroutineMigration(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runtime.LockOSThread()
	ownerThread := windows.GetCurrentThreadId()
	release, err := store.lock()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(strings.ToUpper(store.Root)))
	retained, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr("Local\\OneTunnel.ProfileStore."+fmtHex(sum[:])))
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		release()
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer windows.CloseHandle(retained)
	runtime.UnlockOSThread()
	migrated := false
	for i := 0; i < 10000; i++ {
		runtime.Gosched()
		if windows.GetCurrentThreadId() != ownerThread {
			migrated = true
			break
		}
	}
	release()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, err := windows.WaitForSingleObject(retained, 50)
	if result == windows.WAIT_OBJECT_0 || result == windows.WAIT_ABANDONED {
		windows.ReleaseMutex(retained)
	}
	if err != nil || result != windows.WAIT_OBJECT_0 {
		t.Fatalf("store mutex not released after migration=%v: wait=%v err=%v", migrated, result, err)
	}
}
