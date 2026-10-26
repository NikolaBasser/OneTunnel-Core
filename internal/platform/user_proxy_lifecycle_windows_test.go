//go:build windows

package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestUserProxyEnableWritesJournalBeforeWatchdogAndProxyChanges(t *testing.T) {
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{
		fakeValueKey(userProxyRegistryKey, "ProxyEnable"): {Exists: true, Type: registry.DWORD, Data: []byte{0, 0, 0, 0}},
		fakeValueKey(userProxyRegistryKey, "ProxyServer"): {Exists: true, Type: registry.SZ, Data: registryStringBytes("http=old-proxy:8080")},
	}}
	path := filepath.Join(t.TempDir(), "lease.json")
	proxy, notifyCalls := fakeEnableProxy(reg, path)
	proxy.armWatchdog = func(lease string, pid uint32, created uint64, journal string) error {
		reg.events = append(reg.events, "watchdog")
		if filepath.Clean(journal) != filepath.Clean(path) {
			t.Fatalf("watchdog got unexpected journal path %q", journal)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("journal was not durable before watchdog arm: %v", err)
		}
		var got proxyJournal
		if err = json.Unmarshal(b, &got); err != nil || got.LeaseID != lease || got.OwnerPID != pid || got.OwnerCreated != created {
			t.Fatalf("unexpected pre-arm journal %#v, err=%v", got, err)
		}
		if !sameRegistryValue(reg.values[fakeValueKey(userProxyRegistryKey, "ProxyEnable")], RawRegistryValue{Exists: true, Type: registry.DWORD, Data: []byte{0, 0, 0, 0}}) ||
			!sameRegistryValue(reg.values[fakeValueKey(userProxyRegistryKey, "ProxyServer")], RawRegistryValue{Exists: true, Type: registry.SZ, Data: registryStringBytes("http=old-proxy:8080")}) {
			t.Fatal("proxy settings changed before watchdog was armed")
		}
		return nil
	}
	if _, err := proxy.Enable("127.0.0.1:19080"); err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{"journal", "watchdog", "ProxyServer", "ProxyEnable"}
	if !reflect.DeepEqual(reg.events, wantOrder) {
		t.Fatalf("activation order=%v, want %v", reg.events, wantOrder)
	}
	if !reg.values[fakeValueKey(userProxyRegistryKey, "ProxyEnable")].Exists || !reg.values[fakeValueKey(userProxyRegistryKey, "ProxyServer")].Exists {
		t.Fatal("proxy settings were not applied after watchdog arm")
	}
	if *notifyCalls != 1 {
		t.Fatalf("notify calls=%d, want 1", *notifyCalls)
	}
}

func TestUserProxyEnableWatchdogArmFailureLeavesProxyUntouched(t *testing.T) {
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{}}
	path := filepath.Join(t.TempDir(), "lease.json")
	proxy, _ := fakeEnableProxy(reg, path)
	proxy.armWatchdog = func(string, uint32, uint64, string) error { return errors.New("watchdog failed") }
	if _, err := proxy.Enable("127.0.0.1:19081"); err == nil {
		t.Fatal("watchdog failure was ignored")
	}
	assertOriginalProxyState(t, reg)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("failed activation journal remains: %v", err)
	}
}

func TestWatchdogMustBreakAwayAndConfirmJobMembership(t *testing.T) {
	flags := userProxyWatchdogCreationFlags()
	for _, required := range []uint32{windows.DETACHED_PROCESS, windows.CREATE_NO_WINDOW, windows.CREATE_BREAKAWAY_FROM_JOB} {
		if flags&required != required {
			t.Fatalf("watchdog creation flags %#x omit required flag %#x", flags, required)
		}
	}
	if err := ensureWatchdogOutsideJob(false, nil); err != nil {
		t.Fatalf("uncontained watchdog rejected: %v", err)
	}
	if err := ensureWatchdogOutsideJob(true, nil); err == nil {
		t.Fatal("watchdog still inside a job was accepted")
	}
	if err := ensureWatchdogOutsideJob(false, errors.New("query failed")); err == nil {
		t.Fatal("unknown job membership was accepted")
	}
}

func TestWatchdogInvalidListenerIsNotAcknowledged(t *testing.T) {
	signals := 0
	err := acknowledgeWatchdogReady("0.0.0.0:19080", func() error { signals++; return nil })
	if err == nil || signals != 0 {
		t.Fatalf("invalid listener err=%v signals=%d", err, signals)
	}
}

func TestWatchdogMonitorErrorStillAttemptsLeaseRecovery(t *testing.T) {
	proxy, _, path, read := fakeWatchdogRecoveryState(t)
	monitorErr := errors.New("monitor failed")
	err := finishProxyWatchdog(monitorErr, func() error {
		return restoreProxyLeaseAfterWatchEnd(proxy, "lease-retry", read, func() (func(), error) { return func() {}, nil }, func(time.Duration) {})
	})
	if !errors.Is(err, monitorErr) {
		t.Fatalf("monitor error was lost: %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("monitor error skipped exact-lease restore: %v", statErr)
	}
}

func TestUserProxyEnablePartialWriteFailureRollsBack(t *testing.T) {
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{}}
	reg.failWrite = "ProxyServer"
	path := filepath.Join(t.TempDir(), "lease.json")
	proxy, _ := fakeEnableProxy(reg, path)
	proxy.armWatchdog = func(string, uint32, uint64, string) error { return nil }
	if _, err := proxy.Enable("127.0.0.1:19082"); err == nil {
		t.Fatal("partial registry write failure was ignored")
	}
	assertOriginalProxyState(t, reg)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("successful rollback should remove journal, got stat error %v", err)
	}
}

func TestUserProxyEnableNotifyFailureRollsBackAndKeepsRecoveryJournal(t *testing.T) {
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{}}
	path := filepath.Join(t.TempDir(), "lease.json")
	proxy, notifyCalls := fakeEnableProxy(reg, path)
	proxy.armWatchdog = func(string, uint32, uint64, string) error { return nil }
	proxy.notify = func() error { *notifyCalls++; return errors.New("WinINET notification failed") }
	if _, err := proxy.Enable("127.0.0.1:19083"); err == nil {
		t.Fatal("notification failure was ignored")
	}
	assertOriginalProxyState(t, reg)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("failed notification must retain recovery journal: %v", err)
	}
	if *notifyCalls != 2 {
		t.Fatalf("notify calls=%d, want activation and rollback notifications", *notifyCalls)
	}
}

func TestUserProxyOwnsAndDisableHandleWatchdogClearedLease(t *testing.T) {
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{}}
	path := filepath.Join(t.TempDir(), "user-proxy.dpapi")
	proxy := &UserProxy{registry: reg, journalPath: path, lockAutomation: func() (func(), error) { return func() {}, nil }}
	if owns, err := proxy.Owns("lease-1"); err != nil || owns {
		t.Fatalf("missing journal ownership=%v err=%v", owns, err)
	}
	if conflict, err := proxy.Disable("lease-1"); err != nil || conflict {
		t.Fatalf("disable after watchdog cleanup: conflict=%v err=%v", conflict, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("idempotent disable created journal: %v", err)
	}
	if owns, err := proxy.Owns("lease-1"); err != nil || owns {
		t.Fatalf("watchdog-cleared lease ownership=%v err=%v", owns, err)
	}

	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	created, err := currentProcessCreationTime()
	if err != nil {
		t.Fatal(err)
	}
	applied := map[string]RawRegistryValue{
		"ProxyEnable": {Exists: true, Type: registry.DWORD, Data: []byte{1, 0, 0, 0}},
		"ProxyServer": {Exists: true, Type: registry.SZ, Data: registryStringBytes("http=127.0.0.1:19084;https=127.0.0.1:19084")},
	}
	for name, value := range applied {
		reg.values[fakeValueKey(userProxyRegistryKey, name)] = cloneRaw(value)
	}
	journal := proxyJournal{
		Schema: userProxyJournalSchema, LeaseID: "lease-1", OwnerSID: sid,
		OwnerPID: windows.GetCurrentProcessId(), OwnerCreated: created, Listener: "127.0.0.1:19084",
		Baseline: map[string]RawRegistryValue{"ProxyEnable": {}, "ProxyServer": {}}, Applied: applied,
	}
	if err = proxy.writeJournal(journal); err != nil {
		t.Fatal(err)
	}
	if owns, err := proxy.Owns("lease-1"); err != nil || !owns {
		t.Fatalf("current journal ownership=%v err=%v", owns, err)
	}
	if owns, err := proxy.Owns("lease-other"); err != nil || owns {
		t.Fatalf("foreign lease ownership=%v err=%v", owns, err)
	}
	if conflict, err := proxy.Disable("lease-other"); err == nil || conflict {
		t.Fatalf("foreign lease disable should be rejected: conflict=%v err=%v", conflict, err)
	}
	if owns, err := proxy.Owns("lease-1"); err != nil || !owns {
		t.Fatalf("foreign disable changed current lease: owns=%v err=%v", owns, err)
	}
	if conflict, err := proxy.Disable("lease-1"); err != nil || conflict {
		t.Fatalf("owned disable: conflict=%v err=%v", conflict, err)
	}
	if owns, err := proxy.Owns("lease-1"); err != nil || owns {
		t.Fatalf("restored lease still reported owned=%v err=%v", owns, err)
	}
}

func TestWatchdogListenerMonitorRequiresThreeConsecutiveFailures(t *testing.T) {
	ticks := 0
	probes := 0
	listenerFailed, err := monitorProxyOwnerAndListener(func(interval time.Duration) (bool, error) {
		if interval != 2*time.Second {
			t.Fatalf("wait interval=%s", interval)
		}
		ticks++
		return false, nil
	}, func(address string, timeout time.Duration) error {
		if address != "127.0.0.1:19876" || timeout != time.Second {
			t.Fatalf("unexpected listener probe %q timeout=%s", address, timeout)
		}
		probes++
		return errors.New("listener unavailable")
	}, "127.0.0.1:19876", 2*time.Second, 3)
	if err != nil || !listenerFailed || ticks != 3 || probes != 3 {
		t.Fatalf("listenerFailed=%v ticks=%d probes=%d err=%v", listenerFailed, ticks, probes, err)
	}
}

func TestWatchdogListenerMonitorResetsAfterSuccessfulProbe(t *testing.T) {
	ticks := 0
	probeResults := []error{errors.New("one"), nil, errors.New("two"), errors.New("three"), errors.New("four")}
	listenerFailed, err := monitorProxyOwnerAndListener(func(time.Duration) (bool, error) {
		ticks++
		return false, nil
	}, func(string, time.Duration) error { return probeResults[ticks-1] }, "127.0.0.1:19877", 2*time.Second, 3)
	if err != nil || !listenerFailed || ticks != 5 {
		t.Fatalf("listenerFailed=%v ticks=%d err=%v", listenerFailed, ticks, err)
	}
}

func TestWatchdogListenerMonitorStopsWhenOwnerExits(t *testing.T) {
	probes := 0
	listenerFailed, err := monitorProxyOwnerAndListener(func(time.Duration) (bool, error) { return true, nil }, func(string, time.Duration) error {
		probes++
		return nil
	}, "127.0.0.1:19878", 2*time.Second, 3)
	if err != nil || listenerFailed || probes != 0 {
		t.Fatalf("listenerFailed=%v probes=%d err=%v", listenerFailed, probes, err)
	}
	if _, err = monitorProxyOwnerAndListener(func(time.Duration) (bool, error) { return false, nil }, func(string, time.Duration) error { return nil }, "example.com:80", 2*time.Second, 3); err == nil {
		t.Fatal("non-loopback hostname was accepted for watchdog probing")
	}
}

func TestWatchdogStopsPollingWhenLeaseIsRemoved(t *testing.T) {
	waits, checks, probes := 0, 0, 0
	failed, err := monitorProxyLeaseOwnerAndListener(func(time.Duration) (bool, error) {
		waits++
		return false, nil
	}, func() (bool, error) {
		checks++
		return false, nil
	}, func(string, time.Duration) error {
		probes++
		return nil
	}, "127.0.0.1:19879", 2*time.Second, 3)
	if err != nil || failed || waits != 1 || checks != 1 || probes != 0 {
		t.Fatalf("failed=%v waits=%d checks=%d probes=%d err=%v", failed, waits, checks, probes, err)
	}
}

func TestNewUserProxyAtUsesOnlyConfiguredRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ONETUNNEL_DATA_DIR", root)
	proxy, err := NewUserProxyAt(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := filepath.Clean(proxy.journalPath), filepath.Join(filepath.Clean(root), "user-proxy.dpapi"); got != want {
		t.Fatalf("journal path=%q, want %q", got, want)
	}
	if _, err = NewUserProxyAt(filepath.Join(root, "other")); err == nil {
		t.Fatal("unconfigured root was accepted")
	}
}

func TestProxyJournalDurablePublicationDoesNotOverwriteExistingLease(t *testing.T) {
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "user-proxy.dpapi")
	proxy := &UserProxy{journalPath: path}
	first := proxyJournal{
		Schema: userProxyJournalSchema, LeaseID: "lease-first", OwnerSID: sid,
		Listener: "127.0.0.1:19090",
		Baseline: map[string]RawRegistryValue{},
		Applied:  map[string]RawRegistryValue{"ProxyEnable": {Exists: true, Type: registry.DWORD, Data: []byte{1, 0, 0, 0}}},
	}
	if err = proxy.writeJournal(first); err != nil {
		t.Fatal(err)
	}
	loaded, err := proxy.readJournal()
	if err != nil || loaded.LeaseID != first.LeaseID {
		t.Fatalf("journal round trip lease=%q err=%v", loaded.LeaseID, err)
	}
	second := first
	second.LeaseID = "lease-second"
	if err = proxy.writeJournal(second); err == nil {
		t.Fatal("existing lease journal was overwritten")
	}
	loaded, err = proxy.readJournal()
	if err != nil || loaded.LeaseID != first.LeaseID {
		t.Fatalf("prior journal changed lease=%q err=%v", loaded.LeaseID, err)
	}
}

func fakeEnableProxy(reg *fakeUserRegistry, path string) (*UserProxy, *int) {
	notifyCalls := 0
	proxy := &UserProxy{registry: reg, journalPath: path}
	proxy.lockAutomation = func() (func(), error) { return func() {}, nil }
	proxy.ownerIdentity = func() (string, uint32, uint64, error) { return "S-1-5-21-test", 456, 789, nil }
	proxy.queryProxyFlags = func() (uint32, error) { return 0, nil }
	proxy.probeListener = func(address string, timeout time.Duration) error { return nil }
	proxy.writeJournalFn = func(j proxyJournal) error {
		reg.events = append(reg.events, "journal")
		b, err := json.Marshal(j)
		if err != nil {
			return err
		}
		return os.WriteFile(path, b, 0600)
	}
	proxy.notify = func() error { notifyCalls++; return nil }
	return proxy, &notifyCalls
}

func assertOriginalProxyState(t *testing.T, reg *fakeUserRegistry) {
	t.Helper()
	for _, name := range []string{"ProxyEnable", "ProxyServer"} {
		if value := reg.values[fakeValueKey(userProxyRegistryKey, name)]; value.Exists {
			t.Errorf("%s should have returned to absent baseline: %#v", name, value)
		}
	}
}

func TestWatchdogOwnerHelper(t *testing.T) {
	if os.Getenv("ONETUNNEL_WATCHDOG_HELPER") != "owner" {
		return
	}
	stopPath := os.Getenv("ONETUNNEL_WATCHDOG_OWNER_STOP")
	for {
		if _, err := os.Stat(stopPath); err == nil {
			process, e := windows.GetCurrentProcess()
			if e != nil {
				t.Fatal(e)
			}
			if e = windows.TerminateProcess(process, 73); e != nil {
				t.Fatal(e)
			}
			t.Fatal("TerminateProcess unexpectedly returned")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWatchdogRecoveryHelper(t *testing.T) {
	if os.Getenv("ONETUNNEL_WATCHDOG_HELPER") != "watcher" {
		return
	}
	ownerPID, err := strconv.ParseUint(os.Getenv("ONETUNNEL_WATCHDOG_OWNER_PID"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	ownerCreated, err := strconv.ParseUint(os.Getenv("ONETUNNEL_WATCHDOG_OWNER_CREATED"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(ownerPID))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(owner)
	var created, exited, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(owner, &created, &exited, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	identity := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	if identity != ownerCreated {
		t.Fatalf("owner creation identity=%d, want %d", identity, ownerCreated)
	}
	if err = os.WriteFile(os.Getenv("ONETUNNEL_WATCHDOG_ACK"), []byte("validated"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = windows.WaitForSingleObject(owner, windows.INFINITE); err != nil {
		t.Fatal(err)
	}

	reg := &diskUserRegistry{path: os.Getenv("ONETUNNEL_WATCHDOG_REGISTRY")}
	proxy := &UserProxy{registry: reg, journalPath: os.Getenv("ONETUNNEL_WATCHDOG_JOURNAL")}
	lease := os.Getenv("ONETUNNEL_WATCHDOG_LEASE")
	gatePath := os.Getenv("ONETUNNEL_WATCHDOG_LOCK_GATE")
	lock := func() (func(), error) {
		if gatePath == "" {
			return func() {}, nil
		}
		if err := os.WriteFile(gatePath+".attempt", []byte("waiting"), 0600); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(gatePath); os.IsNotExist(err) {
				return func() {}, nil
			}
			time.Sleep(10 * time.Millisecond)
		}
		return nil, errors.New("test lock gate timed out")
	}
	readJournal := func() (proxyJournal, error) {
		var journal proxyJournal
		data, err := os.ReadFile(proxy.journalPath)
		if err != nil {
			return journal, err
		}
		err = json.Unmarshal(data, &journal)
		return journal, err
	}
	if err = restoreProxyLeaseAfterWatchEnd(proxy, lease, readJournal, lock, func(time.Duration) {}); err != nil {
		t.Fatal(err)
	}
}

func TestProxyWatchdogRestoresAfterOwnerProcessDies(t *testing.T) {
	runProxyWatchdogProcessTest(t, false)
}

func TestProxyWatchdogDoesNotRestoreSupersedingLease(t *testing.T) {
	runProxyWatchdogProcessTest(t, true)
}

func TestWatchdogRecoveryRetriesTransientRestoreAndNotifyFailures(t *testing.T) {
	proxy, reg, path, read := fakeWatchdogRecoveryState(t)
	reg.writeFailures = map[string]int{"ProxyEnable": 1}
	notifyCalls, pauseCalls := 0, 0
	proxy.notify = func() error {
		notifyCalls++
		if notifyCalls == 1 {
			return errors.New("transient notification failure")
		}
		return nil
	}
	err := restoreProxyLeaseAfterWatchEnd(proxy, "lease-retry", read, func() (func(), error) { return func() {}, nil }, func(delay time.Duration) {
		if delay != time.Second {
			t.Fatalf("retry delay=%s", delay)
		}
		pauseCalls++
	})
	if err != nil {
		t.Fatal(err)
	}
	if notifyCalls != 2 || pauseCalls != 2 {
		t.Fatalf("notify calls=%d pause calls=%d", notifyCalls, pauseCalls)
	}
	assertOriginalProxyState(t, reg)
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("successful retry left journal: %v", err)
	}
}

func TestWatchdogRecoveryExhaustionPreservesJournalAndForeignValues(t *testing.T) {
	proxy, reg, path, read := fakeWatchdogRecoveryState(t)
	reg.failWrite = "ProxyEnable"
	pauses := 0
	err := restoreProxyLeaseAfterWatchEnd(proxy, "lease-retry", read, func() (func(), error) { return func() {}, nil }, func(time.Duration) { pauses++ })
	if err == nil || pauses != 9 {
		t.Fatalf("exhaustion err=%v pauses=%d", err, pauses)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatalf("exhaustion removed recovery journal: %v", err)
	}
	if !sameRegistryValue(reg.values[fakeValueKey(userProxyRegistryKey, "ProxyEnable")], testAppliedProxyValues()["ProxyEnable"]) {
		t.Fatal("failed recovery changed the still-owned enable value")
	}
}

func TestWatchdogRecoveryReportsCompletedSelectiveRestore(t *testing.T) {
	for _, notifyFailures := range []int{0, 1} {
		t.Run(fmt.Sprintf("notify failures %d", notifyFailures), func(t *testing.T) {
			proxy, reg, path, read := fakeWatchdogRecoveryState(t)
			foreign := RawRegistryValue{Exists: true, Type: registry.SZ, Data: registryStringBytes("http=foreign.test:8080")}
			reg.values[fakeValueKey(userProxyRegistryKey, "ProxyServer")] = foreign
			notifications, pauses := 0, 0
			proxy.notify = func() error {
				notifications++
				if notifications <= notifyFailures {
					return errors.New("transient notification failure")
				}
				return nil
			}
			err := restoreProxyLeaseAfterWatchEnd(proxy, "lease-retry", read, func() (func(), error) { return func() {}, nil }, func(time.Duration) { pauses++ })
			if err == nil {
				t.Fatal("selective restoration conflict was reported as success")
			}
			if pauses != notifyFailures || notifications != notifyFailures+1 {
				t.Fatalf("completed restore retried: pauses=%d notifications=%d", pauses, notifications)
			}
			if !sameRegistryValue(reg.values[fakeValueKey(userProxyRegistryKey, "ProxyServer")], foreign) {
				t.Fatal("foreign edit was overwritten")
			}
			if reg.values[fakeValueKey(userProxyRegistryKey, "ProxyEnable")].Exists {
				t.Fatal("owned value was not restored")
			}
			if _, err = os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("completed restore retained journal: %v", err)
			}
		})
	}
}

func TestWatchdogRecoverySkipsMissingOrSupersededLease(t *testing.T) {
	proxy, reg, path, read := fakeWatchdogRecoveryState(t)
	writes, pauses := len(reg.events), 0
	if err := restoreProxyLeaseAfterWatchEnd(proxy, "another-lease", read, func() (func(), error) { return func() {}, nil }, func(time.Duration) { pauses++ }); err != nil {
		t.Fatal(err)
	}
	if len(reg.events) != writes || pauses != 0 {
		t.Fatalf("superseded lease caused effects: writes %d->%d pauses=%d", writes, len(reg.events), pauses)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := restoreProxyLeaseAfterWatchEnd(proxy, "lease-retry", read, func() (func(), error) { return func() {}, nil }, func(time.Duration) { pauses++ }); err != nil {
		t.Fatal(err)
	}
	if len(reg.events) != writes || pauses != 0 {
		t.Fatalf("missing journal caused effects: writes %d->%d pauses=%d", writes, len(reg.events), pauses)
	}
}

func fakeWatchdogRecoveryState(t *testing.T) (*UserProxy, *fakeUserRegistry, string, func() (proxyJournal, error)) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "journal.json")
	journal := proxyJournal{
		Schema: userProxyJournalSchema, LeaseID: "lease-retry", OwnerSID: "test", OwnerPID: 1, OwnerCreated: 1,
		Listener: "127.0.0.1:19091",
		Baseline: map[string]RawRegistryValue{"ProxyEnable": {}, "ProxyServer": {}},
		Applied:  testAppliedProxyValues(),
	}
	data, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{
		fakeValueKey(userProxyRegistryKey, "ProxyEnable"): cloneRaw(journal.Applied["ProxyEnable"]),
		fakeValueKey(userProxyRegistryKey, "ProxyServer"): cloneRaw(journal.Applied["ProxyServer"]),
	}}
	proxy := &UserProxy{registry: reg, journalPath: path}
	read := func() (proxyJournal, error) {
		var value proxyJournal
		b, err := os.ReadFile(path)
		if err != nil {
			return value, err
		}
		err = json.Unmarshal(b, &value)
		return value, err
	}
	return proxy, reg, path, read
}

func testAppliedProxyValues() map[string]RawRegistryValue {
	return map[string]RawRegistryValue{
		"ProxyEnable": {Exists: true, Type: registry.DWORD, Data: []byte{1, 0, 0, 0}},
		"ProxyServer": {Exists: true, Type: registry.SZ, Data: registryStringBytes("http=127.0.0.1:19091;https=127.0.0.1:19091")},
	}
}

func runProxyWatchdogProcessTest(t *testing.T, supersede bool) {
	t.Helper()
	dir := t.TempDir()
	registryPath := filepath.Join(dir, "registry.json")
	journalPath := filepath.Join(dir, "journal.json")
	ackPath := filepath.Join(dir, "ack")
	ownerStopPath := filepath.Join(dir, "owner-stop")
	gatePath := ""
	if supersede {
		gatePath = filepath.Join(dir, "lock-gate")
		if err := os.WriteFile(gatePath, []byte("held"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	lease := "lease-old"
	applied := map[string]RawRegistryValue{
		"ProxyEnable": {Exists: true, Type: registry.DWORD, Data: []byte{1, 0, 0, 0}},
		"ProxyServer": {Exists: true, Type: registry.SZ, Data: registryStringBytes("http=127.0.0.1:19080;https=127.0.0.1:19080")},
	}
	baseline := map[string]RawRegistryValue{"ProxyEnable": {}, "ProxyServer": {}}
	if err := writeDiskRegistry(registryPath, applied); err != nil {
		t.Fatal(err)
	}
	if err := writeJournalJSON(journalPath, proxyJournal{Schema: userProxyJournalSchema, LeaseID: lease, OwnerSID: "test", OwnerPID: 1, OwnerCreated: 1, Baseline: baseline, Applied: applied}); err != nil {
		t.Fatal(err)
	}

	ownerCmd := exec.Command(os.Args[0], "-test.run=^TestWatchdogOwnerHelper$")
	ownerCmd.Env = append(os.Environ(), "ONETUNNEL_WATCHDOG_HELPER=owner", "ONETUNNEL_WATCHDOG_OWNER_STOP="+ownerStopPath)
	if err := ownerCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.WriteFile(ownerStopPath, []byte("terminate"), 0600)
		_ = ownerCmd.Wait()
	}()
	ownerPID := uint32(ownerCmd.Process.Pid)
	ownerHandle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, ownerPID)
	if err != nil {
		_ = os.WriteFile(ownerStopPath, []byte("terminate"), 0600)
		t.Fatal(err)
	}
	var created, exited, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(ownerHandle, &created, &exited, &kernel, &user); err != nil {
		_ = os.WriteFile(ownerStopPath, []byte("terminate"), 0600)
		_ = windows.CloseHandle(ownerHandle)
		t.Fatal(err)
	}
	ownerCreated := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	if err = windows.CloseHandle(ownerHandle); err != nil {
		t.Fatal(err)
	}
	if err = writeJournalJSON(journalPath, proxyJournal{Schema: userProxyJournalSchema, LeaseID: lease, OwnerSID: "test", OwnerPID: ownerPID, OwnerCreated: ownerCreated, Baseline: baseline, Applied: applied}); err != nil {
		t.Fatal(err)
	}

	watcherCmd := exec.Command(os.Args[0], "-test.run=^TestWatchdogRecoveryHelper$")
	watcherCmd.Env = append(os.Environ(),
		"ONETUNNEL_WATCHDOG_HELPER=watcher",
		"ONETUNNEL_WATCHDOG_OWNER_PID="+strconv.FormatUint(uint64(ownerPID), 10),
		"ONETUNNEL_WATCHDOG_OWNER_CREATED="+strconv.FormatUint(ownerCreated, 10),
		"ONETUNNEL_WATCHDOG_ACK="+ackPath,
		"ONETUNNEL_WATCHDOG_REGISTRY="+registryPath,
		"ONETUNNEL_WATCHDOG_JOURNAL="+journalPath,
		"ONETUNNEL_WATCHDOG_LEASE="+lease,
		"ONETUNNEL_WATCHDOG_LOCK_GATE="+gatePath,
	)
	if err = watcherCmd.Start(); err != nil {
		_ = os.WriteFile(ownerStopPath, []byte("terminate"), 0600)
		t.Fatal(err)
	}
	defer func() {
		if gatePath != "" {
			_ = os.Remove(gatePath)
		}
		_ = watcherCmd.Wait()
	}()
	if err = waitForFile(ackPath, 5*time.Second); err != nil {
		_ = os.WriteFile(ownerStopPath, []byte("terminate"), 0600)
		t.Fatal(err)
	}
	if err = os.WriteFile(ownerStopPath, []byte("terminate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = ownerCmd.Wait(); err == nil {
		t.Fatal("owner process unexpectedly exited successfully after termination")
	}
	if supersede {
		if err = waitForFile(gatePath+".attempt", 5*time.Second); err != nil {
			_ = watcherCmd.Process.Kill()
			_ = watcherCmd.Wait()
			t.Fatal(err)
		}
		if err = writeJournalJSON(journalPath, proxyJournal{Schema: userProxyJournalSchema, LeaseID: "lease-new", OwnerSID: "test", OwnerPID: ownerPID, OwnerCreated: ownerCreated, Baseline: baseline, Applied: applied}); err != nil {
			t.Fatal(err)
		}
		if err = os.Remove(gatePath); err != nil {
			t.Fatal(err)
		}
	}
	if err = watcherCmd.Wait(); err != nil {
		t.Fatalf("watchdog helper failed after owner exit: %v", err)
	}
	reg := &diskUserRegistry{path: registryPath}
	values, err := reg.load()
	if err != nil {
		t.Fatal(err)
	}
	if supersede {
		if got := values["ProxyEnable"]; !sameRegistryValue(got, applied["ProxyEnable"]) {
			t.Fatalf("superseding lease was restored: %#v", got)
		}
		journal, e := readJournalJSON(journalPath)
		if e != nil || journal.LeaseID != "lease-new" {
			t.Fatalf("new lease journal changed: %#v, err=%v", journal, e)
		}
	} else {
		for _, name := range []string{"ProxyEnable", "ProxyServer"} {
			if values[name].Exists {
				t.Fatalf("owner death did not restore baseline %s: %#v", name, values[name])
			}
		}
		if _, err = os.Stat(journalPath); !os.IsNotExist(err) {
			t.Fatalf("watchdog did not remove restored journal: %v", err)
		}
	}
}

func waitForFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}

func writeJournalJSON(path string, journal proxyJournal) error {
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func writeDiskRegistry(path string, values map[string]RawRegistryValue) error {
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func readJournalJSON(path string) (proxyJournal, error) {
	var journal proxyJournal
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &journal)
	}
	return journal, err
}

type diskUserRegistry struct{ path string }

func (r *diskUserRegistry) load() (map[string]RawRegistryValue, error) {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return nil, err
	}
	values := map[string]RawRegistryValue{}
	err = json.Unmarshal(data, &values)
	return values, err
}

func (r *diskUserRegistry) save(values map[string]RawRegistryValue) error {
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}
	return os.WriteFile(r.path, data, 0600)
}

func (r *diskUserRegistry) Read(key, name string) (RawRegistryValue, error) {
	values, err := r.load()
	if err != nil {
		return RawRegistryValue{}, err
	}
	return cloneRaw(values[name]), nil
}

func (r *diskUserRegistry) Write(key, name string, value RawRegistryValue) error {
	values, err := r.load()
	if err != nil {
		return err
	}
	if value.Exists {
		values[name] = cloneRaw(value)
	} else {
		delete(values, name)
	}
	return r.save(values)
}

func (r *diskUserRegistry) Delete(key, name string) error {
	return r.Write(key, name, RawRegistryValue{})
}
