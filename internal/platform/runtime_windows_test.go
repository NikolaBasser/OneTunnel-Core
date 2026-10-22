package platform

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"onetunnel/core/internal/control"
)

func TestWFPLayoutsAndLegacyOwnership(t *testing.T) {
	var f wFilter
	var p wProvider
	var s wSublayer
	var c wCondition
	if unsafe.Sizeof(f) != 200 || unsafe.Offsetof(f.Provider) != 40 || unsafe.Offsetof(f.Weight) != 96 || unsafe.Offsetof(f.Conditions) != 120 || unsafe.Offsetof(f.Action) != 128 || unsafe.Offsetof(f.Context) != 152 || unsafe.Offsetof(f.EffectiveWeight) != 184 || unsafe.Sizeof(p) != 64 || unsafe.Sizeof(s) != 72 || unsafe.Sizeof(c) != 40 {
		t.Fatal("WFP layout differs from native/C# ABI")
	}
	lock := trafficLock{owner: "S-1-5-21-111-222-333-1001", root: `C:\ProgramData\OneTunnel\Service\S-1-5-21-111-222-333-1001`}
	if !strings.EqualFold(lock.key("provider").String(), "{8e7a1990-8f66-dbf3-f148-c16c878e10d7}") {
		t.Fatal("legacy GUID byte order changed")
	}
	hash := lock.ownerHash()
	if strings.ToUpper(hex.EncodeToString(hash[:])) != "4C20404B20199693B107D983186E4D87541912F64026A3ACD783A263E88669F6" {
		t.Fatal("legacy runtime owner hash changed")
	}
}
func TestUnifiedWireGuardEngineAndLegacyNamespace(t *testing.T) {
	r := &Runtime{directory: t.TempDir()}
	if r.enginePath(0) != r.enginePath(1) || filepath.Base(r.enginePath(1)) != "amneziawg.exe" {
		t.Fatal("WireGuard still needs separate engine")
	}
	if nativeServiceName(&Session{Kind: "AmneziaWG", TunnelName: "OneTunnel123456789abc"}) != "AmneziaWGTunnel$OneTunnel123456789abc" || nativeServiceName(&Session{Kind: "WireGuard", TunnelName: "OneTunnel123456789abc"}) != "WireGuardTunnel$OneTunnel123456789abc" {
		t.Fatal("legacy recovery service namespace changed")
	}
	if removeLegacyWireGuardService(context.Background(), "../unowned") == nil {
		t.Fatal("unowned service cleanup accepted")
	}
}
func TestLegacyWGServiceRemovalWithoutEngine(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires elevated synthetic SCM fixture")
	}
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	name := "OneTunnel" + strings.ToLower(strings.ReplaceAll(strings.Trim(guid.String(), "{}"), "-", "")[:12])
	service, err := manager.CreateService("WireGuardTunnel$"+name, filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), mgr.Config{DisplayName: "OneTunnel legacy recovery fixture"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		s, e := manager.OpenService("WireGuardTunnel$" + name)
		if e == nil {
			s.Delete()
			s.Close()
		}
	}()
	service.Close()
	if err = removeLegacyWireGuardService(context.Background(), name); err != nil {
		t.Fatal(err)
	}
	if _, exists := nativeServiceState("WireGuardTunnel$" + name); exists {
		t.Fatal("legacy service survived deletion")
	}
	if err = removeLegacyWireGuardService(context.Background(), name); err != nil {
		t.Fatal("recovery not idempotent", err)
	}
}
func TestAtomicJournalAndUnsafeRecovery(t *testing.T) {
	root := t.TempDir()
	if e := os.Mkdir(filepath.Join(root, "runtime"), 0700); e != nil {
		t.Fatal(e)
	}
	lock := trafficLock{root: root}
	r := &Runtime{root: root, directory: root, lock: lock, update: func(control.State) {}}
	for _, session := range []Session{{Kind: "WireGuard", TunnelName: "../bad", Engine: "untrusted.exe"}, {Kind: "arbitrary", TunnelName: "OneTunnel123456789abc"}} {
		if e := atomicJSON(r.journal(), session); e != nil {
			t.Fatal(e)
		}
		if e := r.recover(context.Background()); e == nil {
			t.Fatal("unsafe recovery journal accepted")
		}
		if r.session != nil || !r.recovery() {
			t.Fatal("rejected journal altered active state")
		}
	}
	data, e := os.ReadFile(r.journal())
	if e != nil || !json.Valid(data) {
		t.Fatal("journal incomplete")
	}
	if exists(r.journal() + ".new") {
		t.Fatal("journal temporary file left behind")
	}
}
func TestProcessTicksMatchDotNetEpoch(t *testing.T) {
	ticks, e := processTicks(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getpid()))
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	var creation, exit, kernel, user windows.Filetime
	if e = windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); e != nil {
		t.Fatal(e)
	}
	if ticks != creation.Nanoseconds()/100+621355968000000000 {
		t.Fatal("recovery PID birth time incompatible with .NET UTC ticks")
	}
}

func TestExitedTransportRequiresRecovery(t *testing.T) {
	for _, locked := range []bool{false, true} {
		root := t.TempDir()
		r := &Runtime{root: root, lock: trafficLock{root: root}, session: &Session{Kind: "proxy"}, update: func(control.State) {}}
		if locked {
			if e := os.WriteFile(filepath.Join(root, "kill-switch.json"), []byte("{}"), 0600); e != nil {
				t.Fatal(e)
			}
		}
		done := make(chan struct{})
		r.engine = &child{done: done}
		r.publish("")
		if !r.snapshot().Active {
			t.Fatal("live transport reported inactive")
		}
		close(done)
		r.poll()
		r.publish("")
		s := r.snapshot()
		if s.Active || !s.NeedsRecovery || s.TrafficLocked != locked || r.session == nil {
			t.Fatal("exited transport must retain cleanup session and protection, but report inactive")
		}
	}
}

func TestRecoveryWithRetainedExitedProcessHandle(t *testing.T) {
	c := exec.Command("cmd.exe", "/c", "exit", "0")
	if e := c.Start(); e != nil {
		t.Fatal(e)
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(c.Process.Pid))
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	pid := c.Process.Pid
	if e := c.Wait(); e != nil {
		t.Fatal(e)
	}
	if e := stopChild(context.Background(), nil, pid, 0, "unused.exe"); e != nil {
		t.Fatalf("an exited engine must not prevent traffic-lock cleanup: %v", e)
	}
}
