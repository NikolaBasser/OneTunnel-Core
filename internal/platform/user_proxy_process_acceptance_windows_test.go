//go:build windows && onetunnel_registry_process_acceptance

package platform

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type processRecoveryFixture struct {
	Leaf     string
	Deadline time.Time
}

func TestUserProxyIsolatedProcessRecovery(t *testing.T) {
	before := actualProxyRawSnapshot(t)
	t.Cleanup(func() {
		after := actualProxyRawSnapshot(t)
		for name, value := range before {
			if !sameRegistryValue(value, after[name]) {
				t.Error("actual proxy settings changed")
			}
		}
	})
	for _, mode := range []string{"owner death", "owner and watcher death", "foreign edit"} {
		t.Run(mode, func(t *testing.T) {
			r := newIsolatedProxyRegistry(t)
			dir := t.TempDir()
			baseline := map[string]RawRegistryValue{
				"ProxyEnable": {Exists: true, Type: registry.DWORD, Data: []byte{0, 0, 0, 0}},
				"ProxyServer": {Exists: true, Type: registry.EXPAND_SZ, Data: registryStringBytes("http=baseline.test:8080")},
			}
			for name, value := range baseline {
				if err := (windowsUserRegistry{}).Write(r.leaf, name, value); err != nil {
					t.Fatal(err)
				}
			}
			cfg := processRecoveryFixture{Leaf: r.leaf, Deadline: time.Now().Add(5 * time.Second)}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, "fixture.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			owner := startRegistryRecoveryHelper(t, dir, "owner")
			if err = waitForFile(filepath.Join(dir, "journal-ready"), 2*time.Second); err != nil {
				t.Fatal(err)
			}
			watcher := startRegistryRecoveryHelper(t, dir, "watcher")
			deadline := startRegistryRecoveryHelper(t, dir, "deadline")
			for _, role := range []string{"watcher", "deadline"} {
				if err = waitForFile(filepath.Join(dir, role+"-ready"), 2*time.Second); err != nil {
					t.Fatal(err)
				}
			}
			assertIsolatedBaseline(t, r, baseline)
			if time.Until(cfg.Deadline) < 2*time.Second {
				t.Fatal("insufficient immutable recovery window")
			}
			if err = os.WriteFile(filepath.Join(dir, "armed"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err = waitForFile(filepath.Join(dir, "applied"), time.Second); err != nil {
				t.Fatal(err)
			}
			p := &UserProxy{registry: r, journalPath: filepath.Join(dir, "user-proxy.dpapi")}
			j, err := p.readJournal()
			if err != nil {
				t.Fatal(err)
			}
			if j.OwnerPID != uint32(owner.Process.Pid) {
				t.Fatal("unexpected journal owner")
			}
			assertIsolatedBaseline(t, r, j.Applied)
			if mode != "owner death" {
				killRegistryRecoveryHelper(t, watcher)
			}
			if mode == "foreign edit" {
				foreign := RawRegistryValue{Exists: true, Type: registry.SZ, Data: registryStringBytes("http=foreign.test:8080")}
				if err = r.Write(userProxyRegistryKey, "ProxyServer", foreign); err != nil {
					t.Fatal(err)
				}
				baseline["ProxyServer"] = foreign
			}
			killRegistryRecoveryHelper(t, owner)
			if mode == "owner death" {
				if err = watcher.Wait(); err != nil {
					t.Fatal(err)
				}
				if _, err = os.Stat(filepath.Join(dir, "watcher-restored")); err != nil {
					t.Fatal(err)
				}
				if time.Until(cfg.Deadline) < time.Second {
					t.Fatal("watcher recovery was not proven before independent deadline")
				}
				assertIsolatedBaseline(t, r, baseline)
				if _, err = os.Stat(p.journalPath); !os.IsNotExist(err) {
					t.Fatal("watcher did not remove the recovered journal")
				}
			} else {
				if _, err = os.Stat(p.journalPath); err != nil {
					t.Fatal("journal vanished before deadline recovery")
				}
				if time.Until(cfg.Deadline) < time.Second {
					t.Fatal("deadline elapsed before process-death proof")
				}
				value, readErr := r.Read(userProxyRegistryKey, "ProxyEnable")
				if readErr != nil || !sameRegistryValue(value, j.Applied["ProxyEnable"]) {
					t.Fatal("owned value restored before independent deadline")
				}
			}
			if err = deadline.Wait(); err != nil {
				t.Fatal(err)
			}
			result, err := os.ReadFile(filepath.Join(dir, "deadline-restored"))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "foreign edit" && string(result) != "conflict" {
				t.Fatalf("foreign edit outcome=%q", result)
			}
			if mode != "foreign edit" && string(result) != "ok" {
				t.Fatalf("recovery outcome=%q", result)
			}
			assertIsolatedBaseline(t, r, baseline)
			if _, err = os.Stat(p.journalPath); !os.IsNotExist(err) {
				t.Fatal("recovered journal remains")
			}
		})
	}
}

func startRegistryRecoveryHelper(t *testing.T, dir, role string) *exec.Cmd {
	t.Helper()
	logPath := filepath.Join(dir, role+".log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	cmd := exec.Command(os.Args[0], "-test.run=^TestUserProxyRegistryProcessHelper$")
	cmd.Env = append(os.Environ(), "ONETUNNEL_REGISTRY_PROCESS_ROLE="+role, "ONETUNNEL_REGISTRY_PROCESS_DIR="+dir)
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		if t.Failed() {
			if data, err := os.ReadFile(logPath); err == nil {
				t.Logf("%s: %s", role, data)
			}
		}
	})
	return cmd
}

func killRegistryRecoveryHelper(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("terminated helper unexpectedly succeeded")
	}
}

func TestUserProxyRegistryProcessHelper(t *testing.T) {
	role := os.Getenv("ONETUNNEL_REGISTRY_PROCESS_ROLE")
	if role == "" {
		return
	}
	if role != "owner" && role != "watcher" && role != "deadline" {
		t.Fatal("invalid helper role")
	}
	timer := time.AfterFunc(20*time.Second, func() { os.Exit(91) })
	defer timer.Stop()
	dir := os.Getenv("ONETUNNEL_REGISTRY_PROCESS_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("fixture directory must be absolute")
	}
	data, err := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg processRecoveryFixture
	if err = json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	prefix := userProxyTestRegistryRoot + `\UserProxy-`
	nonce, err := hex.DecodeString(strings.TrimPrefix(cfg.Leaf, prefix))
	if err != nil || len(nonce) != 16 || !strings.HasPrefix(cfg.Leaf, prefix) {
		t.Fatal("refusing non-isolated registry leaf")
	}
	remaining := time.Until(cfg.Deadline)
	if remaining <= 0 || remaining > 6*time.Second {
		t.Fatal("invalid fixed recovery deadline")
	}
	r := &isolatedProxyRegistry{leaf: cfg.Leaf}
	p := &UserProxy{registry: r, journalPath: filepath.Join(dir, "user-proxy.dpapi"), notify: func() error { return nil }, queryProxyFlags: func() (uint32, error) { return 0, nil }}
	writeMarker := func(name, value string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if role == "owner" {
		p.armWatchdog = func(string, uint32, uint64, string) error {
			writeMarker("journal-ready", "")
			return waitForFile(filepath.Join(dir, "armed"), 3*time.Second)
		}
		if _, err = p.Enable(startAcceptanceListener(t)); err != nil {
			t.Fatal(err)
		}
		writeMarker("applied", "")
		select {}
	}
	j, err := p.readJournal()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, j.OwnerPID)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(owner)
	var born, exited, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(owner, &born, &exited, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	if uint64(born.HighDateTime)<<32|uint64(born.LowDateTime) != j.OwnerCreated {
		t.Fatal("owner identity mismatch")
	}
	writeMarker(role+"-ready", "")
	if role == "deadline" {
		for time.Now().Before(cfg.Deadline) {
			time.Sleep(time.Until(cfg.Deadline))
		}
	} else {
		_, err = monitorProxyLeaseOwnerAndListener(func(interval time.Duration) (bool, error) {
			state, err := windows.WaitForSingleObject(owner, uint32(interval/time.Millisecond))
			if err != nil {
				return false, err
			}
			if state == windows.WAIT_OBJECT_0 {
				return true, nil
			}
			if state != uint32(windows.WAIT_TIMEOUT) {
				return false, fmt.Errorf("unexpected process wait %d", state)
			}
			return false, nil
		}, func() (bool, error) { return p.Owns(j.LeaseID) }, probeLoopbackListener, j.Listener, 50*time.Millisecond, 3)
		if err != nil {
			t.Fatal(err)
		}
	}
	err = restoreProxyLeaseAfterWatchEnd(p, j.LeaseID, p.readJournal, p.userAutomationLock, nil)
	outcome := "ok"
	if err != nil {
		if err.Error() != "proxy settings were changed externally; owned values restored selectively" {
			t.Fatal(err)
		}
		outcome = "conflict"
	}
	if role == "deadline" && time.Now().Before(cfg.Deadline) {
		t.Fatal(errors.New("recovery preceded fixed deadline"))
	}
	writeMarker(role+"-restored", outcome)
}
