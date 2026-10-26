//go:build windows && onetunnel_user_proxy_live_acceptance

package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

type liveStartupRecovery struct {
	Baseline RawRegistryValue
	Owned    []RawRegistryValue
	Deadline time.Time
}

func liveStartupRestore(snapshot liveStartupRecovery) error {
	unlock, err := lockUserAutomationTimeout(5000)
	if err != nil {
		return err
	}
	defer unlock()
	reg := windowsUserRegistry{}
	current, err := reg.Read(userProxyRunKey, userProxyRunValue)
	if err != nil || sameRegistryValue(current, snapshot.Baseline) {
		return err
	}
	for _, owned := range snapshot.Owned {
		if sameRegistryValue(current, owned) {
			return reg.Write(userProxyRunKey, userProxyRunValue, snapshot.Baseline)
		}
	}
	return errors.New("unrecognized startup edit preserved during recovery")
}

func TestUserStartupLiveRecoveryHelper(t *testing.T) {
	if os.Getenv("ONETUNNEL_LIVE_STARTUP_HELPER") != "rollback" {
		t.Skip("independent startup recovery helper")
	}
	liveProxyGuard(t)
	inJob, err := currentProcessInJob()
	if err = ensureWatchdogOutsideJob(inJob, err); err != nil {
		t.Fatal(err)
	}
	dir := os.Getenv("ONETUNNEL_LIVE_STARTUP_DIR")
	data, err := os.ReadFile(filepath.Join(dir, "startup-recovery.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot liveStartupRecovery
	if err = json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if remaining := time.Until(snapshot.Deadline); remaining < 5*time.Second || remaining > 25*time.Second {
		t.Fatal("invalid bounded startup recovery deadline")
	}
	if err = os.WriteFile(filepath.Join(dir, "startup-ready"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for time.Now().Before(snapshot.Deadline) {
		if _, err = os.Stat(filepath.Join(dir, "startup-done")); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err = liveStartupRestore(snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestUserStartupLiveAcceptance(t *testing.T) {
	liveProxyGuard(t)
	const executable = `C:\OneTunnel-Test\roadmap-20261026\app\OneTunnel.exe`
	startup := UserStartup{}
	command, err := startup.ProposedCommand(executable)
	if err != nil {
		t.Fatal("stable real application required:", err)
	}
	reg := windowsUserRegistry{}
	baseline, err := reg.Read(userProxyRunKey, userProxyRunValue)
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Exists {
		if _, err = startup.Enable(executable, ""); err == nil {
			t.Fatal("existing startup entry was adopted")
		}
		after, readErr := reg.Read(userProxyRunKey, userProxyRunValue)
		if readErr != nil || !sameRegistryValue(after, baseline) {
			t.Fatal("existing startup entry changed", readErr)
		}
		t.Fatal("dedicated-server startup baseline is occupied; refusal verified, acceptance requires an absent value")
	}
	owned := RawRegistryValue{Exists: true, Type: registry.SZ, Data: registryStringBytes(command)}
	foreign := RawRegistryValue{Exists: true, Type: registry.SZ, Data: registryStringBytes(`C:\OneTunnel-Test\foreign-startup-test-do-not-run.exe`)}
	snapshot := liveStartupRecovery{Baseline: baseline, Owned: []RawRegistryValue{owned, foreign}, Deadline: time.Now().Add(25 * time.Second)}
	dir := t.TempDir()
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "startup-recovery.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "startup-rollback.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	helper := exec.Command(os.Args[0], "-test.run=^TestUserStartupLiveRecoveryHelper$", "-test.timeout=35s")
	helper.Env = append(os.Environ(), "ONETUNNEL_LIVE_STARTUP_HELPER=rollback", "ONETUNNEL_LIVE_STARTUP_DIR="+dir)
	helper.SysProcAttr = &syscall.SysProcAttr{CreationFlags: userProxyWatchdogCreationFlags()}
	helper.Stdout, helper.Stderr = log, log
	if err = helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := liveStartupRestore(snapshot); err != nil {
			t.Error("owned startup restoration:", err)
		} else {
			after, readErr := reg.Read(userProxyRunKey, userProxyRunValue)
			if readErr != nil || !sameRegistryValue(after, baseline) {
				t.Error("exact startup baseline not restored", readErr)
			} else if err := os.WriteFile(filepath.Join(dir, "startup-done"), nil, 0600); err != nil {
				t.Error(err)
			}
		}
		// Retain recovery inputs until the independent helper exits, even on failure.
		if err := helper.Wait(); err != nil {
			t.Error("independent startup recovery:", err)
		}
	})
	if err = liveProxyWait(filepath.Join(dir, "startup-ready"), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	mutate := func(change func() error) {
		t.Helper()
		if time.Until(snapshot.Deadline) < 5*time.Second {
			t.Fatal("insufficient startup recovery window")
		}
		if err := change(); err != nil {
			t.Fatal(err)
		}
	}
	mutate(func() error {
		got, err := startup.Enable(executable, "")
		if err == nil && got != command {
			return fmt.Errorf("startup command differs: %q", got)
		}
		return err
	})
	current, err := reg.Read(userProxyRunKey, userProxyRunValue)
	if err != nil || !sameRegistryValue(current, owned) {
		t.Fatal("actual typed Run value differs", err)
	}
	if enabled, err := startup.Status(command); err != nil || !enabled {
		t.Fatal("actual startup status absent", err)
	}
	mutate(func() error { _, err := startup.Enable(executable, command); return err })
	mutate(func() error {
		conflict, err := startup.Disable(command)
		if err == nil && conflict {
			return errors.New("owned startup disable reported conflict")
		}
		return err
	})
	if enabled, err := startup.Status(command); err != nil || enabled {
		t.Fatal("startup status remains enabled after disable", err)
	}
	mutate(func() error { return reg.Write(userProxyRunKey, userProxyRunValue, foreign) })
	conflict, err := startup.Disable(command)
	if err != nil || !conflict {
		t.Fatal("foreign startup edit conflict missing", err)
	}
	current, err = reg.Read(userProxyRunKey, userProxyRunValue)
	if err != nil || !sameRegistryValue(current, foreign) {
		t.Fatal("foreign startup edit was overwritten", err)
	}
	if _, err := startup.Enable(executable, command); err == nil {
		t.Fatal("foreign startup entry replaced during enable")
	}
	current, err = reg.Read(userProxyRunKey, userProxyRunValue)
	if err != nil || !sameRegistryValue(current, foreign) {
		t.Fatal("rejected enable changed foreign startup edit", err)
	}
	t.Log("actual HKCU Run enable/status/idempotence/disable and foreign preservation verified; Windows logon launch is not tested")
}
