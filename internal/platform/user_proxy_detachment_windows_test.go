//go:build windows && onetunnel_detachment_acceptance

package platform

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This exercises only process containment. It never opens a proxy journal,
// registry key, listener or production watchdog entry point.
func TestUserProxyDetachedProcessSurvivesOwnerJob(t *testing.T) {
	inJob, jobErr := currentProcessInJob()
	if jobErr != nil {
		t.Fatal(jobErr)
	}
	t.Logf("acceptance runner already in a Windows job: %v", inJob)
	dir := t.TempDir()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		t.Fatal(err)
	}
	owner := exec.Command(os.Args[0], "-test.run=^TestUserProxyDetachmentHelper$")
	logPath := filepath.Join(dir, "owner.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	owner.Stdout, owner.Stderr = log, log
	owner.Env = append(os.Environ(), "ONETUNNEL_DETACHMENT_ROLE=owner", "ONETUNNEL_DETACHMENT_DIR="+dir)
	if err = owner.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Process.Kill(); _ = owner.Wait() }()
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(owner.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err = windows.AssignProcessToJobObject(job, h); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "start"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = waitForDetachmentReady(dir); err != nil {
		output, _ := os.ReadFile(logPath)
		t.Fatalf("%v; owner: %s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(dir, "ready"))
	if err != nil {
		t.Fatal(err)
	}
	var pid uint32
	var created uint64
	if _, err = fmt.Sscanf(string(data), "%d %d", &pid, &created); err != nil {
		t.Fatal(err)
	}
	child, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(child)
	var born, exited, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(child, &born, &exited, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	if uint64(born.HighDateTime)<<32|uint64(born.LowDateTime) != created {
		t.Fatal("child identity changed")
	}
	defer func() { _ = windows.TerminateProcess(child, 1); _, _ = windows.WaitForSingleObject(child, 5000) }()
	if err = windows.TerminateJobObject(job, 42); err != nil {
		t.Fatal(err)
	}
	if state, e := windows.WaitForSingleObject(h, 5000); e != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatalf("owner termination state=%d err=%v", state, e)
	}
	if state, e := windows.WaitForSingleObject(child, 0); e != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("detached child did not survive: state=%d err=%v", state, e)
	}
	if err = os.WriteFile(filepath.Join(dir, "continue"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if state, e := windows.WaitForSingleObject(child, 5000); e != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatalf("child exit state=%d err=%v", state, e)
	}
	var code uint32
	if err = windows.GetExitCodeProcess(child, &code); err != nil || code != 0 {
		t.Fatalf("child exit=%d err=%v", code, err)
	}
	if _, err = os.Stat(filepath.Join(dir, "survived")); err != nil {
		t.Fatal(err)
	}
}

func TestUserProxyDetachmentHelper(t *testing.T) {
	role := os.Getenv("ONETUNNEL_DETACHMENT_ROLE")
	if role == "" {
		return
	}
	dir := os.Getenv("ONETUNNEL_DETACHMENT_DIR")
	if dir == "" {
		t.Fatal("missing isolated directory")
	}
	// Bounds orphan lifetime even if the parent test unexpectedly terminates.
	timer := time.AfterFunc(20*time.Second, func() { os.Exit(90) })
	defer timer.Stop()
	switch role {
	case "owner":
		if err := waitForFile(filepath.Join(dir, "start"), 10*time.Second); err != nil {
			t.Fatal(err)
		}
		inJob, err := currentProcessInJob()
		if err != nil || !inJob {
			t.Fatalf("owner job=%v err=%v", inJob, err)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestUserProxyDetachmentHelper$")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		child.Env = append(os.Environ(), "ONETUNNEL_DETACHMENT_ROLE=child")
		child.SysProcAttr = &syscall.SysProcAttr{CreationFlags: userProxyWatchdogCreationFlags()}
		if err = child.Start(); err != nil {
			t.Fatal(err)
		}
		defer child.Process.Release()
		select {}
	case "child":
		inJob, err := currentProcessInJob()
		if err = ensureWatchdogOutsideJob(inJob, err); err != nil {
			_ = os.WriteFile(filepath.Join(dir, "rejected"), []byte(err.Error()), 0600)
			t.Fatal(err)
		}
		process, err := windows.GetCurrentProcess()
		if err != nil {
			t.Fatal(err)
		}
		var born, exited, kernel, user windows.Filetime
		if err = windows.GetProcessTimes(process, &born, &exited, &kernel, &user); err != nil {
			t.Fatal(err)
		}
		identity := strconv.Itoa(os.Getpid()) + " " + strconv.FormatUint(uint64(born.HighDateTime)<<32|uint64(born.LowDateTime), 10)
		if err = os.WriteFile(filepath.Join(dir, "ready.tmp"), []byte(identity), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(filepath.Join(dir, "ready.tmp"), filepath.Join(dir, "ready")); err != nil {
			t.Fatal(err)
		}
		if err = waitForFile(filepath.Join(dir, "continue"), 15*time.Second); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "survived"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown helper role")
	}
}

func waitForDetachmentReady(dir string) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if rejected, err := os.ReadFile(filepath.Join(dir, "rejected")); err == nil {
			return fmt.Errorf("detachment rejected: %s", rejected)
		}
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("detachment readiness timed out")
}
