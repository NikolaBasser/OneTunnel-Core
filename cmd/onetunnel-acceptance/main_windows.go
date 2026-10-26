//go:build windows && onetunnel_safety_test

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
	"golang.org/x/sys/windows"
)

func main() {
	mode := flag.String("mode", "", "init, guard, guard-inspection-fault, fallback, worker, inspect, or recover")
	path := flag.String("plan", "", "exact protected plan.json path")
	duration := flag.Int("duration", 60, "immutable deadline in seconds (init only)")
	workerMode := flag.String("worker-mode", "marker", "marker or permit (init only; neither blocks traffic)")
	flag.Parse()
	if flag.NArg() != 0 || *path == "" {
		fatal(errors.New("explicit mode and protected plan required"))
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		fatal(errors.New("elevated administrator/SYSTEM required"))
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		fatal(err)
	}
	if *mode == "init" {
		if err = initialize(*path, programData, *duration, *workerMode); err != nil {
			fatal(err)
		}
		return
	}
	p, err := loadPlan(*path, programData)
	if err != nil {
		fatal(err)
	}
	switch *mode {
	case "worker":
		err = worker(p)
	case "fallback":
		err = fallback(p)
	case "recover":
		err = recoverRun(p)
	case "inspect":
		err = inspect(p)
	case "guard", "guard-inspection-fault":
		err = guard(p, *mode == "guard-inspection-fault")
	default:
		err = errors.New("unsupported mode; no traffic-blocking action is implemented")
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

func tickCount() uint64 {
	value, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64").Call()
	return uint64(value)
}

func bootID() (string, error) {
	var data [64]byte
	var length uint32
	if err := windows.NtQuerySystemInformation(windows.SystemBootEnvironmentInformation, unsafe.Pointer(&data[0]), uint32(len(data)), &length); err != nil {
		return "", err
	}
	if length < 16 {
		return "", errors.New("boot identity unavailable")
	}
	return (*windows.GUID)(unsafe.Pointer(&data[0])).String(), nil
}

func binaryHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func initialize(path, programData string, seconds int, workerMode string) error {
	id := filepath.Base(filepath.Dir(path))
	root, network, owner, provider, fingerprint := scope(programData, id)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	if err = verifyFile(exe); err != nil {
		return err
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	hash, err := binaryHash(exe)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	p := plan{Version: 1, RunID: id, GuardRoot: root, NetworkRoot: network, Owner: owner, Provider: provider, Fingerprint: fingerprint, Executable: exe, SHA256: hash, BootID: boot, WorkerMode: workerMode, Created: now, Deadline: now.Add(time.Duration(seconds) * time.Second), DurationSeconds: seconds, StartTick: tickCount()}
	if err = p.validate(programData, path); err != nil {
		return err
	}
	if err = verifyTrust(root, programData); err != nil {
		return err
	}
	if _, err = os.Lstat(network); !os.IsNotExist(err) {
		return errors.New("synthetic network root already exists or is inaccessible")
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	f, err := createPrivateFile(path)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func loadPlan(path, programData string) (plan, error) {
	var p plan
	if err := verifyTrust(filepath.Dir(path), programData); err != nil {
		return p, err
	}
	if err := verifyFile(path); err != nil {
		return p, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if len(data) > 16384 {
		return p, errors.New("oversized plan")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&p); err != nil {
		return p, err
	}
	if d.Decode(new(any)) != io.EOF {
		return p, errors.New("invalid plan tail")
	}
	if err = p.validate(programData, path); err != nil {
		return p, err
	}
	if err = verifyFile(p.Executable); err != nil {
		return p, err
	}
	exe, err := os.Executable()
	if err != nil {
		return p, err
	}
	if !strings.EqualFold(filepath.Clean(exe), p.Executable) {
		return p, errors.New("guardian executable path mismatch")
	}
	hash, err := binaryHash(exe)
	if err != nil || hash != p.SHA256 {
		return p, errors.New("guardian executable hash mismatch")
	}
	return p, nil
}

func verifyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("required file unavailable")
	}
	a, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("reparse acceptance file refused")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544" {
		return errors.New("acceptance file owner is not SYSTEM/Administrators")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		return errors.New("acceptance file ACL mismatch")
	}
	seen := map[string]bool{}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != 0x001f01ff { // FILE_ALL_ACCESS
			return errors.New("unexpected acceptance file rights")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if sid != "S-1-5-18" && sid != "S-1-5-32-544" {
			return errors.New("unexpected acceptance file trustee")
		}
		seen[sid] = true
	}
	if len(seen) != 2 {
		return errors.New("missing acceptance file trustee")
	}
	return nil
}

func createPrivateFile(path string) (*os.File, error) {
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func verifyTrust(root, programData string) error {
	base := filepath.Join(programData, "OneTunnelAcceptance")
	if filepath.Dir(root) != base || !runIDPattern.MatchString(filepath.Base(root)) {
		return errors.New("untrusted acceptance root")
	}
	for _, path := range []string{base, root} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			return errors.New("acceptance root unavailable")
		}
		a, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
		if err != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("acceptance root reparse refused")
		}
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		if owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544" {
			return errors.New("acceptance root owner is not SYSTEM/Administrators")
		}
		sddl := sd.String()
		start := strings.Index(sddl, "D:")
		if start < 0 {
			return errors.New("missing private DACL")
		}
		dacl := strings.TrimPrefix(sddl[start+2:], "P")
		if dacl == sddl[start+2:] {
			return errors.New("DACL inheritance must be protected")
		}
		dacl = strings.TrimPrefix(dacl, "AI")
		if dacl != "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" && dacl != "(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)" {
			return errors.New("acceptance DACL must grant SYSTEM/Administrators only")
		}
	}
	return nil
}

func writeJSON(p plan, name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	target := filepath.Join(p.GuardRoot, name)
	f, err := createPrivateFile(filepath.Join(p.GuardRoot, "atomic-"+rand.Text()))
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return windows.MoveFileEx(windows.StringToUTF16Ptr(temp), windows.StringToUTF16Ptr(target), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func event(p plan, kind string, err error) {
	message := ""
	if err != nil {
		message = err.Error()
	}
	data, _ := json.Marshal(struct {
		UTC         time.Time
		Kind, Error string
	}{time.Now().UTC(), kind, message})
	f, openErr := os.OpenFile(filepath.Join(p.GuardRoot, "events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if openErr == nil {
		_, _ = f.Write(append(data, '\n'))
		_ = f.Sync()
		_ = f.Close()
	}
}

func terminal(p plan) bool {
	_, err := os.Stat(filepath.Join(p.GuardRoot, "terminal.json"))
	return err == nil || !os.IsNotExist(err)
}

func fallback(p plan) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if user.User.Sid.String() != "S-1-5-18" {
		return errors.New("fallback requires SYSTEM scheduled-task principal")
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	awaitDeadline(p, boot, time.Now, func() time.Duration { return tickElapsed(p, tickCount()) }, func() bool { return terminal(p) }, func() {
		_ = writeJSON(p, "fallback-ready.json", struct {
			RunID, SHA256, BootID, Principal string
			UTC                              time.Time
		}{p.RunID, p.SHA256, boot, user.User.Sid.String(), time.Now().UTC()})
		time.Sleep(200 * time.Millisecond)
	})
	for {
		if err = recoverRun(p); err == nil {
			return nil
		}
		event(p, "recovery-retry", err)
		time.Sleep(time.Second)
	}
}

func guard(p plan, inspectionFault bool) (result error) {
	boot, err := bootID()
	if err != nil {
		return err
	}
	if terminal(p) || due(p, boot, time.Now().UTC(), tickElapsed(p, tickCount())) {
		return recoverRun(p)
	}
	var proof struct {
		RunID, SHA256, BootID, Principal string
		UTC                              time.Time
	}
	data, err := os.ReadFile(filepath.Join(p.GuardRoot, "fallback-ready.json"))
	if err != nil {
		return errors.New("SYSTEM fallback has not acknowledged this run")
	}
	if json.Unmarshal(data, &proof) != nil || proof.RunID != p.RunID || proof.SHA256 != p.SHA256 || proof.BootID != boot || proof.Principal != "S-1-5-18" || time.Since(proof.UTC) < 0 || time.Since(proof.UTC) > 2*time.Second {
		return errors.New("SYSTEM fallback proof invalid or stale")
	}
	claim, err := createPrivateFile(filepath.Join(p.GuardRoot, "guard-started.json"))
	if err != nil {
		return errors.New("guardian already started or cannot claim this run")
	}
	if _, err = claim.WriteString(time.Now().UTC().Format(time.RFC3339Nano)); err == nil {
		err = claim.Sync()
	}
	_ = claim.Close()
	if err != nil {
		return err
	}
	job, err := createJob(p)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(job)
	defer func() {
		if err := recoverRun(p); err != nil {
			event(p, "primary-recovery-failed", err)
			result = errors.Join(result, err)
		}
	}()
	if err = withGate(p, func() error {
		if terminal(p) || due(p, boot, time.Now().UTC(), tickElapsed(p, tickCount())) {
			return errors.New("run expired before worker launch")
		}
		return spawnWorker(p, job)
	}); err != nil {
		return err
	}
	if inspectionFault {
		event(p, "injected-worker-identity-unavailable", errors.New("synthetic inspection failure; deadline remains armed"))
	}
	awaitDeadline(p, boot, time.Now, func() time.Duration { return tickElapsed(p, tickCount()) }, func() bool { return terminal(p) }, func() { time.Sleep(100 * time.Millisecond) })
	return nil
}

func worker(p plan) error {
	if err := verifyWorkerJob(p); err != nil {
		return err
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	if p.WorkerMode == "permit" {
		if err = withGate(p, func() error {
			if terminal(p) || due(p, boot, time.Now().UTC(), tickElapsed(p, tickCount())) {
				return errors.New("permit worker expired before one-shot installation")
			}
			if err := platform.CreateAcceptancePermitCanary(p.Owner, p.NetworkRoot); err != nil {
				return err
			}
			return writeJSON(p, "permit-created.json", struct {
				RunID, Provider, Fingerprint string
				Filters, Sublayers           int
				UTC                          time.Time
			}{p.RunID, p.Provider, p.Fingerprint, 4, 1, time.Now().UTC()})
		}); err != nil {
			return err
		}
	}
	for !terminal(p) && !due(p, boot, time.Now().UTC(), tickElapsed(p, tickCount())) {
		if err = writeJSON(p, "worker-heartbeat.json", struct {
			PID int
			UTC time.Time
		}{os.Getpid(), time.Now().UTC()}); err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func recoverRun(p plan) error {
	return withGate(p, func() error {
		return recoverySequence(func() error { return writeJSON(p, "terminal.json", struct{ UTC time.Time }{time.Now().UTC()}) }, func() error { return terminateOwnedJob(p) }, func() error { return platform.RecoverEmergencyWFPProviderExpected(p.Provider, p.Fingerprint) }, func() error {
			return writeJSON(p, "recovered.json", struct {
				RunID, Provider, WorkerMode, Scope string
				UTC                                time.Time
			}{p.RunID, p.Provider, p.WorkerMode, "marker/permit-only; no deny, adapter, route, DNS, service or registry mutation", time.Now().UTC()})
		})
	})
}

func inspect(p plan) error {
	entries, err := platform.EmergencyWFPInventory()
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(inspectionForPlan(p, entries))
}

type inspectionView struct {
	RunID, Provider, ExpectedFingerprint, RootFingerprint string
	Present, Recoverable                                  bool
	Filters, Sublayers                                    int
}

func inspectionForPlan(p plan, entries []platform.EmergencyWFPProvider) inspectionView {
	view := inspectionView{RunID: p.RunID, Provider: p.Provider, ExpectedFingerprint: p.Fingerprint}
	for _, entry := range entries {
		if entry.GUID == p.Provider {
			view.Present = true
			view.RootFingerprint = entry.RootFingerprint
			view.Recoverable = entry.Recoverable
			view.Filters = entry.Filters
			view.Sublayers = entry.Sublayers
			break
		}
	}
	return view
}
