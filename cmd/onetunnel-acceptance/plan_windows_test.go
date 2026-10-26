//go:build windows && onetunnel_safety_test

package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
)

func syntheticPlan() plan {
	id := strings.Repeat("a", 32)
	root, network, owner, provider, fingerprint := scope(`C:\ProgramData`, id)
	created := time.Unix(1000, 0).UTC()
	return plan{Version: 1, RunID: id, GuardRoot: root, NetworkRoot: network, Owner: owner, Provider: provider, Fingerprint: fingerprint, Executable: filepath.Join(root, "OneTunnel.Acceptance.exe"), SHA256: strings.Repeat("0", 64), BootID: "{00000000-0000-0000-0000-000000000001}", WorkerMode: "marker", Created: created, Deadline: created.Add(time.Minute), DurationSeconds: 60, StartTick: 1000}
}

func TestAcceptanceRecoveryAlwaysAttemptsScopedWFP(t *testing.T) {
	for _, failed := range []string{"terminal", "job", "wfp"} {
		t.Run(failed, func(t *testing.T) {
			var calls []string
			step := func(name string) func() error {
				return func() error {
					calls = append(calls, name)
					if name == failed {
						return errors.New(name + " unavailable")
					}
					return nil
				}
			}
			if err := recoverySequence(step("terminal"), step("job"), step("wfp"), step("confirmed")); err == nil {
				t.Fatal("failed recovery reported success")
			}
			if strings.Join(calls, ",") != "terminal,job,wfp" {
				t.Fatalf("scoped recovery skipped or false confirmation: %v", calls)
			}
		})
	}
	var confirmed bool
	if err := recoverySequence(func() error { return nil }, func() error { return nil }, func() error { return nil }, func() error { confirmed = true; return nil }); err != nil || !confirmed {
		t.Fatal("complete recovery did not confirm")
	}
}

func TestAcceptancePlanRejectsScopeOrDeadlineChanges(t *testing.T) {
	p := syntheticPlan()
	manifest := filepath.Join(p.GuardRoot, "plan.json")
	if err := p.validate(`C:\ProgramData`, manifest); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*plan){
		"production-owner":    func(p *plan) { p.Owner = "S-1-5-18" },
		"foreign-provider":    func(p *plan) { p.Provider = "{00000000-0000-0000-0000-000000000001}" },
		"foreign-root":        func(p *plan) { p.NetworkRoot = `C:\ProgramData\OneTunnel` },
		"arbitrary-worker":    func(p *plan) { p.WorkerMode = "connect" },
		"external-executable": func(p *plan) { p.Executable = `C:\Temp\worker.exe` },
		"deadline-extension":  func(p *plan) { p.Deadline = p.Deadline.Add(time.Second) },
		"excess-duration":     func(p *plan) { p.DurationSeconds = 121; p.Deadline = p.Created.Add(121 * time.Second) },
		"invalid-hash":        func(p *plan) { p.SHA256 = "missing" },
		"invalid-boot":        func(p *plan) { p.BootID = "missing" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := p
			change(&changed)
			if changed.validate(`C:\ProgramData`, manifest) == nil {
				t.Fatal("unsafe plan accepted")
			}
		})
	}
}

func TestAcceptanceModesNeverAcceptTrafficBlocking(t *testing.T) {
	p := syntheticPlan()
	manifest := filepath.Join(p.GuardRoot, "plan.json")
	for _, mode := range []string{"marker", "permit", "block", "connect", "tun", ""} {
		p.WorkerMode = mode
		err := p.validate(`C:\ProgramData`, manifest)
		if (err == nil) != (mode == "marker" || mode == "permit") {
			t.Fatalf("worker mode %q accepted incorrectly: %v", mode, err)
		}
	}
}

func TestAcceptanceDeadlineDoesNotDependOnWorkerIdentity(t *testing.T) {
	p := syntheticPlan()
	if due(p, p.BootID, p.Created, 0) {
		t.Fatal("fresh plan expired")
	}
	if !due(p, p.BootID, p.Created.Add(-time.Hour), time.Minute) {
		t.Fatal("clock rollback extended monotonic deadline")
	}
	if !due(p, p.BootID, p.Deadline, 0) {
		t.Fatal("UTC deadline ignored")
	}
	if !due(p, "different-boot", p.Created, 0) {
		t.Fatal("reboot did not require immediate recovery")
	}
	// No worker PID/creation-time state is accepted by the deadline decision.
	if due(p, p.BootID, p.Created, 59*time.Second) {
		t.Fatal("deadline fired early")
	}
}

func TestAcceptanceSyntheticProviderMatchesHistoricalDerivation(t *testing.T) {
	_, _, _, provider, _ := scope(`C:\ProgramData`, "412bc58265d84cddbfcf68e95d556301")
	if provider != "{D6E3D9D9-3BA8-55E5-532F-4C821DB7929D}" {
		t.Fatalf("provider key byte order changed: %s", provider)
	}
}

func TestAcceptanceWaitSurvivesDiagnosticFailureAndClockRollback(t *testing.T) {
	p := syntheticPlan()
	ticks := p.StartTick
	pauses := 0
	// A worker inspection failure is diagnostic only: it is never passed as a timer termination condition.
	inspectionUnavailable := true
	recovered := false
	awaitDeadline(p, p.BootID, func() time.Time { return p.Created.Add(-time.Hour) }, func() time.Duration { return tickElapsed(p, ticks) }, func() bool { return false }, func() {
		pauses++
		if !inspectionUnavailable {
			t.Fatal("fixture lost inspection fault")
		}
		ticks += 1000
	})
	recovered = true
	if !recovered || pauses != 60 {
		t.Fatalf("recovery responsibility ended before immutable deadline: %d", pauses)
	}
	if tickElapsed(p, p.StartTick-1) != time.Minute {
		t.Fatal("stale boot tick must expire immediately")
	}
}

func TestAcceptanceInspectionReportsOnlyExactPlanProvider(t *testing.T) {
	p := syntheticPlan()
	foreign := platform.EmergencyWFPProvider{GUID: "{11111111-1111-4111-8111-111111111111}", RootFingerprint: "foreign", Recoverable: true, Filters: 99, Sublayers: 2}
	absent := inspectionForPlan(p, []platform.EmergencyWFPProvider{foreign})
	if absent.Present || absent.Filters != 0 || absent.Sublayers != 0 || absent.Provider != p.Provider || absent.ExpectedFingerprint != p.Fingerprint {
		t.Fatalf("foreign provider adopted: %+v", absent)
	}
	owned := platform.EmergencyWFPProvider{GUID: p.Provider, RootFingerprint: p.Fingerprint, Recoverable: true, Filters: 4, Sublayers: 1}
	present := inspectionForPlan(p, []platform.EmergencyWFPProvider{foreign, owned})
	if !present.Present || !present.Recoverable || present.RootFingerprint != p.Fingerprint || present.Filters != 4 || present.Sublayers != 1 {
		t.Fatalf("exact provider not reported: %+v", present)
	}
	owned.RootFingerprint = "mismatch"
	mismatch := inspectionForPlan(p, []platform.EmergencyWFPProvider{owned})
	if mismatch.RootFingerprint == mismatch.ExpectedFingerprint {
		t.Fatal("inspection hid a mismatching fingerprint")
	}
}
