//go:build windows && embeddedxray && embeddedsingbox

package platform

import (
	"encoding/json"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const fixtureService = "OneTunnelEmbeddedFixture"

type embeddedFixtureService struct{ t *testing.T }

func TestMain(m *testing.M) {
	system, _ := svc.IsWindowsService()
	if system {
		exe, _ := os.Executable()
		if file, err := os.Create(filepath.Join(filepath.Dir(exe), "worker.log")); err == nil {
			os.Stdout = file
			os.Stderr = file
			log.SetOutput(file)
		}
	}
	os.Exit(m.Run())
}

func (s *embeddedFixtureService) Execute(_ []string, _ <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.Running}
	ok := s.t.Run("SystemLocalTraffic", TestEmbeddedRuntimeLocalTraffic)
	if fullDeviceEmbeddingEnabled() {
		ok = s.t.Run("IsolatedTun", testEmbeddedTunSCM) && ok
	}
	if embeddedAWGEnabled() {
		ok = s.t.Run("EmbeddedAWG", testEmbeddedAWGSCM) && ok
	}
	exe, _ := os.Executable()
	data, _ := json.Marshal(map[string]bool{"Passed": ok, "System": windows.GetCurrentProcessToken().IsElevated(), "SyntheticHostRoutesTested": fullDeviceEmbeddingEnabled() || embeddedAWGEnabled(), "DefaultRoutesChanged": false, "WFPChanged": false, "IsolatedTun": fullDeviceEmbeddingEnabled(), "EmbeddedAWG": embeddedAWGEnabled()})
	if err := os.WriteFile(filepath.Join(filepath.Dir(exe), "system-fixture-result.json"), data, 0600); err != nil {
		return false, 1
	}
	if !ok {
		return false, 1
	}
	return false, 0
}

func TestEmbeddedSCMWorker(t *testing.T) {
	system, err := svc.IsWindowsService()
	if err != nil || !system {
		t.Skip("SCM worker only")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatal("SYSTEM required")
	}
	if err := svc.Run(fixtureService, &embeddedFixtureService{t}); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedSCMIntegration(t *testing.T) {
	if os.Getenv("ONETUNNEL_TEST_SCM") != "1" {
		t.Skip("explicit isolated SCM fixture required")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("admin fixture runner required")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(filepath.Dir(exe), "system-fixture-result.json")
	if _, err := os.Stat(result); !os.IsNotExist(err) {
		t.Fatal("fresh fixture result required")
	}
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	service, err := manager.CreateService(fixtureService, exe, mgr.Config{DisplayName: "OneTunnel isolated embedded loopback fixture"}, "-test.run=^TestEmbeddedSCMWorker$", "-test.timeout=45s", "-test.v")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	defer service.Delete()
	defer service.Control(svc.Stop)
	if err = service.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		data, readErr := os.ReadFile(result)
		if readErr == nil {
			var r struct{ Passed, System bool }
			if json.Unmarshal(data, &r) != nil || !r.Passed || !r.System {
				t.Fatal("SYSTEM traffic fixture failed")
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("SYSTEM fixture timeout")
}
