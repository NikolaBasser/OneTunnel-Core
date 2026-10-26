//go:build windows && onetunnel_safety_test

package platform

import (
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"testing"
)

func TestReliabilityAcceptanceAllowlist(t *testing.T) {
	for _, target := range []string{"example.com:443", "www.gstatic.com:443", "captive.apple.com:443"} {
		if !acceptanceConnectTarget(target) {
			t.Fatalf("reject %s", target)
		}
	}
	for _, target := range []string{"example.com:80", "example.com:0443", "example.com.:443", "EXAMPLE.COM:443", "example.com:443@evil.invalid", "evil.invalid:443", "127.0.0.1:443", "[::1]:443", "example.com", "example.com:443:443"} {
		if acceptanceConnectTarget(target) {
			t.Fatalf("allow %s", target)
		}
	}
}
func TestReliabilityAcceptanceCases(t *testing.T) {
	for _, value := range []string{"reconnect", "fallback"} {
		if !validReliabilityCase(value) {
			t.Fatal(value)
		}
	}
	for _, value := range []string{"", "full", "native", "Reconnect", "reconnect/fallback"} {
		if validReliabilityCase(value) {
			t.Fatal(value)
		}
	}
}
func TestReliabilityAcceptanceRestoredState(t *testing.T) {
	id := "synthetic"
	good := control.State{Active: true, LocalPort: 1234, ProfileID: &id, Statistics: &control.ConnectionStatistics{SessionID: "new"}}
	if !acceptanceRestored(good, id, "old") {
		t.Fatal("valid restored state")
	}
	for name, mutate := range map[string]func(*control.State){
		"recovery":   func(s *control.State) { s.NeedsRecovery = true },
		"full":       func(s *control.State) { s.FullDeviceMode = true },
		"inactive":   func(s *control.State) { s.Active = false },
		"retrying":   func(s *control.State) { s.Reconnecting = true },
		"attempt":    func(s *control.State) { s.ReconnectAttempt = 1 },
		"locked":     func(s *control.State) { s.TrafficLocked = true },
		"whole":      func(s *control.State) { s.WholeDevice = true },
		"profile":    func(s *control.State) { s.ProfileID = nil },
		"statistics": func(s *control.State) { s.Statistics = nil },
		"port":       func(s *control.State) { s.LocalPort = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			state := good
			mutate(&state)
			if acceptanceRestored(state, id, "old") {
				t.Fatal("accepted invalid state")
			}
		})
	}
	if acceptanceRestored(good, id, "new") || acceptanceRestored(good, "other", "old") {
		t.Fatal("accepted stale session or wrong profile")
	}
}
