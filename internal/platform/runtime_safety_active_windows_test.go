//go:build windows && onetunnel_safety_test

package platform

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestActiveSafetySessionRejectsUnownedOperations(t *testing.T) {
	root := filepath.Join(t.TempDir(), "isolated")
	directory := filepath.Join(t.TempDir(), "service")
	session := Session{Kind: "proxy", FullDevice: true, TunnelName: "OneTunnel012345abcdef", ConfigPath: filepath.Join(root, "runtime", "OneTunnel012345abcdef.json"), Engine: filepath.Join(directory, "engines", "sing-box.exe")}
	check := func(s Session) error {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return validateActiveSafetySession(b, root, directory)
	}
	if err := check(session); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*Session){
		func(s *Session) { s.Kind = "AmneziaWG" }, func(s *Session) { s.FullDevice = false }, func(s *Session) { s.EmbeddedNative = true },
		func(s *Session) { s.Pid = 123 }, func(s *Session) { s.XrayPid = 123 }, func(s *Session) { s.Started = 123 },
		func(s *Session) { s.Engine = filepath.Join(directory, "foreign.exe") }, func(s *Session) { s.ConfigPath = filepath.Join(root, "..", "foreign.json") },
		func(s *Session) { s.TunnelName = "OneTunnelInstalled" },
	} {
		s := session
		edit(&s)
		if err := check(s); err == nil {
			t.Fatalf("accepted unsafe session: %+v", s)
		}
	}
	b, _ := json.Marshal(session)
	if err := validateActiveSafetySession(append(b, []byte(" {}")...), root, directory); err == nil {
		t.Fatal("accepted JSON tail")
	}
	if err := validateActiveSafetySession([]byte(`{"Unknown":true}`), root, directory); err == nil {
		t.Fatal("accepted unknown field")
	}
}
func TestEmergencyLockReleaseRejectsForeignOwnerBeforeEffects(t *testing.T) {
	if err := ReleaseSafetyActiveLock("OneTunnel-Service", t.TempDir()); err == nil {
		t.Fatal("accepted installed owner")
	}
}
