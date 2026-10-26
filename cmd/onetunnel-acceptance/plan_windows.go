//go:build windows && onetunnel_safety_test

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// No arbitrary executable, profile, or traffic-blocking action is accepted.
type plan struct {
	Version                                                     int
	RunID, GuardRoot, NetworkRoot, Owner, Provider, Fingerprint string
	Executable, SHA256, BootID, WorkerMode                      string
	Created, Deadline                                           time.Time
	DurationSeconds                                             int
	StartTick                                                   uint64
}

var runIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func scope(programData, id string) (root, network, owner, provider, fingerprint string) {
	root = filepath.Join(programData, "OneTunnelAcceptance", id)
	network = filepath.Join(programData, "OneTunnel-Phase4Runtime-"+id)
	owner = "OneTunnel-Test-" + id
	h := sha256.Sum256([]byte("OneTunnel.WFP.v1/" + owner + "/provider"))
	key := windows.GUID{Data1: binary.LittleEndian.Uint32(h[:4]), Data2: binary.LittleEndian.Uint16(h[4:6]), Data3: binary.LittleEndian.Uint16(h[6:8]), Data4: [8]byte(h[8:16])}
	provider = key.String()
	f := sha256.Sum256([]byte(strings.ToUpper(strings.TrimRight(filepath.Clean(network), `\`))))
	fingerprint = hex.EncodeToString(f[:])
	return
}

func (p plan) validate(programData, manifest string) error {
	if p.Version != 1 || !runIDPattern.MatchString(p.RunID) || p.DurationSeconds < 15 || p.DurationSeconds > 120 || (p.WorkerMode != "marker" && p.WorkerMode != "permit") {
		return errors.New("invalid or unsupported acceptance plan")
	}
	root, network, owner, provider, fingerprint := scope(programData, p.RunID)
	if p.GuardRoot != root || p.NetworkRoot != network || p.Owner != owner || p.Provider != provider || p.Fingerprint != fingerprint || manifest != filepath.Join(root, "plan.json") || p.Executable != filepath.Join(root, "OneTunnel.Acceptance.exe") {
		return errors.New("acceptance plan scope mismatch")
	}
	h, err := hex.DecodeString(p.SHA256)
	if err != nil || len(h) != 32 || p.StartTick == 0 || p.Created.IsZero() || !p.Deadline.Equal(p.Created.Add(time.Duration(p.DurationSeconds)*time.Second)) {
		return errors.New("invalid acceptance plan integrity/deadline")
	}
	if _, err = windows.GUIDFromString(p.BootID); err != nil {
		return errors.New("invalid acceptance boot identity")
	}
	return nil
}

func tickElapsed(p plan, current uint64) time.Duration {
	limit := time.Duration(p.DurationSeconds) * time.Second
	if current < p.StartTick || current-p.StartTick >= uint64(p.DurationSeconds)*1000 {
		return limit
	}
	return time.Duration(current-p.StartTick) * time.Millisecond
}

func due(p plan, boot string, utc time.Time, elapsed time.Duration) bool {
	return p.BootID != boot || !utc.Before(p.Deadline) || elapsed >= time.Duration(p.DurationSeconds)*time.Second
}

func awaitDeadline(p plan, boot string, utc func() time.Time, elapsed func() time.Duration, stopped func() bool, pause func()) {
	for !stopped() && !due(p, boot, utc(), elapsed()) {
		pause()
	}
}

func recoverySequence(terminal, stopJob, cleanupWFP, confirm func() error) error {
	terminalErr := terminal()
	jobErr := stopJob()
	wfpErr := cleanupWFP()
	if err := errors.Join(terminalErr, jobErr, wfpErr); err != nil {
		return err
	}
	return confirm()
}
