//go:build windows && onetunnel_safety_test && embeddedawg

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/profiles"
)

func TestIsolatedDataPathRefusesRealRootRelativesAndReparse(t *testing.T) {
	base := t.TempDir()
	forbidden := filepath.Join(base, "real", "OneTunnel")
	root := filepath.Join(base, "isolated")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "profiles.bin")
	if err := os.WriteFile(file, []byte("synthetic encrypted fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := validateDataRoot(root, forbidden); err != nil || got != root {
		t.Fatal("isolated copy rejected", err)
	}
	for _, path := range []string{"", "relative", forbidden, filepath.Join(forbidden, "child"), filepath.Dir(forbidden), strings.ToUpper(forbidden), `\\server\share\copy`, `//server/share/copy`} {
		if _, err := validateDataRoot(path, forbidden); err == nil {
			t.Fatalf("unsafe path accepted: %q", path)
		}
	}
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateDataRoot(root, forbidden); err == nil {
		t.Fatal("empty encrypted copy accepted")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := validateDataRoot(root, forbidden); err == nil {
		t.Fatal("missing encrypted copy accepted")
	}
}

func TestNativeProbeClassificationIsBoundedAndSanitized(t *testing.T) {
	var items []profiles.Profile
	for _, source := range []string{"ok", "failed", "no-target", "negative", "missing"} {
		items = append(items, profiles.Profile{Protocol: 0, Source: source, ID: "private-id", Name: "private-name"})
	}
	items = append(items, profiles.Profile{Protocol: 2, Source: "must not probe"}, profiles.Profile{Protocol: 1, Source: "ok"})
	calls := 0
	rows := probeProfiles(context.Background(), items, func(ctx context.Context, source string, kind int) (bool, *int64, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 12*time.Second {
			t.Fatal("per-probe deadline missing")
		}
		latency := int64(7)
		switch source {
		case "ok":
			return true, &latency, nil
		case "failed":
			return true, &latency, errors.New("private error endpoint/password")
		case "no-target":
			return false, &latency, nil
		case "negative":
			latency = -1
			return true, &latency, nil
		case "missing":
			return true, nil, nil
		default:
			t.Fatal("non-native profile probed")
			return false, nil, nil
		}
	})
	if calls != 6 || rows[0].Count != 5 || rows[0].Attempted != 4 || rows[0].Success != 1 || rows[1].Success != 1 {
		t.Fatalf("unexpected aggregate: %+v calls=%d", rows, calls)
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"private", "Source", "ID", "Name", "error", "no-target"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("report contains private metadata %q", private)
		}
	}
	for len(items) < 30 {
		items = append(items, profiles.Profile{Protocol: 1, Source: "ok"})
	}
	calls = 0
	probeProfiles(context.Background(), items, func(context.Context, string, int) (bool, *int64, error) { calls++; return false, nil, nil })
	if calls != 16 {
		t.Fatalf("probe cap not enforced: %d", calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probeProfiles(ctx, items, func(context.Context, string, int) (bool, *int64, error) {
		t.Fatal("canceled batch probed")
		return false, nil, nil
	})
}
