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

	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
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

func TestProxyProbeRejectsNativeAndInvalidBeforeEffects(t *testing.T) {
	for _, kind := range []int{-1, 0, 1, 11, 100} {
		got := platform.ProbeProxyForAcceptance(context.Background(), "must-not-access", profiles.Profile{Protocol: kind, Source: "secret"})
		if got.CheckCompleted || got.NetworkTest || got.Success || got.CleanupError || got.HTTPSLatencyMilliseconds != nil {
			t.Fatal("unsafe protocol accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := platform.ProbeProxyForAcceptance(ctx, "must-not-access", profiles.Profile{Protocol: 2}); got.CheckCompleted || got.CleanupError {
		t.Fatal("canceled probe had effects")
	}
}

func TestProxyOffsetFiltersBeforeSkippingAndPreservesOrder(t *testing.T) {
	items := []profiles.Profile{{Protocol: 0, ID: "native"}, {Protocol: 2, ID: "first"}, {Protocol: 99, ID: "unknown"}, {Protocol: 1, ID: "native"}, {Protocol: 4, ID: "second"}, {Protocol: 5, ID: "third"}}
	for _, offset := range []int{-1, 4, 100} {
		if _, err := filterProxyProfilesFromOffset(items, offset); err == nil {
			t.Fatal("invalid offset accepted")
		}
	}
	for _, invalid := range []struct {
		scope  string
		offset int
	}{{"native", 1}, {"native", -1}, {"proxy", -1}, {"unknown", 0}} {
		if validateProbeScopeOffset(invalid.scope, invalid.offset) == nil {
			t.Fatal("invalid scope offset accepted")
		}
	}
	if validateProbeScopeOffset("native", 0) != nil || validateProbeScopeOffset("proxy", 32) != nil {
		t.Fatal("valid scope rejected")
	}
	got, err := filterProxyProfilesFromOffset(items, 1)
	if err != nil || len(got) != 2 || got[0].ID != "second" || got[1].ID != "third" {
		t.Fatal("offset applied before protocol filtering")
	}
	got[0].ID = "changed"
	if items[4].ID != "second" {
		t.Fatal("filter aliases input slice")
	}
	if got, err = filterProxyProfilesFromOffset(items, 3); err != nil || len(got) != 0 {
		t.Fatal("end offset should be an empty batch")
	}
	var batch []profiles.Profile
	for i := 0; i < 38; i++ {
		batch = append(batch, profiles.Profile{Protocol: 2})
	}
	remaining, err := filterProxyProfilesFromOffset(batch, 32)
	if err != nil || len(remaining) != 6 {
		t.Fatal("resume did not select remaining six")
	}
	calls := 0
	rows := probeProxyProfiles(context.Background(), remaining, func(context.Context, profiles.Profile) platform.ProxyAcceptanceCheck {
		calls++
		return platform.ProxyAcceptanceCheck{CheckCompleted: true}
	})
	if calls != 6 || rows[0].Count != 6 || rows[0].CheckCompleted != 6 {
		t.Fatal("resume reran previous profiles")
	}
}

func TestProxyProbeAggregationIsBoundedAndSanitized(t *testing.T) {
	items := []profiles.Profile{{Protocol: 0}, {Protocol: 1}, {Protocol: -1}, {Protocol: 99}}
	for _, source := range []string{"ok", "negative", "incomplete", "invalid-latency", "missing-latency"} {
		items = append(items, profiles.Profile{Protocol: 2, Source: source, Name: "private-name", ID: "private-id"})
	}
	calls := 0
	rows := probeProxyProfiles(context.Background(), items, func(ctx context.Context, p profiles.Profile) platform.ProxyAcceptanceCheck {
		calls++
		if p.Protocol != 2 {
			t.Fatal("non-proxy dispatched")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 30*time.Second {
			t.Fatal("missing deadline")
		}
		latency := int64(9)
		check := platform.ProxyAcceptanceCheck{CheckCompleted: true, NetworkTest: true, Success: true, HTTPSLatencyMilliseconds: &latency}
		switch p.Source {
		case "negative":
			check.Success = false
		case "incomplete":
			check.CheckCompleted = false
		case "invalid-latency":
			latency = -1
		case "missing-latency":
			check.HTTPSLatencyMilliseconds = nil
		}
		return check
	})
	if calls != 5 || rows[0].Count != 5 || rows[0].Attempted != 5 || rows[0].CheckCompleted != 4 || rows[0].Success != 1 || rows[0].HTTPSLatencyMilliseconds[0] != 9 {
		t.Fatalf("unexpected aggregate %+v", rows[0])
	}
	data, _ := json.Marshal(rows)
	for _, secret := range []string{"private", "Source", "Name", "ID", "negative", "incomplete"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("private metadata in report")
		}
	}
	items = nil
	for i := 0; i < 40; i++ {
		items = append(items, profiles.Profile{Protocol: 3})
	}
	calls = 0
	probeProxyProfiles(context.Background(), items, func(context.Context, profiles.Profile) platform.ProxyAcceptanceCheck {
		calls++
		return platform.ProxyAcceptanceCheck{CheckCompleted: true}
	})
	if calls != 32 {
		t.Fatalf("cap bypassed: %d", calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probeProxyProfiles(ctx, items, func(context.Context, profiles.Profile) platform.ProxyAcceptanceCheck {
		t.Fatal("canceled batch dispatched")
		return platform.ProxyAcceptanceCheck{}
	})
	calls = 0
	rows = probeProxyProfiles(context.Background(), items, func(context.Context, profiles.Profile) platform.ProxyAcceptanceCheck {
		calls++
		return platform.ProxyAcceptanceCheck{CheckCompleted: true, Success: true, CleanupError: true}
	})
	if calls != 1 || rows[1].CleanupError != 1 || rows[1].Success != 0 {
		t.Fatal("cleanup failure did not abort batch")
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
