//go:build windows && onetunnel_safety_test

package platform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestProxyAcceptanceRejectsBeforeRuntimeEffects(t *testing.T) {
	for _, kind := range []int{-1, 0, 1, len(protocol.Names)} {
		result := ProbeProxyForAcceptance(context.Background(), "not-an-engine-directory", control.Profile{Protocol: kind})
		if result.CheckCompleted || result.NetworkTest || result.Success || result.CleanupError {
			t.Fatalf("unsafe protocol %d was not rejected: %+v", kind, result)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := ProbeProxyForAcceptance(ctx, "not-an-engine-directory", control.Profile{Protocol: 2})
	if result.CheckCompleted || result.CleanupError {
		t.Fatalf("cancelled probe reached runtime effects: %+v", result)
	}
}

func TestProxyAcceptanceCleanupPreservesForeignDirectory(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "foreign.txt")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if removeEmptyAcceptanceRuntime(root, "OneTunnel-Service") {
		t.Fatal("foreign runtime accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatal("foreign file changed")
	}
}
