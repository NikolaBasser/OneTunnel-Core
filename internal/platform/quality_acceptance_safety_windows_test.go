//go:build windows && onetunnel_safety_test

package platform

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"golang.org/x/sys/windows"
)

func TestQualityLiveVMSelectionAndFallback(t *testing.T) {
	if os.Getenv("ONETUNNEL_QUALITY_ACCEPTANCE") != "1" {
		t.Skip("explicit VM acceptance opt-in required")
	}
	host, _ := os.Hostname()
	if !strings.EqualFold(host, "WIN-67BE833BA6F") || !windows.GetCurrentProcessToken().IsElevated() || !embeddedSingBoxAllowed(false, false) {
		t.Fatal("requires dedicated elevated production-engine VM")
	}
	slow, err := newAcceptanceGateway()
	if err != nil {
		t.Fatal(err)
	}
	defer slow.stop()
	fast, err := newAcceptanceGateway()
	if err != nil {
		t.Fatal(err)
	}
	defer fast.stop()
	slow.mu.Lock()
	slow.delay = 900 * time.Millisecond
	slow.mu.Unlock()
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(random[:])
	owner := "OneTunnel-Test-" + id
	data, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(data, "OneTunnel-Phase4Runtime-"+id)
	r, err := NewSafetyTestRuntime(t.TempDir(), owner, root, func(control.State) {})
	if err != nil {
		t.Fatal(err)
	}
	r.forceSecureBootstrap = true
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		stopped, err := r.Call(ctx, control.Request{Version: 1, Command: "stop"})
		if err != nil || stopped.Error != nil || stopped.State.Active || stopped.State.TrafficLocked {
			t.Error("stop did not restore idle state")
		}
		r.Close()
		if !removeEmptyAcceptanceRuntime(root, owner) {
			t.Error("isolated runtime not removed")
		}
	}()
	p := control.Profile{ID: "11111111-1111-4111-8111-111111111111", Name: "Slow quality fixture", Group: "quality", Protocol: 6, Source: "http://" + slow.address, Reliability: &control.ReliabilityOptions{AutoReconnect: true, UseFallbacks: true, AutoSelect: true}}
	b := p
	b.ID = "22222222-2222-4222-8222-222222222222"
	b.Name = "Fast quality fixture"
	b.Source = "http://" + fast.address
	request := control.Request{Version: 1, Command: "start", Profile: &p, Fallbacks: []control.Profile{b}}
	if code := control.Validate(request); code != "" {
		t.Fatal(code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	started := time.Now()
	reply, err := r.Call(ctx, request)
	if err != nil || reply.Error != nil {
		t.Fatalf("start: %v %+v", err, reply.Error)
	}
	if err = httpsCheck(ctx, reply.State.LocalPort); err != nil {
		t.Fatal(err)
	}
	initialSession := reply.State.Statistics.SessionID
	waitFor := func(expected string) control.State {
		for ctx.Err() == nil {
			state := r.snapshot()
			if state.Active && !state.Reconnecting && state.ProfileID != nil && *state.ProfileID == expected {
				return state
			}
			time.Sleep(time.Second)
		}
		t.Fatal("timed out waiting for automatic selection/fallback")
		return control.State{}
	}
	selected := waitFor(b.ID)
	if time.Since(started) < 2*time.Minute || selected.Statistics == nil || selected.Statistics.SessionID == initialSession {
		t.Fatal("hold/session boundary not respected")
	}
	if err = httpsCheck(ctx, selected.LocalPort); err != nil {
		t.Fatal(err)
	}
	t.Logf("quality switch after %s; slow CONNECTs=%d fast CONNECTs=%d; verified HTTPS and new statistics session", time.Since(started), slow.count(), fast.count())
	r.operations.Lock()
	quality := r.retry.quality
	fresh := quality != nil && len(quality.samples) == 0
	r.operations.Unlock()
	if !fresh {
		t.Fatal("quality history survived promotion")
	}
	fast.stop()
	restored := waitFor(p.ID)
	if err = httpsCheck(ctx, restored.LocalPort); err != nil {
		t.Fatal(err)
	}
	t.Logf("ordinary outage fallback restored slow peer after %s", time.Since(started))
	if restored.TrafficLocked || restored.WholeDevice {
		t.Fatal("proxy-only test changed device network")
	}
}
