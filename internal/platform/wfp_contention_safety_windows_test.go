//go:build windows && onetunnel_safety_test

package platform

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"time"
)

// No providers, filters or sublayers are added. The independent timer releases
// the empty competing transaction even if the lookup unexpectedly blocks.
func TestWFPProviderReadTimesOutUnderContention(t *testing.T) {
	host, _ := os.Hostname()
	if host != "WIN-67BE833BA6F" {
		t.Skip("dedicated VM required")
	}
	holder, err := openWFP()
	if err != nil {
		t.Fatal(err)
	}
	defer wCall("FwpmEngineClose0", uintptr(holder))
	probe, err := openWFP()
	if err != nil {
		t.Fatal(err)
	}
	defer wCall("FwpmEngineClose0", uintptr(probe))
	key := (trafficLock{owner: "bounded-wfp-test", root: t.TempDir()}).key("provider")
	if p, err := lookupTrafficProvider(probe, &key); !errors.Is(err, windows.Errno(0x80320005)) {
		freeTrafficProvider(p)
		t.Fatalf("missing provider baseline: %v", err)
	}
	if err := wCall("FwpmTransactionBegin0", uintptr(holder), 0); err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	timer := time.AfterFunc(8*time.Second, func() { _ = wCall("FwpmTransactionAbort0", uintptr(holder)); close(released) })
	defer func() {
		if timer.Stop() {
			_ = wCall("FwpmTransactionAbort0", uintptr(holder))
		} else {
			<-released
		}
	}()
	start := time.Now()
	p, err := lookupTrafficProvider(probe, &key)
	freeTrafficProvider(p)
	elapsed := time.Since(start)
	if !errors.Is(err, windows.Errno(0x80320012)) || elapsed < 4*time.Second || elapsed > 7*time.Second {
		t.Fatalf("lookup was not bounded: elapsed=%v err=%v", elapsed, err)
	}
	t.Logf("provider read returned FWP_E_TIMEOUT after %v; no policy objects added", elapsed)
}
