//go:build windows && onetunnel_safety_test && embeddedawg && embeddedsingbox && embeddedtun && embeddedxray

package platform

import (
	"context"
	"encoding/json"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"os"
	"testing"
	"time"
)

func TestProxyChainLiveVMProbeAndHopFailures(t *testing.T) {
	if os.Getenv("ONETUNNEL_CHAIN_ACCEPTANCE") != "1" {
		t.Skip("explicit VM acceptance opt-in required")
	}
	f, err := NewChainAcceptanceFixture("Ethernet")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p := f.Profile()
	// References are by name, including a hop declared later in the document.
	p.Network.Targets[0], p.Network.Targets[1] = p.Network.Targets[1], p.Network.Targets[0]
	before, _ := json.Marshal(p.Network)
	r := &Runtime{qualityUplink: map[bool]string{false: "Ethernet", true: "Ethernet"}}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err = r.probeQuality(ctx, p); err != nil {
		t.Fatal("three-hop HTTPS probe failed", err)
	}
	counts := f.Counts()
	if counts[0] == 0 || counts[1] == 0 || counts[2] == 0 {
		t.Fatal("HTTPS bypassed a chain hop", counts)
	}
	for hop := 0; hop < 3; hop++ {
		if err = f.SetOnline(hop, false); err != nil {
			t.Fatal(err)
		}
		prior := f.Counts()
		check, done := context.WithTimeout(ctx, 4*time.Second)
		_, failed := r.probeQuality(check, p)
		done()
		if failed == nil {
			t.Fatalf("hop %d failure fell back to another route", hop)
		}
		after := f.Counts()
		if after[2] != prior[2] {
			t.Fatal("request reached exit despite failed hop", hop, prior, after)
		}
		if err = f.SetOnline(hop, true); err != nil {
			t.Fatal(err)
		}
		if _, err = r.probeQuality(ctx, p); err != nil {
			t.Fatal("chain did not recover", hop, err)
		}
	}
	after, _ := json.Marshal(p.Network)
	if string(before) != string(after) {
		t.Fatal("probe mutated saved chain")
	}
	if _, err = protocol.NormalizeNetworkOptions(p.Network); err != nil {
		t.Fatal(err)
	}
	t.Logf("three-hop HTTPS verified; each hop failure blocked exit; restored counts=%v", f.Counts())
}
