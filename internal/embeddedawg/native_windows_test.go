package embeddedawg

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestNativeCountersReachRuntimeBoundary(t *testing.T) {
	client, server := startPair(t, false)
	wrapper := &Native{core: client.engine}
	var counters interface {
		Counters() (uint64, uint64, error)
	} = wrapper
	echo, err := server.stack.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.2:9091"))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 512)
		n, from, e := echo.ReadFrom(b)
		if e == nil {
			_, _ = echo.WriteTo(b[:n], from)
		}
	}()
	beforeUp, beforeDown, err := counters.Counters()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := client.DialContext(ctx, "udp", "10.77.0.2:9091")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte("native-statistics")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != "native-statistics" {
		t.Fatal("native UDP round trip", err)
	}
	afterUp, afterDown, err := counters.Counters()
	if err != nil || afterUp <= beforeUp || afterDown <= beforeDown {
		t.Fatalf("native counters unavailable to runtime: up %d->%d, down %d->%d, err %v", beforeUp, afterUp, beforeDown, afterDown, err)
	}
}
