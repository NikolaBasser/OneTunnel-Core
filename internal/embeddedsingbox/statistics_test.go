//go:build windows && embeddedsingbox

package embeddedsingbox

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type fakeStatsOutbound struct {
	adapter.Outbound
	tag string
}

func (o fakeStatsOutbound) Tag() string          { return o.tag }
func (fakeStatsOutbound) Type() string           { return "test" }
func (fakeStatsOutbound) Network() []string      { return nil }
func (fakeStatsOutbound) Dependencies() []string { return nil }

type countConn struct {
	readN, writeN     int
	readErr, writeErr error
}

func (c *countConn) Read(p []byte) (int, error) {
	if c.readN > len(p) {
		c.readN = len(p)
	}
	for i := 0; i < c.readN; i++ {
		p[i] = 'x'
	}
	return c.readN, c.readErr
}
func (c *countConn) Write(p []byte) (int, error) {
	n := c.writeN
	if n > len(p) {
		n = len(p)
	}
	return n, c.writeErr
}
func (*countConn) Close() error                     { return nil }
func (*countConn) LocalAddr() net.Addr              { return fakeAddr("local") }
func (*countConn) RemoteAddr() net.Addr             { return fakeAddr("remote") }
func (*countConn) SetDeadline(time.Time) error      { return nil }
func (*countConn) SetReadDeadline(time.Time) error  { return nil }
func (*countConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return "test" }
func (a fakeAddr) String() string  { return string(a) }

type countPacketConn struct {
	N.PacketConn
	payload           []byte
	readErr, writeErr error
}

type benchmarkPacketConn struct {
	N.PacketConn
	writes atomic.Uint64
}

func (c *benchmarkPacketConn) WritePacket(*buf.Buffer, M.Socksaddr) error {
	c.writes.Add(1)
	return nil
}

func (c countPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	_, _ = b.Write(c.payload)
	return M.Socksaddr{}, c.readErr
}
func (c countPacketConn) WritePacket(*buf.Buffer, M.Socksaddr) error { return c.writeErr }

func TestIngressTrackerCountsOnlySelectedIngressAndSinglePath(t *testing.T) {
	start := time.Unix(100, 0)
	stats, id, err := control.NewStatisticsAccumulator(start, "proxy-payload")
	if err != nil {
		t.Fatal(err)
	}
	tracker := newIngressTracker(stats, false)
	partial := errors.New("partial")
	conn := &countConn{readN: 2, writeN: 3, readErr: partial, writeErr: partial}
	wrapped := tracker.RoutedConnection(context.Background(), conn, adapter.InboundContext{Inbound: "local"}, nil, nil)
	if _, ok := wrapped.(io.ReaderFrom); ok {
		t.Fatal("wrapper exposes ReaderFrom fast-copy bypass")
	}
	if _, ok := wrapped.(io.WriterTo); ok {
		t.Fatal("wrapper exposes WriterTo fast-copy bypass")
	}
	bufRead := make([]byte, 8)
	_, _ = wrapped.Read(bufRead)
	_, _ = wrapped.Write([]byte("12345"))
	failed := tracker.RoutedConnection(context.Background(), &countConn{writeN: 0, writeErr: errors.New("failed")}, adapter.InboundContext{Inbound: "local"}, nil, nil)
	_, _ = failed.Write([]byte("secret"))
	got := stats.Snapshot(start.Add(time.Second), id)
	if *got.UploadedBytes != 2 || *got.DownloadedBytes != 3 {
		t.Fatalf("partial read/write counts: %+v", got)
	}

	// The selected sing-box route takes either the regular wrapper edge or the
	// PreMatch fast-flow NewTracker edge; route.go constructs flow trackers only
	// for PreMatchFlow, then dispatches that flow instead of Route*ConnectionEx.
	tunStats, tunID, err := control.NewStatisticsAccumulator(start, "proxy-payload-and-packets")
	if err != nil {
		t.Fatal(err)
	}
	tunTracker := newIngressTracker(tunStats, true)
	flow := tunTracker.RoutedFlow(context.Background(), adapter.InboundContext{Inbound: "tun-in"}, nil, nil)
	flow.CountForward(7)
	flow.CountReverse(4)
	userTunConn := tunTracker.RoutedConnection(context.Background(), &countConn{readN: 3}, adapter.InboundContext{Inbound: "tun-in"}, nil, fakeStatsOutbound{tag: "proxy"})
	_, _ = userTunConn.Read(bufRead)
	tunTracker.RoutedConnection(context.Background(), &countConn{readN: 9}, adapter.InboundContext{Inbound: "local"}, nil, nil).Read(bufRead)
	if tunTracker.RoutedFlow(context.Background(), adapter.InboundContext{Inbound: "local"}, nil, nil) != nil {
		t.Fatal("local probe entered whole-device flow counts")
	}
	if tunTracker.RoutedFlow(context.Background(), adapter.InboundContext{Inbound: "tun-in"}, nil, fakeStatsOutbound{tag: "xray-uplink"}) != nil {
		t.Fatal("Xray infrastructure flow counted")
	}
	got = tunStats.Snapshot(start.Add(time.Second), tunID)
	if *got.UploadedBytes != 10 || *got.DownloadedBytes != 4 {
		t.Fatalf("unexpected TUN ingress totals: %+v", got)
	}
	infraConn := tunTracker.RoutedConnection(context.Background(), &countConn{readN: 9}, adapter.InboundContext{Inbound: "tun-in"}, nil, fakeStatsOutbound{tag: "xray-uplink"})
	if _, wrapped := infraConn.(trackedConn); wrapped {
		t.Fatal("infrastructure connection was wrapped for counting")
	}
	local := newIngressTracker(stats, false)
	localConn := local.RoutedConnection(context.Background(), &countConn{readN: 2}, adapter.InboundContext{Inbound: "local"}, nil, fakeStatsOutbound{tag: "xray-uplink"})
	_, _ = localConn.Read(bufRead)
	got = stats.Snapshot(start.Add(2*time.Second), id)
	if *got.UploadedBytes != 4 {
		t.Fatalf("local proxy ingress was excluded with bridge outbound: %+v", got)
	}
}

func TestIngressPacketCountsActualPayloadOnlyOnSuccess(t *testing.T) {
	start := time.Unix(200, 0)
	stats, id, err := control.NewStatisticsAccumulator(start, "proxy-payload")
	if err != nil {
		t.Fatal(err)
	}
	tracker := newIngressTracker(stats, false)
	pc := tracker.RoutedPacketConnection(context.Background(), countPacketConn{payload: []byte("12345")}, adapter.InboundContext{Inbound: "local"}, nil, nil)
	b := buf.New()
	defer b.Release()
	if _, err = pc.ReadPacket(b); err != nil {
		t.Fatal(err)
	}
	if err = pc.WritePacket(b, M.Socksaddr{}); err != nil {
		t.Fatal(err)
	}
	bad := tracker.RoutedPacketConnection(context.Background(), countPacketConn{payload: []byte("hidden"), writeErr: errors.New("failed")}, adapter.InboundContext{Inbound: "local"}, nil, nil)
	b2 := buf.New()
	defer b2.Release()
	_, _ = bad.ReadPacket(b2)
	_ = bad.WritePacket(b2, M.Socksaddr{})
	badRead := tracker.RoutedPacketConnection(context.Background(), countPacketConn{payload: []byte("ignored"), readErr: errors.New("failed")}, adapter.InboundContext{Inbound: "local"}, nil, nil)
	b3 := buf.New()
	defer b3.Release()
	_, _ = badRead.ReadPacket(b3)
	got := stats.Snapshot(start.Add(time.Second), id)
	if *got.UploadedBytes != 11 || *got.DownloadedBytes != 5 {
		t.Fatalf("packet counters: %+v", got)
	}
}

func TestIngressCallbacksAndSamplingAreConcurrentSafe(t *testing.T) {
	start := time.Unix(300, 0)
	stats, id, err := control.NewStatisticsAccumulator(start, "proxy-payload")
	if err != nil {
		t.Fatal(err)
	}
	const goroutines = 8
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				stats.AddUploaded(1)
				stats.AddDownloaded(2)
				_ = stats.Snapshot(start.Add(time.Duration(j+1)*time.Millisecond), id)
			}
		}()
	}
	wg.Wait()
	got := stats.Snapshot(start.Add(2*time.Second), id)
	if *got.UploadedBytes != goroutines*1000 || *got.DownloadedBytes != goroutines*2000 {
		t.Fatalf("concurrent totals: %+v", got)
	}
}

// These benchmarks compare the actual in-memory wrapper calls with their
// direct equivalents. They avoid sockets and measure only per-payload overhead.
func BenchmarkIngressWrapperOverhead(b *testing.B) {
	const payloadSize = 1024
	buffer := make([]byte, payloadSize)
	start := time.Unix(400, 0)
	stats, _, err := control.NewStatisticsAccumulator(start, "proxy-payload")
	if err != nil {
		b.Fatal(err)
	}
	tracker := newIngressTracker(stats, false)
	packetBuffer := buf.New()
	defer packetBuffer.Release()
	if _, err := packetBuffer.Write(buffer); err != nil {
		b.Fatal(err)
	}

	b.Run("tcp/direct-read-write", func(b *testing.B) {
		conn := &countConn{readN: payloadSize, writeN: payloadSize}
		b.SetBytes(2 * payloadSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = conn.Read(buffer)
			_, _ = conn.Write(buffer)
		}
	})
	b.Run("tcp/tracked-read-write", func(b *testing.B) {
		conn := tracker.RoutedConnection(context.Background(), &countConn{readN: payloadSize, writeN: payloadSize}, adapter.InboundContext{Inbound: "local"}, nil, nil)
		b.SetBytes(2 * payloadSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = conn.Read(buffer)
			_, _ = conn.Write(buffer)
		}
	})
	b.Run("udp/direct-write", func(b *testing.B) {
		conn := &benchmarkPacketConn{}
		b.SetBytes(payloadSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = conn.WritePacket(packetBuffer, M.Socksaddr{})
		}
		b.StopTimer()
		if got := conn.writes.Load(); got != uint64(b.N) {
			b.Fatalf("lost direct packet writes: %d", got)
		}
	})
	b.Run("udp/tracked-write", func(b *testing.B) {
		base := &benchmarkPacketConn{}
		conn := tracker.RoutedPacketConnection(context.Background(), base, adapter.InboundContext{Inbound: "local"}, nil, nil)
		b.SetBytes(payloadSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = conn.WritePacket(packetBuffer, M.Socksaddr{})
		}
		b.StopTimer()
		if got := base.writes.Load(); got != uint64(b.N) {
			b.Fatalf("lost tracked packet writes: %d", got)
		}
	})
}
