package embeddedsingbox

import (
	"context"
	"net"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ingressTracker is attached once to sing-box before Start. The router invokes
// exactly one of the connection, packet-connection, or pre-match flow paths.
type ingressTracker struct {
	stats       *control.StatisticsAccumulator
	inbound     string
	wholeDevice bool
}

func newIngressTracker(stats *control.StatisticsAccumulator, wholeDevice bool) *ingressTracker {
	inbound := "local"
	if wholeDevice {
		inbound = "tun-in"
	}
	return &ingressTracker{stats: stats, inbound: inbound, wholeDevice: wholeDevice}
}

func (t *ingressTracker) tracks(metadata adapter.InboundContext, outbound adapter.Outbound) bool {
	return t != nil && metadata.Inbound == t.inbound && (!t.wholeDevice || outbound == nil || outbound.Tag() != "xray-uplink")
}

func (t *ingressTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, outbound adapter.Outbound) net.Conn {
	if !t.tracks(metadata, outbound) {
		return conn
	}
	return trackedConn{Conn: conn, stats: t.stats}
}
func (t *ingressTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, outbound adapter.Outbound) N.PacketConn {
	if !t.tracks(metadata, outbound) {
		return conn
	}
	return trackedPacketConn{PacketConn: conn, stats: t.stats}
}
func (t *ingressTracker) RoutedFlow(_ context.Context, metadata adapter.InboundContext, _ adapter.Rule, outbound adapter.Outbound) tun.FlowTracker {
	if !t.tracks(metadata, outbound) {
		return nil
	}
	return &trackedFlow{stats: t.stats}
}

// Embedding net.Conn intentionally exposes only net.Conn's method set, so
// optional WriterTo/ReaderFrom fast-copy methods cannot bypass accounting.
type trackedConn struct {
	net.Conn
	stats *control.StatisticsAccumulator
}

func (c trackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.stats.AddUploaded(uint64(n))
	}
	return n, err
}
func (c trackedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.stats.AddDownloaded(uint64(n))
	}
	return n, err
}

type trackedPacketConn struct {
	N.PacketConn
	stats *control.StatisticsAccumulator
}

// Preserve buffer sizing without exposing an unwrap path that bypasses counters.
func (c trackedPacketConn) FrontHeadroom() int  { return N.CalculateFrontHeadroom(c.PacketConn) }
func (c trackedPacketConn) RearHeadroom() int   { return N.CalculateRearHeadroom(c.PacketConn) }
func (c trackedPacketConn) ReaderOverhead() int { return N.CalculateReaderOverhead(c.PacketConn) }
func (c trackedPacketConn) ReaderMTU() int      { return N.CalculateMTU(c.PacketConn, nil) }
func (c trackedPacketConn) WriterMTU() int      { return N.CalculateMTU(nil, c.PacketConn) }

func (c trackedPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.PacketConn.ReadPacket(b)
	if err == nil {
		c.stats.AddUploaded(uint64(b.Len()))
	}
	return destination, err
}
func (c trackedPacketConn) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
	n := b.Len()
	err := c.PacketConn.WritePacket(b, destination)
	if err == nil {
		c.stats.AddDownloaded(uint64(n))
	}
	return err
}

type trackedFlow struct {
	stats *control.StatisticsAccumulator
}

func (f *trackedFlow) AttachFlow(tun.FlowHandle) {}
func (f *trackedFlow) CountForward(n int) {
	if n > 0 {
		f.stats.AddUploaded(uint64(n))
	}
}
func (f *trackedFlow) CountReverse(n int) {
	if n > 0 {
		f.stats.AddDownloaded(uint64(n))
	}
}
func (f *trackedFlow) FlowEstablished()              {}
func (f *trackedFlow) CloseFlow(tun.FlowCloseReason) {}

var _ adapter.ConnectionTracker = (*ingressTracker)(nil)
var _ net.Conn = trackedConn{}
var _ N.PacketConn = trackedPacketConn{}
var _ tun.FlowTracker = (*trackedFlow)(nil)
