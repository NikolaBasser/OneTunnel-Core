package embeddedawg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"golang.org/x/crypto/curve25519"
)

type observedBind struct {
	conn.Bind
	opened atomic.Bool
	closed atomic.Int32
}

func (b *observedBind) Close() error {
	b.closed.Add(1)
	return b.Bind.Close()
}

func (b *observedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err == nil {
		b.opened.Store(true)
	}
	return fns, actual, err
}

func freeUDPPorts(t testing.TB) (uint16, uint16) {
	t.Helper()
	first, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	ports := [2]uint16{uint16(first.LocalAddr().(*net.UDPAddr).Port), uint16(second.LocalAddr().(*net.UDPAddr).Port)}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	return ports[0], ports[1]
}

func testKeyPair(t testing.TB) (string, string) {
	t.Helper()
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public)
}

func startPair(t testing.TB, obfuscated bool) (*Transport, *Transport) {
	return startPairMode(t, obfuscated, false)
}
func startPairMode(t testing.TB, obfuscated, awg31 bool) (*Transport, *Transport) {
	t.Helper()
	aPriv, aPub := testKeyPair(t)
	bPriv, bPub := testKeyPair(t)
	aPort, bPort := freeUDPPorts(t)
	plan := func(private, peer, endpoint, peerAddress string, local netip.Prefix, port uint16) *Plan {
		values := map[string]string{
			"iprivatekey":          private,
			"ilistenport":          fmt.Sprint(port),
			"ppublickey":           peer,
			"pendpoint":            endpoint,
			"pallowedips":          peerAddress + "/32",
			"ppersistentkeepalive": "1",
		}
		if obfuscated {
			values["ijc"], values["ijmin"], values["ijmax"] = "1", "1", "3"
			values["is1"], values["is2"] = "1", "2"
			values["ih1"], values["ih2"], values["ih3"], values["ih4"] = "11", "12", "13", "14"
		}
		if awg31 {
			values["is1"], values["is2"], values["is3"], values["is4"] = "16", "16", "16", "16"
			values["ih1"], values["ih2"], values["ih3"], values["ih4"] = "1", "2", "3", "4"
			values["iheaderprotectionkey"] = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
			values["icontentpaddingaddition"] = "0-16"
			values["irekeyaftertime"] = "110-130"
			values["irekeytimeout"] = "4-6"
			values["irejectaftertime"] = "170-190"
			values["ikeepalivetimeout"] = "20-30"
			values["imaxhandshakeattempts"] = "12-18"
			values["irandomtrailers"] = "on"
			values["idisablecookies"] = "off"
		}
		return &Plan{Addresses: []netip.Prefix{local}, Routes: []netip.Prefix{netip.MustParsePrefix(peerAddress + "/32")}, MTU: 1280, values: values}
	}
	aPlan := plan(aPriv, bPub, net.JoinHostPort("127.0.0.1", fmt.Sprint(bPort)), "10.77.0.2", netip.MustParsePrefix("10.77.0.1/32"), aPort)
	bPlan := plan(bPriv, aPub, net.JoinHostPort("127.0.0.1", fmt.Sprint(aPort)), "10.77.0.1", netip.MustParsePrefix("10.77.0.2/32"), bPort)
	newTransport := func(p *Plan) *Transport {
		b := &observedBind{Bind: conn.NewStdNetBind()}
		transport, err := StartTransport(p, b, func(conn.Bind) error {
			if !b.opened.Load() {
				return errors.New("physical binding ran before UDP sockets opened")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("start in-process AWG peer: %v", err)
		}
		t.Cleanup(func() { _ = transport.Close() })
		return transport
	}
	return newTransport(aPlan), newTransport(bPlan)
}

func TestTransportTCPRoundTripAndLiteralOnly(t *testing.T) {
	a, b := startPair(t, false)
	listener, err := b.stack.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.2:8081"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 4)
			if _, err = c.Read(buf); err == nil {
				_, _ = c.Write(buf)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := a.DialContext(ctx, "tcp", "10.77.0.2:8081")
	if err != nil {
		as, ar, ae := a.Counters()
		bs, br, be := b.Counters()
		ast, _ := a.engine.Status()
		bst, _ := b.engine.Status()
		t.Fatalf("%v; a counters %d/%d (%v) status %+v, b counters %d/%d (%v) status %+v", err, as, ar, ae, ast, bs, br, be, bst)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte("echo")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err = c.Read(got); err != nil || string(got) != "echo" {
		t.Fatalf("TCP round trip = %q, %v", got, err)
	}
	if _, err := a.DialContext(ctx, "tcp", "example.invalid:443"); err == nil {
		t.Fatal("hostname was accepted by native transport")
	}
	if _, err := a.DialContext(ctx, "tcp", "10.77.0.3:443"); err == nil {
		t.Fatal("destination outside peer AllowedIPs was accepted")
	}
}

func TestTransportUDPMetadataDeadlineAndCancellation(t *testing.T) {
	a, b := startPair(t, true)
	server, err := b.stack.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.2:9090"))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	pc, err := a.ListenPacket(ctx, "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pc.WriteTo([]byte("packet"), &net.UDPAddr{IP: net.IPv4(10, 77, 0, 2), Port: 9090}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := server.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "packet" {
		t.Fatalf("UDP peer receive = %q from %v, %v", buf[:n], from, err)
	}
	if _, err = server.WriteTo([]byte("reply"), from); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err = pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "reply" || from == nil {
		t.Fatalf("UDP reply = %q from %v, %v", buf[:n], from, err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	if _, _, err = pc.ReadFrom(buf); err == nil {
		t.Fatal("UDP read ignored its deadline")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("UDP deadline error = %v", err)
	}
	cancel()
	select {
	case <-pc.(*packetConn).done:
	case <-time.After(time.Second):
		t.Fatal("packet connection remained open after context cancellation")
	}
	if _, _, err = pc.ReadFrom(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after cancellation = %v", err)
	}
	connected, err := a.DialContext(context.Background(), "udp", "10.77.0.2:9090")
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	if _, err = connected.Write([]byte("connected")); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err = server.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "connected" {
		t.Fatalf("connected UDP receive = %q from %v, %v", buf[:n], from, err)
	}
	if _, err = server.WriteTo([]byte("connected reply"), from); err != nil {
		t.Fatal(err)
	}
	_ = connected.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = connected.Read(buf)
	if err != nil || string(buf[:n]) != "connected reply" {
		t.Fatalf("connected UDP reply = %q, %v", buf[:n], err)
	}
}

type packetWriteTrap struct{ wrote bool }

func (c *packetWriteTrap) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (c *packetWriteTrap) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.wrote = true
	return len(p), nil
}
func (*packetWriteTrap) Close() error                     { return nil }
func (*packetWriteTrap) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*packetWriteTrap) SetDeadline(time.Time) error      { return nil }
func (*packetWriteTrap) SetReadDeadline(time.Time) error  { return nil }
func (*packetWriteTrap) SetWriteDeadline(time.Time) error { return nil }

func TestTransportPacketConnRejectsScopedIPv6Destination(t *testing.T) {
	conn := &packetWriteTrap{}
	packet := &packetConn{
		owner: &Transport{
			addrs:  map[bool]bool{true: true},
			routes: []netip.Prefix{netip.MustParsePrefix("::/0")},
		},
		conns: map[bool]net.PacketConn{true: conn},
	}
	_, err := packet.WriteTo([]byte("scoped"), &net.UDPAddr{
		IP:   net.ParseIP("fe80::1"),
		Zone: "Ethernet",
		Port: 53,
	})
	if err == nil || conn.wrote {
		t.Fatalf("scoped IPv6 destination was accepted or transmitted: err=%v wrote=%v", err, conn.wrote)
	}
}

func TestTransportDialCancellation(t *testing.T) {
	a, _ := startPair(t, false)
	a.routes = []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := a.DialContext(ctx, "tcp", "10.77.0.99:8082")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial cancellation error = %v", err)
	}
}

func TestTransportConcurrentCloseClosesPacketFlows(t *testing.T) {
	a, _ := startPair(t, false)
	pc, err := a.ListenPacket(context.Background(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, _, err := pc.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("packet flow after transport close = %v", err)
	}
}

func TestTransportPinFailureRollsBackBind(t *testing.T) {
	private, _ := testKeyPair(t)
	_, public := testKeyPair(t)
	listenPort, endpointPort := freeUDPPorts(t)
	plan := &Plan{
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")},
		Routes:    []netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")},
		MTU:       1280,
		values: map[string]string{
			"iprivatekey": private,
			"ilistenport": fmt.Sprint(listenPort),
			"ppublickey":  public,
			"pendpoint":   net.JoinHostPort("127.0.0.1", fmt.Sprint(endpointPort)),
		},
	}
	bind := &observedBind{Bind: conn.NewStdNetBind()}
	called := false
	if _, err := StartTransport(plan, bind, func(conn.Bind) error {
		called = true
		if !bind.opened.Load() {
			t.Fatal("physical binding ran before UDP sockets opened")
		}
		return errors.New("simulated pin failure")
	}); err == nil {
		t.Fatal("transport started after physical binding failure")
	}
	if !called || bind.closed.Load() == 0 {
		t.Fatalf("pin callback called=%v, bind close calls=%d", called, bind.closed.Load())
	}
}

func BenchmarkTransportUDP1KiBEcho(b *testing.B) {
	for _, protocol := range []struct {
		name       string
		obfuscated bool
	}{{name: "WG"}, {name: "AWG", obfuscated: true}} {
		b.Run(protocol.name, func(b *testing.B) {
			b.StopTimer()
			client, peer := startPair(b, protocol.obfuscated)
			server, err := peer.stack.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.2:9090"))
			if err != nil {
				b.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				buf := make([]byte, 2048)
				for {
					n, from, err := server.ReadFrom(buf)
					if err != nil {
						select {
						case <-done:
							return
						default:
						}
						continue
					}
					if _, err = server.WriteTo(buf[:n], from); err != nil {
						return
					}
				}
			}()
			defer func() {
				close(done)
				_ = server.Close()
				_ = client.Close()
			}()
			ctx := context.Background()
			conn, err := client.DialContext(ctx, "udp", "10.77.0.2:9090")
			if err != nil {
				b.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Hour))
			payload, response := make([]byte, 1024), make([]byte, 1024)
			if _, err := conn.Write(payload); err != nil {
				b.Fatal(err)
			}
			if _, err := io.ReadFull(conn, response); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(2048)
			b.ReportAllocs()
			b.ResetTimer()
			b.StartTimer()
			for i := 0; i < b.N; i++ {
				if _, err := conn.Write(payload); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(conn, response); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTransportPacketUDP1KiBEcho(b *testing.B) {
	for _, protocol := range []struct {
		name       string
		obfuscated bool
	}{{name: "WG"}, {name: "AWG", obfuscated: true}} {
		for _, mode := range []struct {
			name      string
			unwrapped bool
		}{{name: "TransportPacketConn"}, {name: "DirectNetstackPacketConn", unwrapped: true}} {
			b.Run(protocol.name+"/"+mode.name, func(b *testing.B) {
				b.StopTimer()
				client, peer := startPair(b, protocol.obfuscated)
				server, err := peer.stack.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.2:9090"))
				if err != nil {
					b.Fatal(err)
				}
				done := make(chan struct{})
				go func() {
					buf := make([]byte, 2048)
					for {
						n, from, err := server.ReadFrom(buf)
						if err != nil {
							select {
							case <-done:
								return
							default:
							}
							continue
						}
						if _, err = server.WriteTo(buf[:n], from); err != nil {
							return
						}
					}
				}()
				var conn net.PacketConn
				if mode.unwrapped {
					conn, err = client.stack.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:0"))
				} else {
					conn, err = client.ListenPacket(context.Background(), "udp", "")
				}
				if err != nil {
					b.Fatal(err)
				}
				defer func() {
					close(done)
					_ = server.Close()
					_ = conn.Close()
					_ = client.Close()
				}()
				_ = conn.SetDeadline(time.Now().Add(time.Hour))
				payload, response := make([]byte, 1024), make([]byte, 1024)
				remote := &net.UDPAddr{IP: net.IPv4(10, 77, 0, 2), Port: 9090}
				if _, err := conn.WriteTo(payload, remote); err != nil {
					b.Fatal(err)
				}
				if _, _, err := conn.ReadFrom(response); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(2048)
				b.ReportAllocs()
				b.ResetTimer()
				b.StartTimer()
				for i := 0; i < b.N; i++ {
					if _, err := conn.WriteTo(payload, remote); err != nil {
						b.Fatal(err)
					}
					if _, _, err := conn.ReadFrom(response); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
