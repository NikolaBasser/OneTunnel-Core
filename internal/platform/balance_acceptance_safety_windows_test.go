//go:build windows && onetunnel_safety_test && embeddedawg && embeddedsingbox && embeddedtun && embeddedxray

package platform

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedawg"
	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedsingbox"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/proxy"
)

func balanceTestKey(t *testing.T) (string, string) {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	pub, e := curve25519.X25519(k, curve25519.Basepoint)
	if e != nil {
		t.Fatal(e)
	}
	return base64.StdEncoding.EncodeToString(k), base64.StdEncoding.EncodeToString(pub)
}
func balanceTestNative(t *testing.T, kind int, label string) (control.Profile, func()) {
	t.Helper()
	clientPrivate, clientPublic := balanceTestKey(t)
	serverPrivate, serverPublic := balanceTestKey(t)
	socket, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	endpoint := socket.LocalAddr().String()
	_, port, _ := net.SplitHostPort(endpoint)
	socket.Close()
	extras := ""
	if kind == 0 {
		extras = "Jc = 1\nJmin = 1\nJmax = 3\nS1 = 16\nS2 = 16\nH1 = 11\nH2 = 12\nH3 = 13\nH4 = 14\n"
	}
	source := func(private, public, local, peer, remote, listen string) string {
		return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nListenPort = %s\nMTU = 1420\n%s[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s/32\n", private, local, listen, extras, public, remote, peer)
	}
	serverSource := source(serverPrivate, clientPublic, "10.77.0.1", "10.77.0.2", "127.0.0.1:9", port)
	plan, e := embeddedawg.Parse(serverSource, kind, false)
	if e != nil {
		t.Fatal(e)
	}
	device, stack, e := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, 1420)
	if e != nil {
		t.Fatal(e)
	}
	engine, e := embeddedawg.Start(plan, device, conn.NewStdNetBind())
	if e != nil {
		t.Fatal(e)
	}
	listener, e := stack.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:19090"))
	if e != nil {
		t.Fatal(e)
	}
	packet, e := stack.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:19091"))
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				line, e := bufio.NewReader(c).ReadString('\n')
				if e == nil {
					io.WriteString(c, label+":"+line)
				}
			}()
		}
	}()
	go func() {
		b := make([]byte, 256)
		for {
			n, from, e := packet.ReadFrom(b)
			if e != nil {
				return
			}
			packet.WriteTo(append([]byte(label+":"), b[:n]...), from)
		}
	}()
	closeFn := func() { listener.Close(); packet.Close(); engine.Close() }
	t.Cleanup(closeFn)
	id := "11111111-1111-4111-8111-111111111111"
	if kind == 0 {
		id = "22222222-2222-4222-8222-222222222222"
	}
	return control.Profile{ID: id, Name: label, Protocol: kind, Group: label, Source: source(clientPrivate, serverPublic, "10.77.0.2", "10.77.0.1", endpoint, "0")}, closeFn
}
func balanceVMonly(t *testing.T) {
	t.Helper()
	host, _ := os.Hostname()
	if os.Getenv("ONETUNNEL_BALANCE_ACCEPTANCE") != "1" {
		t.Skip("explicit VM acceptance required")
	}
	if host != "WIN-67BE833BA6F" {
		t.Fatal("dedicated VM required")
	}
}

func TestBalanceLiveMixedTransports(t *testing.T) {
	balanceVMonly(t)
	wg, stopWG := balanceTestNative(t, 1, "wg")
	awg, stopAWG := balanceTestNative(t, 0, "awg")
	r := &Runtime{}
	r.captureQualityUplinks()
	gateway, e := newAcceptanceGateway()
	if e != nil {
		t.Fatal(e)
	}
	defer gateway.stop()
	gateway.mu.Lock()
	gateway.allowConnect = func(string) bool { return true }
	gateway.dialConnect = func(ctx context.Context, address string) (net.Conn, error) {
		if address == "10.77.0.1:19090" {
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				line, e := bufio.NewReader(b).ReadString('\n')
				if e == nil {
					io.WriteString(b, "proxy:"+line)
				}
			}()
			return a, nil
		}
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		if net.ParseIP(host) == nil {
			host, e = r.secureQualityBootstrap(ctx, host)
			if e != nil {
				return nil, e
			}
		}
		name, e := r.qualityInterface(host)
		if e != nil {
			return nil, e
		}
		dialer, e := interfaceDialer(name)
		if e != nil {
			return nil, e
		}
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}
	gateway.mu.Unlock()
	p := control.Profile{ID: "33333333-3333-4333-8333-333333333333", Name: "HTTP", Group: "manual", Protocol: 6, Source: "http://" + gateway.address}
	local, e := freePort()
	if e != nil {
		t.Fatal(e)
	}
	plan, e := protocol.CompileBalanced(false, local, nil)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	engine, e := r.startBalanceRouter(ctx, &control.Balance{Mode: "balanced", Best: 3, Interval: 15, MaxRTT: 10000, Members: []control.Profile{wg, awg, p}}, []byte(plan.Proxy), false)
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	dial, e := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", local), nil, proxy.Direct)
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		c, e := dial.(proxy.ContextDialer).DialContext(ctx, "tcp", "10.77.0.1:19090")
		if e != nil {
			t.Fatal("mixed TCP", e)
		}
		c.SetDeadline(time.Now().Add(12 * time.Second))
		io.WriteString(c, "hello\n")
		line, e := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if e != nil {
			t.Fatal("TCP reply", e)
		}
		seen[strings.SplitN(line, ":", 2)[0]] = true
	}
	if len(seen) != 3 {
		t.Fatal("not all actual transports used", seen)
	}
	t.Log("TCP distributed across actual WG, AWG and HTTP proxy")
	udpSeen := map[string]bool{}
	for i := 0; i < 4; i++ {
		packet, e := engine.(*embeddedsingbox.Engine).ListenPacketTo(ctx, "10.77.0.1:19091")
		if e != nil {
			t.Fatal(e)
		}
		packet.SetDeadline(time.Now().Add(5 * time.Second))
		_, e = packet.WriteTo([]byte("udp"), &net.UDPAddr{IP: net.ParseIP("10.77.0.1"), Port: 19091})
		if e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 128)
		n, _, e := packet.ReadFrom(b)
		packet.Close()
		if e != nil {
			t.Fatal(e)
		}
		udpSeen[strings.SplitN(string(b[:n]), ":", 2)[0]] = true
	}
	if len(udpSeen) != 2 {
		t.Fatal("UDP did not use WG and AWG", udpSeen)
	}
	if _, e = engine.(*embeddedsingbox.Engine).DialContext(ctx, "udp", "10.78.0.1:19091"); e == nil {
		t.Fatal("native AllowedIPs or HTTP UDP coverage bypassed")
	}
	stopWG()
	stopAWG()
	gateway.stop()
	failureCtx, done := context.WithTimeout(ctx, 12*time.Second)
	defer done()
	c, e := dial.(proxy.ContextDialer).DialContext(failureCtx, "tcp", "10.77.0.1:19090")
	if e == nil {
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		_, writeErr := io.WriteString(c, "fail\n")
		_, readErr := bufio.NewReader(c).ReadString('\n')
		if writeErr == nil && readErr == nil {
			t.Fatal("all-down unexpectedly passed")
		}
	}
	t.Log("all actual transports stopped: no direct fallback")
	if e = engine.Close(); e != nil {
		t.Fatal(e)
	}
	check, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", local), time.Second)
	if e == nil {
		check.Close()
		t.Fatal("pool listener leaked")
	}
}
