package embeddedsingbox

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedawg"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/curve25519"
)

func nativeTestKeyPair(t *testing.T) (string, string) {
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

func nativeTestUDPPorts(t *testing.T) (uint16, uint16) {
	t.Helper()
	first, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.ListenPacket("udp4", "127.0.0.1:0")
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

func nativeTestPair(t *testing.T) (*embeddedawg.Transport, *embeddedawg.Transport) {
	t.Helper()
	aPrivate, aPublic := nativeTestKeyPair(t)
	bPrivate, bPublic := nativeTestKeyPair(t)
	aPort, bPort := nativeTestUDPPorts(t)
	profile := func(private, peer, endpoint, address, local string, listenPort uint16) *embeddedawg.Plan {
		source := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = 10.77.0.1\nListenPort = %d\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s/32\nPersistentKeepalive = 1\n", private, local, listenPort, peer, endpoint, address)
		plan, err := embeddedawg.Parse(source, 1, false)
		if err != nil {
			t.Fatalf("parse synthetic native peer: %v", err)
		}
		plan.Routes = []netip.Prefix{netip.MustParsePrefix(address + "/32")}
		if err = plan.SetEndpoint(endpoint); err != nil {
			t.Fatal(err)
		}
		return plan
	}
	start := func(plan *embeddedawg.Plan) *embeddedawg.Transport {
		transport, err := embeddedawg.StartTransport(plan, conn.NewStdNetBind(), func(conn.Bind) error { return nil })
		if err != nil {
			t.Fatalf("start synthetic native peer: %v", err)
		}
		t.Cleanup(func() { _ = transport.Close() })
		return transport
	}
	a := profile(aPrivate, bPublic, net.JoinHostPort("127.0.0.1", fmt.Sprint(bPort)), "10.77.0.2", "10.77.0.1", aPort)
	b := profile(bPrivate, aPublic, net.JoinHostPort("127.0.0.1", fmt.Sprint(aPort)), "10.77.0.1", "10.77.0.2", bPort)
	return start(a), start(b)
}

func TestNativeOutboundUDPUsesEphemeralLocalAndPreservesRemote(t *testing.T) {
	clientTransport, peerTransport := nativeTestPair(t)
	peer, err := peerTransport.ListenPacket(context.Background(), "udp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	go func() {
		buf := make([]byte, 128)
		for {
			n, from, readErr := peer.ReadFrom(buf)
			if readErr != nil {
				return
			}
			if _, writeErr := peer.WriteTo(buf[:n], from); writeErr != nil {
				return
			}
		}
	}()

	out := &nativeLiteralDialer{transport: clientTransport}
	target := M.ParseSocksaddr(peer.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	packet, err := out.ListenPacket(ctx, target)
	if err != nil {
		t.Fatalf("open native outbound UDP socket: %v", err)
	}
	defer packet.Close()
	if _, err = packet.WriteTo([]byte("packet-loopback"), target.UDPAddr()); err != nil {
		t.Fatalf("write native outbound packet: %v", err)
	}
	_ = packet.SetDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, 128)
	n, from, err := packet.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "packet-loopback" || from == nil {
		up, down, counterErr := clientTransport.Counters()
		peerUp, peerDown, peerCounterErr := peerTransport.Counters()
		t.Fatalf("native packet round trip: payload=%q from=%v err=%v; client=%d/%d (%v), peer=%d/%d (%v); target=%s local=%s", buf[:n], from, err, up, down, counterErr, peerUp, peerDown, peerCounterErr, target, packet.LocalAddr())
	}

	connected, err := out.DialContext(ctx, N.NetworkUDP, target)
	if err != nil {
		t.Fatalf("dial native connected UDP: %v", err)
	}
	defer connected.Close()
	if _, err = connected.Write([]byte("connected-loopback")); err != nil {
		t.Fatal(err)
	}
	_ = connected.SetDeadline(time.Now().Add(4 * time.Second))
	n, err = connected.Read(buf)
	if err != nil || string(buf[:n]) != "connected-loopback" {
		t.Fatalf("native connected UDP round trip: payload=%q err=%v", buf[:n], err)
	}
}
