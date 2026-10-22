//go:build windows && embeddedawg

package platform

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"net"
	"onetunnel/core/internal/control"
	"onetunnel/core/internal/embeddedawg"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEmbeddedAWGIdentity(t *testing.T) {
	r := &Runtime{directory: t.TempDir()}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []int{0, 1} {
		paths, err := r.transportProcesses(kind, true, false)
		if err != nil || len(paths) != 1 || paths[0] != exe {
			t.Fatal("AWG/WG must share embedded service identity")
		}
	}
}
func awgFixtureKey(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}
func awgFixtureConfig(private, public, address, allowed, extra string, port int) string {
	return fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s/32\nListenPort=0\n%s\n[Peer]\nPublicKey=%s\nAllowedIPs=%s/32\nEndpoint=127.0.0.1:%d\n", private, address, extra, public, allowed, port)
}
func echoReply(packet []byte) []byte {
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return nil
	}
	header := int(packet[0]&15) * 4
	if len(packet) < header+8 || packet[header] != 8 {
		return nil
	}
	reply := append([]byte(nil), packet...)
	copy(reply[12:16], packet[16:20])
	copy(reply[16:20], packet[12:16])
	reply[header] = 0
	reply[header+2] = 0
	reply[header+3] = 0
	var sum uint32
	for i := header; i < len(reply); i += 2 {
		sum += uint32(reply[i]) << 8
		if i+1 < len(reply) {
			sum += uint32(reply[i+1])
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(reply[header+2:header+4], ^uint16(sum))
	return reply
}

// No default routes or DNS changes: OS ping traverses one synthetic /32 route,
// the embedded Windows AWG adapter and a loopback-only encrypted UDP peer.
func testEmbeddedAWGSCM(t *testing.T) {
	system, err := svc.IsWindowsService()
	if err != nil || !system {
		t.Skip("isolated SYSTEM service required")
	}
	for _, kind := range []int{1, 0} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			before4, err4 := routeInterface("1.1.1.1")
			before6, err6 := routeInterface("2606:4700:4700::1111")
			extra := ""
			if kind == 0 {
				extra = "Jc=2\nJmin=32\nJmax=64\nS1=15\nS2=18\nS3=20\nS4=25\nH1=123456-123500\nH2=67543-67550\nH3=123123-123200\nH4=32345-32350\nI1=<b 0x1234><r 5>"
			}
			clientKey, clientPublic := awgFixtureKey(t)
			serverKey, serverPublic := awgFixtureKey(t)
			plan, err := embeddedawg.Parse(awgFixtureConfig(serverKey, clientPublic, "198.18.252.2", "198.18.251.1", extra, 9), kind, false)
			if err != nil {
				t.Fatal(err)
			}
			adapter := tuntest.NewChannelTUN()
			server, err := embeddedawg.Start(plan, adapter.TUN(), conn.NewDefaultBind())
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			status, err := server.Status()
			if err != nil || status.ListenPort == 0 {
				t.Fatal("server port unavailable")
			}
			root := t.TempDir()
			if err = os.Mkdir(filepath.Join(root, "runtime"), 0700); err != nil {
				t.Fatal(err)
			}
			r := &Runtime{root: root, directory: t.TempDir(), lock: trafficLock{root: root}, update: func(control.State) {}}
			defer func() {
				if err := r.disconnect(ctx); err != nil {
					t.Error(err)
				}
			}()
			source := awgFixtureConfig(clientKey, serverPublic, "198.18.251.1", "198.18.252.2", extra, int(status.ListenPort))
			guid, err := windows.GenerateGUID()
			if err != nil {
				t.Fatal(err)
			}
			profile := &control.Profile{ID: strings.ToLower(strings.Trim(guid.String(), "{}")), Name: "synthetic", Protocol: kind, Source: source}
			if err = r.start(ctx, control.Request{Version: 1, Command: "start", Profile: profile}); err != nil {
				t.Fatal(err)
			}
			if r.embeddedNative == nil || !r.session.EmbeddedNative || r.session.Pid != 0 || r.lock.needed() {
				t.Fatal("native engine not embedded")
			}
			for retry := 0; retry < 30; retry++ {
				route, _ := routeInterface("198.18.252.2")
				if route == r.session.TunnelName {
					break
				}
				if err := delay(ctx, 100*time.Millisecond); err != nil {
					t.Fatal(err)
				}
			}
			workerDone := make(chan struct{})
			defer close(workerDone)
			go func() {
				for {
					select {
					case <-workerDone:
						return
					case packet := <-adapter.Inbound:
						reply := echoReply(packet)
						if reply == nil {
							continue
						}
						select {
						case adapter.Outbound <- reply:
						case <-workerDone:
							return
						}
					}
				}
			}()
			ping := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE"), "-n", "1", "-w", "4000", "198.18.252.2")
			if output, pingErr := ping.CombinedOutput(); pingErr != nil {
				status, _ := server.Status()
				route, routeErr := routeInterface("198.18.252.2")
				t.Fatalf("Windows ping failed: %v; routeMatches=%t route=%q routeError=%v; handshake=%t rx=%d tx=%d; %s", pingErr, route == r.session.TunnelName, route, routeErr, status.HandshakeUnix != 0, status.Received, status.Transmitted, output)
			}
			status, err = server.Status()
			if err != nil || status.HandshakeUnix == 0 || status.Received == 0 || status.Transmitted == 0 {
				t.Fatal("encrypted packet counters missing")
			}
			name := r.session.TunnelName
			if err = r.disconnect(ctx); err != nil {
				t.Fatal(err)
			}
			after4, afterErr4 := routeInterface("1.1.1.1")
			after6, afterErr6 := routeInterface("2606:4700:4700::1111")
			if before4 != after4 || before6 != after6 || (err4 == nil) != (afterErr4 == nil) || (err6 == nil) != (afterErr6 == nil) {
				t.Fatal("default routes changed")
			}
			adapters, err := net.Interfaces()
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range adapters {
				if a.Name == name {
					t.Fatal("AWG adapter not removed")
				}
			}
			if r.session != nil || r.recovery() || r.embeddedNative != nil {
				t.Fatal("embedded AWG cleanup incomplete")
			}
		})
	}
}
