package embeddedawg

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

func TestMultiplePeersValidationAndUAPI(t *testing.T) {
	private, _ := testKeyPair(t)
	_, a := testKeyPair(t)
	_, b := testKeyPair(t)
	source := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=10.77.0.1/32,fd77::1/128\nDNS=10.77.0.2\n[Peer]\nPublicKey=%s\nEndpoint=127.0.0.1:42001\nAllowedIPs=0.0.0.0/0,::/0\n[Peer]\nPublicKey=%s\nEndpoint=127.0.0.1:42002\nAllowedIPs=10.77.0.3/32,fd77::3/128\n", private, a, b)
	plan, err := Parse(source, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := plan.UAPI()
	if err != nil {
		t.Fatal(err)
	}
	peers := strings.Split(string(data), "public_key=")
	if len(peers) != 3 || strings.Contains(peers[2], "allowed_ip=0.0.0.0/0") || !strings.Contains(peers[2], "allowed_ip=10.77.0.3/32") {
		t.Fatal("peer routes reassigned")
	}
	if len(plan.Endpoints()) != 2 || len(plan.Routes) != 4 {
		t.Fatal("peer endpoint/routes lost")
	}
	if plan.SetEndpoint("127.0.0.1:42003") == nil {
		t.Fatal("single-endpoint update accepted for multiple peers")
	}
	before := strings.Join(plan.Endpoints(), ",")
	calls := 0
	if plan.ResolveEndpoints(func(value string) (string, error) {
		calls++
		if calls == 2 {
			return "", fmt.Errorf("bootstrap failed")
		}
		return "127.0.0.1:42003", nil
	}) == nil || strings.Join(plan.Endpoints(), ",") != before {
		t.Fatal("partial endpoint resolution committed")
	}
	if err = plan.ResolveEndpoints(func(value string) (string, error) { return value, nil }); err != nil {
		t.Fatal(err)
	}
	overlapping := &Plan{values: map[string]string{"iprivatekey": private, "ppublickey": b}}
	if !plan.SamePeer(overlapping) {
		t.Fatal("second peer identity can roam active connection")
	}
	for name, bad := range map[string]string{
		"duplicate-key":             strings.Replace(source, b, a, 1),
		"duplicate-prefix":          strings.Replace(source, "10.77.0.3/32,fd77::3/128", "0.0.0.1/0", 1),
		"malformed-second-endpoint": strings.Replace(source, "127.0.0.1:42002", "invalid", 1),
		"second-interface":          source + "[Interface]\nPrivateKey=" + private + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(bad, 1, false); err == nil {
				t.Fatal("invalid multi-peer accepted")
			}
		})
	}
	limited := strings.Replace(source, "0.0.0.0/0,::/0", "10.77.0.2/32,fd77::2/128", 1)
	if _, err = Parse(limited, 1, false); err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(limited, 1, true); err == nil {
		t.Fatal("full device expanded peer routes implicitly")
	}
	ipv4Only := strings.Replace(source, "0.0.0.0/0,::/0", "0.0.0.0/0", 1)
	if _, err = Parse(ipv4Only, 1, true); err == nil {
		t.Fatal("missing IPv6 default accepted")
	}
}

func TestMultiplePeersTrafficAndFailureIsolation(t *testing.T) {
	for _, mode := range []string{"wg", "awg", "awg31"} {
		kind := 1
		if mode != "wg" {
			kind = 0
		}
		t.Run(mode, func(t *testing.T) {
			private := make([]string, 3)
			public := make([]string, 3)
			ports := make([]uint16, 3)
			for i := range private {
				private[i], public[i] = testKeyPair(t)
				ports[i], _ = freeUDPPorts(t)
			}
			obfuscation := ""
			if kind == 0 {
				obfuscation = "Jc=1\nJmin=1\nJmax=3\nS1=1\nS2=2\nH1=11\nH2=12\nH3=13\nH4=14\n"
			}
			if mode == "awg31" {
				obfuscation = "Jc=3\nJmin=10\nJmax=30\nS1=16\nS2=16\nS3=16\nS4=16\nH1=1\nH2=2\nH3=3\nH4=4\nHeaderProtectionKey=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\nContentPaddingAddition=0-16\nRekeyAfterTime=110-130\nRekeyTimeout=4-6\nRejectAfterTime=170-190\nKeepaliveTimeout=20-30\nMaxHandshakeAttempts=12-18\nRandomTrailers=on\nDisableCookies=off\n"
			}
			peer := func(i int) string {
				return fmt.Sprintf("[Peer]\nPublicKey=%s\nEndpoint=127.0.0.1:%d\nAllowedIPs=10.77.0.%d/32,fd77::%d/128\nPersistentKeepalive=1\n", public[i], ports[i], i+1, i+1)
			}
			transports := make([]*Transport, 3)
			for i := range transports {
				source := fmt.Sprintf("[Interface]\nPrivateKey=%s\nListenPort=%d\nAddress=10.77.0.%d/32,fd77::%d/128\nMTU=1280\n%s", private[i], ports[i], i+1, i+1, obfuscation)
				if i == 0 {
					source += peer(1) + peer(2)
				} else {
					source += peer(0)
				}
				plan, err := Parse(source, kind, false)
				if err != nil {
					t.Fatal(err)
				}
				transport, err := StartTransport(plan, conn.NewStdNetBind(), func(conn.Bind) error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				transports[i] = transport
				t.Cleanup(func() { transport.Close() })
			}
			for i := 1; i < 3; i++ {
				for _, address := range []string{fmt.Sprintf("10.77.0.%d", i+1), fmt.Sprintf("fd77::%d", i+1)} {
					udp, err := transports[i].stack.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(address), 9090))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { udp.Close() })
					go func() {
						b := make([]byte, 4096)
						for {
							n, from, e := udp.ReadFrom(b)
							if e != nil {
								return
							}
							_, _ = udp.WriteTo(b[:n], from)
						}
					}()
					tcp, err := transports[i].stack.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(address), 8080))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { tcp.Close() })
					go func() {
						for {
							c, e := tcp.Accept()
							if e != nil {
								return
							}
							go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
						}
					}()
				}
			}
			exchange := func(network, address string, want bool) {
				t.Helper()
				port := "8080"
				if network == "udp" {
					port = "9090"
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				c, err := transports[0].DialContext(ctx, network, net.JoinHostPort(address, port))
				if err != nil {
					if want {
						t.Fatal(err)
					}
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				payload := "multi-peer/" + network + "/" + address
				_, err = io.WriteString(c, payload)
				b := make([]byte, len(payload))
				if err == nil {
					_, err = io.ReadFull(c, b)
				}
				if want && (err != nil || string(b) != payload) {
					t.Fatalf("%s %s: %v", network, address, err)
				}
				if !want && err == nil {
					t.Fatal("offline peer bypassed")
				}
			}
			for _, network := range []string{"tcp", "udp"} {
				for _, address := range []string{"10.77.0.2", "10.77.0.3", "fd77::2", "fd77::3"} {
					exchange(network, address, true)
				}
			}
			if err := transports[1].Close(); err != nil {
				t.Fatal(err)
			}
			for _, network := range []string{"tcp", "udp"} {
				exchange(network, "10.77.0.2", false)
				exchange(network, "10.77.0.3", true)
				exchange(network, "fd77::3", true)
			}
			for _, address := range []string{"10.77.0.4:80", "[fd77::4]:80"} {
				if _, err := transports[0].DialContext(context.Background(), "tcp", address); err == nil {
					t.Fatal("route scope expanded")
				}
			}
			sent, received, err := transports[0].Counters()
			if err != nil || sent == 0 || received == 0 {
				t.Fatal("multi-peer statistics unavailable", err)
			}
		})
	}
}
