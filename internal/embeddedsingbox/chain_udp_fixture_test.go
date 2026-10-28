//go:build windows && amd64 && with_naive_outbound && with_purego

package embeddedsingbox

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	M "github.com/sagernet/sing/common/metadata"
)

// A gate counts encrypted datagrams and can discard either direction without
// changing the compiled client or any server's routing configuration.
type udpChainGate struct {
	online atomic.Bool
	sent   atomic.Int64
}

func newUDPChainGate(t *testing.T, port int, frontPort ...int) (int, *udpChainGate) {
	t.Helper()
	address := "127.0.0.1:0"
	if len(frontPort) > 0 {
		address = fmt.Sprintf("127.0.0.1:%d", frontPort[0])
	}
	front, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	gate := &udpChainGate{}
	gate.online.Store(true)
	var mu sync.Mutex
	sockets := map[string]*net.UDPConn{}
	t.Cleanup(func() {
		front.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, socket := range sockets {
			socket.Close()
		}
	})
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := front.ReadFrom(buffer)
			if err != nil {
				return
			}
			if !gate.online.Load() {
				continue
			}
			mu.Lock()
			socket := sockets[peer.String()]
			if socket == nil {
				socket, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
				if err == nil {
					sockets[peer.String()] = socket
					go func(socket *net.UDPConn, peer net.Addr) {
						data := make([]byte, 65535)
						for {
							n, err := socket.Read(data)
							if err != nil {
								return
							}
							if gate.online.Load() {
								_, _ = front.WriteTo(data[:n], peer)
							}
						}
					}(socket, peer)
				}
			}
			mu.Unlock()
			if err == nil {
				gate.sent.Add(1)
				_, _ = socket.Write(buffer[:n])
			}
		}
	}()
	return front.LocalAddr().(*net.UDPAddr).Port, gate
}

func TestCompiledUDPChains(t *testing.T) {
	host, _ := os.Hostname()
	if host != "WIN-67BE833BA6F" {
		t.Skip("live chain acceptance runs only on the dedicated VM")
	}
	tlsFixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := tlsFixture.TLS.Certificates[0]
	tlsFixture.Close()
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	for _, kinds := range [][]int{{5, 5}, {5, 5, 5}, {5, protocol.Trojan}, {protocol.Trojan, 5}, {5, protocol.Trojan, 5}, {protocol.Trojan, 5, protocol.Trojan}} {
		t.Run(fmt.Sprint(kinds), func(t *testing.T) {
			hops := len(kinds)
			sources := make([]string, hops)
			countsAtHop := make([]func() int64, hops)
			setOnline := make([]func(bool), hops)
			for i := range sources {
				port := freePort(t)
				password := fmt.Sprintf("chain-fixture-password-%d", i)
				in := map[string]any{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port, "method": "chacha20-ietf-poly1305", "password": password}
				if kinds[i] == protocol.Trojan {
					delete(in, "method")
					delete(in, "password")
					in["type"] = "trojan"
					in["users"] = []any{map[string]any{"password": password}}
					in["tls"] = map[string]any{"enabled": true, "certificate": []string{certPEM}, "key": []string{keyPEM}}
				}
				startJSON(t, map[string]any{"inbounds": []any{in}, "outbounds": []any{map[string]any{"type": "direct"}}})
				tcpGate := newMuxGate(t, port)
				countsAtHop[i] = tcpGate.accepted.Load
				setOnline[i] = tcpGate.setOnline
				front := tcpGate.listener.Addr().(*net.TCPAddr).Port
				if kinds[i] == protocol.Trojan {
					sources[i] = fmt.Sprintf("trojan://%s@127.0.0.1:%d?sni=example.com", password, front)
				} else {
					_, udpGate := newUDPChainGate(t, port, front)
					countsAtHop[i] = func() int64 { return tcpGate.accepted.Load() + udpGate.sent.Load() }
					setOnline[i] = func(value bool) { tcpGate.setOnline(value); udpGate.online.Store(value) }
					sources[i] = fmt.Sprintf("ss://chacha20-ietf-poly1305:%s@127.0.0.1:%d", password, front)
				}
			}
			targets := []protocol.PolicyTarget{}
			via := "@primary"
			for i := 1; i < hops; i++ {
				name := fmt.Sprintf("hop%d", i)
				targets = append([]protocol.PolicyTarget{{Name: name, Protocol: kinds[i], Source: sources[i], Via: via}}, targets...)
				via = name
			}
			localPort := freePort(t)
			plan, err := protocol.CompileWithNetwork(sources[0], kinds[0], true, localPort, freePort(t), "unused", nil, &protocol.NetworkOptions{Targets: targets, Rules: []protocol.NetworkRule{{Kind: "network", Value: "udp", Action: "proxy", Outbound: via}}})
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]any
			if err = json.Unmarshal([]byte(plan.Proxy), &config); err != nil {
				t.Fatal(err)
			}
			// Retain the compiled proxy ingress and UDP policy; only OS TUN is removed.
			inbounds := []any{}
			for _, in := range config["inbounds"].([]any) {
				if in.(map[string]any)["type"] != "tun" {
					inbounds = append(inbounds, in)
				}
			}
			config["inbounds"] = inbounds
			for _, out := range config["outbounds"].([]any) {
				o := out.(map[string]any)
				if o["type"] == "trojan" {
					o["tls"].(map[string]any)["certificate"] = []string{certPEM}
				}
			}
			startJSON(t, config)
			ingress := startJSON(t, map[string]any{"outbounds": []any{map[string]any{"type": "socks", "tag": "ingress", "server": "127.0.0.1", "server_port": localPort, "version": "5"}}})
			out, ok := ingress.instance.Outbound().Outbound("ingress")
			if !ok {
				t.Fatal("compiled exit missing")
			}
			for _, family := range []string{"udp4", "udp6"} {
				t.Run(family, func(t *testing.T) {
					address := "127.0.0.1:0"
					if family == "udp6" {
						address = "[::1]:0"
					}
					echo, err := net.ListenPacket(family, address)
					if err != nil {
						t.Fatal(err)
					}
					defer echo.Close()
					var received atomic.Int64
					go func() {
						b := make([]byte, 65535)
						for {
							n, p, e := echo.ReadFrom(b)
							if e != nil {
								return
							}
							received.Add(1)
							_, _ = echo.WriteTo(b[:n], p)
						}
					}()
					destination := M.ParseSocksaddr(echo.LocalAddr().String())
					sequence := 0
					exchange := func(want bool) {
						t.Helper()
						sequence++
						before := received.Load()
						counts := make([]int64, hops)
						for i, count := range countsAtHop {
							counts[i] = count()
						}
						ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
						defer cancel()
						packet, err := out.ListenPacket(ctx, destination)
						if err != nil {
							if want {
								t.Fatal(err)
							}
							return
						}
						defer packet.Close()
						_ = packet.SetDeadline(time.Now().Add(800 * time.Millisecond))
						payload := bytes.Repeat([]byte(fmt.Sprintf("%s/%d/", family, sequence)), 512)
						_, err = packet.WriteTo(payload, destination.UDPAddr())
						b := make([]byte, 65535)
						n := 0
						if err == nil {
							n, _, err = packet.ReadFrom(b)
						}
						if want {
							if err != nil || !bytes.Equal(payload, b[:n]) {
								t.Fatalf("UDP round trip: %v", err)
							}
							for i, count := range countsAtHop {
								if count() <= counts[i] {
									t.Fatalf("hop %d bypassed", i)
								}
							}
						} else if err == nil || received.Load() != before {
							t.Fatal("failed hop bypassed or payload reached destination")
						}
					}
					exchange(true)
					for i, online := range setOnline {
						online(false)
						exchange(false)
						online(true)
						exchange(true)
						t.Logf("hop %d: outage blocked; restored UDP delivery", i)
					}
				})
			}
		})
	}
}
