//go:build windows && amd64 && with_naive_outbound && with_purego

package embeddedsingbox

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	M "github.com/sagernet/sing/common/metadata"
)

type muxGate struct {
	listener net.Listener
	accepted atomic.Int64
	mu       sync.Mutex
	online   bool
	flows    map[net.Conn]bool
}

func (g *muxGate) setOnline(value bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.online = value
	if !value {
		for c := range g.flows {
			c.Close()
		}
	}
}
func newMuxGate(t *testing.T, backend int) *muxGate {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &muxGate{listener: listener, online: true, flows: map[net.Conn]bool{}}
	t.Cleanup(func() { listener.Close(); g.setOnline(false) })
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				g.mu.Lock()
				if !g.online {
					g.mu.Unlock()
					return
				}
				g.accepted.Add(1)
				g.flows[c] = true
				g.mu.Unlock()
				defer func() { g.mu.Lock(); delete(g.flows, c); g.mu.Unlock() }()
				up, e := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", backend))
				if e != nil {
					return
				}
				defer up.Close()
				g.mu.Lock()
				if !g.online {
					g.mu.Unlock()
					return
				}
				g.flows[up] = true
				g.mu.Unlock()
				defer func() { g.mu.Lock(); delete(g.flows, up); g.mu.Unlock() }()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(up, c); up.Close(); close(done) }()
				_, _ = io.Copy(c, up)
				c.Close()
				<-done
			}()
		}
	}()
	return g
}

func TestSingMultiplexSharesStreamsUDPAndRecovers(t *testing.T) {
	tlsFixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := tlsFixture.TLS.Certificates[0]
	tlsFixture.Close()
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	for _, kind := range []int{5, protocol.Trojan} {
		for _, mode := range []string{"h2mux", "smux", "yamux"} {
			for _, padding := range []bool{false, true} {
				for _, connections := range []int{0, 1} {
					t.Run(fmt.Sprintf("%d-%s-padding-%v-pool-%d", kind, mode, padding, connections), func(t *testing.T) {
						var delivered atomic.Int64
						target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							delivered.Add(1)
							time.Sleep(20 * time.Millisecond)
							_, _ = io.WriteString(w, "mux:"+r.URL.Path)
						}))
						t.Cleanup(target.Close)
						backend := freePort(t)
						in := map[string]any{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": backend, "method": "chacha20-ietf-poly1305", "password": "mux-fixture", "multiplex": map[string]any{"enabled": true, "padding": padding}}
						if kind == protocol.Trojan {
							delete(in, "method")
							delete(in, "password")
							in["type"] = "trojan"
							in["users"] = []any{map[string]any{"password": "mux-fixture"}}
							in["tls"] = map[string]any{"enabled": true, "certificate": []string{certPEM}, "key": []string{keyPEM}}
						}
						startJSON(t, map[string]any{"inbounds": []any{in}, "outbounds": []any{map[string]any{"type": "direct"}}})
						gate := newMuxGate(t, backend)
						source := fmt.Sprintf("ss://chacha20-ietf-poly1305:mux-fixture@%s", gate.listener.Addr())
						if kind == protocol.Trojan {
							source = fmt.Sprintf("trojan://mux-fixture@%s?sni=example.com", gate.listener.Addr())
						}
						local := freePort(t)
						options := &protocol.TransportOptions{Mux: true, MuxProtocol: mode, MuxConcurrency: 16, MuxMaxConnections: connections, MuxPadding: padding, FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20"}
						plan, e := protocol.CompileWithOptions(source, kind, false, local, freePort(t), "unused", options)
						if e != nil {
							t.Fatal(e)
						}
						var config map[string]any
						_ = json.Unmarshal([]byte(plan.Proxy), &config)
						if kind == protocol.Trojan {
							config["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["certificate"] = []string{certPEM}
						}
						engine := startJSON(t, config)
						proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", local))
						transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true, MaxConnsPerHost: 16}
						defer transport.CloseIdleConnections()
						client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
						get := func(path string) error {
							r, e := client.Get(target.URL + path)
							if e != nil {
								return e
							}
							defer r.Body.Close()
							b, e := io.ReadAll(r.Body)
							if e != nil {
								return e
							}
							if string(b) != "mux:"+path {
								return fmt.Errorf("payload mismatch: %s", b)
							}
							return nil
						}
						start := make(chan struct{})
						results := make(chan error, 8)
						for i := 0; i < 8; i++ {
							go func() { <-start; results <- get(fmt.Sprintf("/stream-%d", i)) }()
						}
						close(start)
						for i := 0; i < 8; i++ {
							if e := <-results; e != nil {
								t.Fatal(e)
							}
						}
						if gate.accepted.Load() != 1 {
							t.Fatal("streams not multiplexed", gate.accepted.Load())
						}
						echo, e := net.ListenPacket("udp4", "127.0.0.1:0")
						if e != nil {
							t.Fatal(e)
						}
						defer echo.Close()
						go func() {
							b := make([]byte, 8192)
							n, from, e := echo.ReadFrom(b)
							if e == nil {
								_, _ = echo.WriteTo(b[:n], from)
							}
						}()
						out, _ := engine.instance.Outbound().Outbound("proxy")
						destination := M.ParseSocksaddr(echo.LocalAddr().String())
						ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
						defer cancel()
						packet, e := out.ListenPacket(ctx, destination)
						if e != nil {
							t.Fatal(e)
						}
						defer packet.Close()
						_ = packet.SetDeadline(time.Now().Add(2 * time.Second))
						_, _ = packet.WriteTo([]byte("mux-udp"), destination.UDPAddr())
						b := make([]byte, 128)
						n, _, e := packet.ReadFrom(b)
						if e != nil || string(b[:n]) != "mux-udp" {
							t.Fatal("UDP mux failed", e)
						}
						if gate.accepted.Load() != 1 {
							t.Fatal("UDP opened an independent bypass connection")
						}
						before := delivered.Load()
						gate.setOnline(false)
						if get("/offline") == nil || delivered.Load() != before {
							t.Fatal("mux outage bypassed")
						}
						gate.setOnline(true)
						var restored error
						for i := 0; i < 3; i++ {
							restored = get("/restored")
							if restored == nil {
								break
							}
							time.Sleep(100 * time.Millisecond)
						}
						if restored != nil {
							t.Fatal("mux did not recover", restored)
						}
						if gate.accepted.Load() < 2 {
							t.Fatal("no replacement mux session")
						}
					})
				}
			}
		}
	}
}
