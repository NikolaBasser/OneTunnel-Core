package embeddedxray

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var portMu sync.Mutex
var usedPorts = map[int]bool{}

func TestUDPNoiseBeforeHysteriaHandshake(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	local := freePort(t)
	options := &protocol.TransportOptions{Noise: true, FragmentLength: "64", FragmentInterval: "0", NoiseLength: "53", NoiseDelay: "0", MuxConcurrency: 4}
	plan, err := protocol.CompileWithOptions("hy2://fixture@"+server.LocalAddr().String()+"?sni=localhost", 4, false, freePort(t), local, "", options)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := Start([]byte(plan.Xray))
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", local), nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, _ := dialer.Dial("tcp", "127.0.0.1:12345")
		if c != nil {
			c.Close()
		}
	}()
	server.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 65535)
	for i := 0; i < 8; i++ {
		n, _, e := server.ReadFrom(buffer)
		if e != nil {
			t.Fatal("configured UDP noise never reached the socket", e)
		}
		if n == 53 {
			return
		}
	}
	t.Fatal("configured UDP noise length not observed")
}

func freePort(t *testing.T) int {
	t.Helper()
	portMu.Lock()
	defer portMu.Unlock()
	for attempt := 0; attempt < 100; attempt++ {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		p := l.Addr().(*net.TCPAddr).Port
		u, e := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		l.Close()
		if e != nil {
			continue
		}
		u.Close()
		if usedPorts[p] {
			continue
		}
		usedPorts[p] = true
		return p
	}
	t.Fatal("no unused fixture port")
	return 0
}

func TestVlessLifecycle(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "embedded-ok") }))
	defer target.Close()
	for _, transport := range []string{"tcp", "ws", "grpc", "httpupgrade", "xhttp", "kcp"} {
		t.Run(transport, func(t *testing.T) {
			serverPort, clientPort := freePort(t), freePort(t)
			id := "6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a"
			serverConfig := fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[{"id":%q}],"decryption":"none"},"streamSettings":{"network":%q}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8","::1/128"]}]}}]}`, serverPort, id, transport)
			server, e := Start([]byte(serverConfig))
			if e != nil {
				t.Fatal(e)
			}
			defer server.Close()
			source := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=%s", id, serverPort, transport)
			plan, e := protocol.CompileWithOptions(source, 2, false, freePort(t), clientPort, "unused", nil)
			if e != nil {
				t.Fatal(e)
			}
			plan.Xray = strings.ReplaceAll(plan.Xray, `"loglevel":"none"`, `"loglevel":"none"`)
			client, e := Start([]byte(plan.Xray))
			if e != nil {
				t.Fatal(e)
			}
			address := net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort))
			dialer, e := proxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 3 * time.Second})
			if e != nil {
				t.Fatal(e)
			}
			tr := &http.Transport{Dial: dialer.Dial}
			httpClient := &http.Client{Transport: tr, Timeout: 8 * time.Second}
			response, e := httpClient.Get(target.URL)
			if e != nil {
				client.Close()
				t.Fatal(e)
			}
			body, e := io.ReadAll(response.Body)
			response.Body.Close()
			tr.CloseIdleConnections()
			if e != nil || string(body) != "embedded-ok" {
				t.Fatal("unexpected local traffic", e)
			}
			if e = client.Close(); e != nil {
				t.Fatal(e)
			}
			if e = client.Close(); e != nil {
				t.Fatal(e)
			}
			if transport != "kcp" {
				l, e := net.Listen("tcp4", address)
				if e != nil {
					t.Fatal("listener not released", e)
				}
				l.Close()
			}
		})
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, s := range []string{`invalid`, `{"outbounds":[{"protocol":"unsupported"}]}`} {
		if e, err := Start([]byte(s)); err == nil {
			e.Close()
			t.Fatal("accepted invalid config")
		}
	}
}

func TestOccupiedPortRollback(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	data := []byte(fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"socks"}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8","::1/128"]}]}}]}`, listener.Addr().(*net.TCPAddr).Port))
	if engine, err := Start(data); err == nil {
		engine.Close()
		t.Fatal("accepted occupied port")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	engine, err := Start(data)
	if err != nil {
		t.Fatal("failed restart after rollback", err)
	}
	defer engine.Close()
}

func TestTLSFragmentMuxTraffic(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "tls-mux-ok") }))
	defer target.Close()
	tlsFixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsFixture.Close()
	cert := tlsFixture.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	pin := sha256.Sum256(cert.Certificate[0])
	for _, mode := range []string{"tls", "fragment", "mux", "fragment-mux"} {
		t.Run(mode, func(t *testing.T) {
			serverPort, clientPort := freePort(t), freePort(t)
			id := "6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a"
			config := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": serverPort, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": id}}, "decryption": "none"}, "streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificate": strings.Split(strings.TrimSpace(certPEM), "\n"), "key": strings.Split(strings.TrimSpace(keyPEM), "\n")}}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8", "::1/128"}}}}}}}
			data, _ := json.Marshal(config)
			server, err := Start(data)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			source := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=tls&sni=example.com&pcs=%X", id, serverPort, pin[:])
			options := &protocol.TransportOptions{Fragment: strings.Contains(mode, "fragment"), Mux: strings.Contains(mode, "mux"), FragmentLength: "64", FragmentInterval: "0", NoiseLength: "64", NoiseDelay: "0", MuxConcurrency: 4}
			plan, err := protocol.CompileWithOptions(source, 2, false, freePort(t), clientPort, "unused", options)
			if err != nil {
				t.Fatal(err)
			}
			client, err := Start([]byte(plan.Xray))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), nil, &net.Dialer{Timeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			tr := &http.Transport{Dial: dialer.Dial, DisableKeepAlives: true}
			defer tr.CloseIdleConnections()
			for request := 0; request < 3; request++ {
				response, err := (&http.Client{Transport: tr, Timeout: 6 * time.Second}).Get(target.URL)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(body) != "tls-mux-ok" {
					t.Fatal("TLS/MUX payload failed", err)
				}
			}
		})
	}
}
