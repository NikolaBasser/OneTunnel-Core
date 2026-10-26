//go:build windows && amd64 && with_naive_outbound && with_purego

package embeddedsingbox

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedxray"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

var portMu sync.Mutex
var usedPorts = map[int]bool{}

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
		u, e := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", p))
		l.Close()
		if e != nil {
			continue
		}
		u.Close()
		if usedPorts[p] {
			continue
		}
		usedPorts[p] = true
		// Reservation lives as long as this test, not the entire -count process.
		// Engine cleanup is registered later and therefore closes listeners first.
		t.Cleanup(func() {
			portMu.Lock()
			delete(usedPorts, p)
			portMu.Unlock()
		})
		return p
	}
	t.Fatal("no unused fixture port")
	return 0
}

func TestFixturePortReservationReleased(t *testing.T) {
	var port int
	t.Run("reservation", func(t *testing.T) {
		port = freePort(t)
		portMu.Lock()
		reserved := usedPorts[port]
		portMu.Unlock()
		if port <= 0 || !reserved {
			t.Fatal("fixture port was not reserved")
		}
	})
	portMu.Lock()
	reserved := usedPorts[port]
	portMu.Unlock()
	if reserved {
		t.Fatal("completed fixture retained its port reservation")
	}
}
func startJSON(t *testing.T, v any) *Engine {
	t.Helper()
	data, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	engine, e := Start(data, false)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { engine.Close() })
	return engine
}

func TestCompiledProxyTraffic(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "sing-embedded-ok") }))
	defer target.Close()
	tlsFixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsFixture.Close()
	cert := tlsFixture.TLS.Certificates[0]
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	key, e := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	for _, kind := range []string{"socks", "socks-auth", "ss", "ss2022", "hy2", "hy2-salamander"} {
		t.Run(kind, func(t *testing.T) {
			serverPort, clientPort := freePort(t), freePort(t)
			in := map[string]any{"listen": "127.0.0.1", "listen_port": serverPort, "type": "socks"}
			source := fmt.Sprintf("socks5://127.0.0.1:%d", serverPort)
			protocolID := 3
			var clock map[string]any
			switch kind {
			case "socks-auth":
				in["users"] = []any{map[string]any{"username": "fixture", "password": "fixture-password"}}
				source = fmt.Sprintf("socks5://fixture:fixture-password@127.0.0.1:%d", serverPort)
			case "ss":
				in["type"] = "shadowsocks"
				in["method"] = "aes-128-gcm"
				in["password"] = "fixture-password"
				source = fmt.Sprintf("ss://%s@127.0.0.1:%d", base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:fixture-password")), serverPort)
				protocolID = 5
			case "ss2022":
				password := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
				in["type"] = "shadowsocks"
				in["method"] = "2022-blake3-aes-128-gcm"
				in["password"] = password
				source = fmt.Sprintf("ss://%s@127.0.0.1:%d", base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:"+password)), serverPort)
				protocolID = 5
				clock = map[string]any{"enabled": true, "server": "127.0.0.1", "server_port": fakeNTP(t, 2*time.Minute, true)}
			case "hy2", "hy2-salamander":
				in["type"] = "hysteria2"
				in["users"] = []any{map[string]any{"password": "fixture-password"}}
				in["tls"] = map[string]any{"enabled": true, "certificate": []string{certPEM}, "key": []string{keyPEM}}
				source = fmt.Sprintf("hy2://fixture-password@127.0.0.1:%d?sni=example.com", serverPort)
				protocolID = 4
				if kind == "hy2-salamander" {
					in["obfs"] = map[string]any{"type": "salamander", "password": "fixture-obfs"}
					source += "&obfs=salamander&obfs-password=fixture-obfs"
				}
			}
			serverConfig := map[string]any{"inbounds": []any{in}, "outbounds": []any{map[string]any{"type": "direct"}}}
			if clock != nil {
				serverConfig["ntp"] = clock
			}
			startJSON(t, serverConfig)
			plan, e := protocol.CompileWithOptions(source, protocolID, false, clientPort, freePort(t), "unused", nil)
			if e != nil {
				t.Fatal(e)
			}
			var configuration map[string]any
			if e = json.Unmarshal([]byte(plan.Proxy), &configuration); e != nil {
				t.Fatal(e)
			}
			if protocolID == 4 {
				// Production currently routes Hysteria2 through Xray. Exercise the
				// embedded sing-box QUIC implementation independently as well.
				out := map[string]any{"type": "hysteria2", "tag": "proxy", "server": "127.0.0.1", "server_port": serverPort, "password": "fixture-password", "tls": map[string]any{"enabled": true, "server_name": "example.com", "certificate": []string{certPEM}}}
				if kind == "hy2-salamander" {
					out["obfs"] = map[string]any{"type": "salamander", "password": "fixture-obfs"}
				}
				configuration["outbounds"] = []any{out}
			}
			if clock != nil {
				configuration["ntp"] = clock
			}
			client := startJSON(t, configuration)
			proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", clientPort))
			tr := &http.Transport{Proxy: http.ProxyURL(proxy)}
			defer tr.CloseIdleConnections()
			httpClient := &http.Client{Transport: tr, Timeout: 8 * time.Second}
			response, e := httpClient.Get(target.URL)
			if e != nil {
				t.Fatal(e)
			}
			body, e := io.ReadAll(response.Body)
			response.Body.Close()
			if e != nil || string(body) != "sing-embedded-ok" {
				t.Fatal("local traffic failed", e)
			}
			tr.CloseIdleConnections()
			if e = client.Close(); e != nil {
				t.Fatal(e)
			}
			if e = client.Close(); e != nil {
				t.Fatal(e)
			}
			l, e := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", clientPort))
			if e != nil {
				t.Fatal("listener not released", e)
			}
			l.Close()
		})
	}
}

func TestRejectPrivilegedFeatures(t *testing.T) {
	inputs := []string{`{"ntp":{"enabled":true}}`, `{"endpoints":[{"type":"wireguard"}]}`, `invalid`}
	if !tunSupported() {
		inputs = append(inputs, `{"inbounds":[{"type":"tun","auto_route":true}]}`)
	}
	for _, data := range inputs {
		if instance, e := Start([]byte(data), false); e == nil {
			instance.Close()
			t.Fatal("unsafe configuration accepted")
		}
	}
}

func TestCompiledHysteriaBridge(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer fixture.Close()
	cert := fixture.TLS.Certificates[0]
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hy2-bridge-ok") }))
	defer target.Close()
	for _, obfs := range []bool{false, true} {
		t.Run(fmt.Sprintf("salamander-%t", obfs), func(t *testing.T) {
			serverPort, bridgePort, clientPort := freePort(t), freePort(t), freePort(t)
			in := map[string]any{"type": "hysteria2", "listen": "127.0.0.1", "listen_port": serverPort, "users": []any{map[string]any{"password": "fixture-password"}}, "tls": map[string]any{"enabled": true, "certificate": []string{certPEM}, "key": []string{keyPEM}}}
			source := fmt.Sprintf("hy2://fixture-password@127.0.0.1:%d?sni=example.com", serverPort)
			if obfs {
				in["obfs"] = map[string]any{"type": "salamander", "password": "fixture-obfs"}
				source += "&obfs=salamander&obfs-password=fixture-obfs"
			}
			startJSON(t, map[string]any{"inbounds": []any{in}, "outbounds": []any{map[string]any{"type": "direct"}}})
			plan, err := protocol.CompileWithOptions(source, 4, false, clientPort, bridgePort, "unused", nil)
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]any
			json.Unmarshal([]byte(plan.Xray), &config)
			out := config["outbounds"].([]any)[0].(map[string]any)
			tls := out["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
			pin := sha256.Sum256(cert.Certificate[0])
			tls["pinnedPeerCertSha256"] = fmt.Sprintf("%X", pin[:])
			data, _ := json.Marshal(config)
			bridge, err := embeddedxray.Start(data)
			if err != nil {
				t.Fatal(err)
			}
			defer bridge.Close()
			frontend, err := Start([]byte(plan.Proxy), false)
			if err != nil {
				t.Fatal(err)
			}
			defer frontend.Close()
			proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", clientPort))
			tr := &http.Transport{Proxy: http.ProxyURL(proxy)}
			defer tr.CloseIdleConnections()
			response, err := (&http.Client{Transport: tr, Timeout: 8 * time.Second}).Get(target.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != "hy2-bridge-ok" {
				t.Fatalf("compiled bridge traffic failed: status=%d body=%q error=%v", response.StatusCode, string(body), err)
			}
		})
	}
}
