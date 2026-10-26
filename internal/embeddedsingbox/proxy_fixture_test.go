//go:build windows && amd64 && with_naive_outbound && with_purego

package embeddedsingbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"github.com/sagernet/sing-box/adapter"
	T "github.com/sagernet/sing-box/transport/trojan"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The upstream test server reads its 56-byte authentication prefix once.
// HTTPUpgrade buffering is a stream, so collect that prefix before injecting it.
type fixtureAuthConn struct {
	net.Conn
	reader io.Reader
	first  bool
}

func (c *fixtureAuthConn) Read(p []byte) (int, error) {
	if !c.first && len(p) == T.KeyLength {
		c.first = true
		return io.ReadFull(c.reader, p)
	}
	return c.reader.Read(p)
}

type fixtureSegmentReader struct{ io.Reader }

func (r fixtureSegmentReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func TestTrojanFixtureFragmentedAuthentication(t *testing.T) {
	service := T.NewService[int](nil, nil, nil)
	if err := service.UpdateUsers([]int{0}, []string{"fixture-password"}); err != nil {
		t.Fatal(err)
	}
	key := T.Key("fixture-password")
	// Unknown command follows a valid authentication, avoiding any real routing.
	data := append(append([]byte{}, key[:]...), '\r', '\n', 0)
	broken := &fixtureAuthConn{reader: fixtureSegmentReader{bytes.NewReader(data)}, first: true}
	if err := service.NewConnection(context.Background(), broken, M.Socksaddr{}, nil); err == nil || !strings.Contains(err.Error(), "bad request size") {
		t.Fatalf("upstream partial-read regression not reproduced: %v", err)
	}
	fixed := &fixtureAuthConn{reader: fixtureSegmentReader{bytes.NewReader(data)}}
	if err := service.NewConnection(context.Background(), fixed, M.Socksaddr{}, nil); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("complete authentication prefix not preserved: %v", err)
	}
}

func startUpgradeFixture(t *testing.T, in map[string]any, port int, certificate tls.Certificate) {
	t.Helper()
	delete(in, "transport")
	delete(in, "tls")
	in["tag"] = "fixture"
	in["listen_port"] = 0
	engine := startJSON(t, map[string]any{"inbounds": []any{in}, "outbounds": []any{map[string]any{"type": "direct"}}})
	item, ok := engine.instance.Inbound().Get("fixture")
	if !ok {
		t.Fatal("missing fixture inbound")
	}
	handler, ok := item.(adapter.TCPInjectableInbound)
	if !ok {
		t.Fatal("fixture inbound cannot inject streams")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/fixture" || !strings.EqualFold(r.Header.Get("Connection"), "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.Header.Get("Sec-WebSocket-Key") != "" {
			http.Error(w, "invalid upgrade", 400)
			return
		}
		w.Header().Set("Connection", "upgrade")
		w.Header().Set("Upgrade", "websocket")
		w.WriteHeader(101)
		controller := http.NewResponseController(w)
		if err := controller.Flush(); err != nil {
			return
		}
		conn, rw, err := controller.Hijack()
		if err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		handler.NewConnection(context.Background(), &fixtureAuthConn{Conn: conn, reader: rw.Reader}, adapter.InboundContext{Source: M.ParseSocksaddr(r.RemoteAddr)}, nil)
	}))
	_ = server.Listener.Close()
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
}

func ensureNaiveFixture(t *testing.T) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(filepath.Dir(binary), "libcronet.dll")
	data, err := os.ReadFile(destination)
	created := false
	if os.IsNotExist(err) {
		goTool := filepath.Join(runtime.GOROOT(), "bin", "go.exe")
		module, lookupErr := exec.Command(goTool, "list", "-mod=readonly", "-m", "-f", "{{.Dir}}", "github.com/sagernet/cronet-go/lib/windows_amd64").Output()
		if lookupErr != nil {
			t.Fatal("locate pinned Naive dependency:", lookupErr)
		}
		data, err = os.ReadFile(filepath.Join(strings.TrimSpace(string(module)), "libcronet.dll"))
	}
	if err != nil {
		t.Fatal("read pinned Naive dependency:", err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != protocol.NaiveLibrarySHA256 {
		t.Fatal("pinned Naive dependency checksum mismatch")
	}
	if _, statErr := os.Stat(destination); os.IsNotExist(statErr) {
		if err := os.WriteFile(destination, data, 0600); err != nil {
			t.Fatal("stage pinned Naive dependency:", err)
		}
		created = true
	} else if statErr != nil {
		t.Fatal("inspect staged Naive dependency:", statErr)
	}
	if created {
		t.Cleanup(func() { _ = os.Remove(destination) })
	}
}

func TestNewProxyTraffic(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "new-protocol-payload") }))
	defer target.Close()
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer fixture.Close()
	cert := fixture.TLS.Certificates[0]
	template, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, template, template, template.PublicKey, cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert.Certificate[0] = der
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	for _, typ := range []string{"http", "https", "trojan", "trojan-ws", "trojan-grpc", "trojan-httpupgrade", "tuic", "anytls", "naive"} {
		t.Run(typ, func(t *testing.T) {
			if typ == "naive" {
				ensureNaiveFixture(t)
			}
			serverPort, clientPort := freePort(t), freePort(t)
			in := map[string]any{"type": typ, "listen": "127.0.0.1", "listen_port": serverPort}
			source := fmt.Sprintf("%s://fixture:fixture-password@127.0.0.1:%d", typ, serverPort)
			kind := protocol.HTTP
			switch typ {
			case "http", "https":
				in["type"] = "http"
				in["users"] = []any{map[string]any{"username": "fixture", "password": "fixture-password"}}
			case "trojan", "trojan-ws", "trojan-grpc", "trojan-httpupgrade":
				in["type"] = "trojan"
				kind = protocol.Trojan
				source = fmt.Sprintf("trojan://fixture-password@127.0.0.1:%d", serverPort)
				in["users"] = []any{map[string]any{"password": "fixture-password"}}
				if strings.HasPrefix(typ, "trojan-") {
					transport := strings.TrimPrefix(typ, "trojan-")
					in["transport"] = map[string]any{"type": transport, "path": "/fixture"}
					if transport == "grpc" {
						in["transport"] = map[string]any{"type": "grpc", "service_name": "fixture"}
						source += "?security=tls&type=grpc&serviceName=fixture"
					} else {
						source += "?security=tls&type=" + transport + "&path=%2Ffixture"
					}
				}

			case "tuic":
				kind = protocol.TUIC
				id := "11111111-1111-4111-8111-111111111111"
				source = fmt.Sprintf("tuic://%s:fixture-password@127.0.0.1:%d", id, serverPort)
				in["users"] = []any{map[string]any{"uuid": id, "password": "fixture-password"}}
			case "anytls":
				kind = protocol.AnyTLS
				source = fmt.Sprintf("anytls://fixture-password@127.0.0.1:%d", serverPort)
				in["users"] = []any{map[string]any{"password": "fixture-password"}}
			case "naive":
				in["network"] = "tcp"
				kind = protocol.Naive
				source = fmt.Sprintf("naive+https://fixture:fixture-password@127.0.0.1:%d", serverPort)
				in["users"] = []any{map[string]any{"username": "fixture", "password": "fixture-password"}}
			}
			if typ != "http" {
				in["tls"] = map[string]any{"enabled": true, "certificate": []string{certPEM}, "key": []string{keyPEM}}
			}
			if typ == "trojan-httpupgrade" {
				startUpgradeFixture(t, in, serverPort, cert)
			} else {
				startJSON(t, map[string]any{"inbounds": []any{in}, "outbounds": []any{map[string]any{"type": "direct"}}})
			}
			plan, err := protocol.Compile(source, kind, false, clientPort, freePort(t), "unused")
			if err != nil {
				t.Fatal(err)
			}
			var conf map[string]any
			json.Unmarshal([]byte(plan.Proxy), &conf)
			out := conf["outbounds"].([]any)[0].(map[string]any)
			if typ != "http" {
				tls := out["tls"].(map[string]any)
				tls["server_name"] = "example.com"
				tls["certificate"] = []string{certPEM}
			}
			// Recompile the actual imported JSON, including the pinned test CA.
			raw, _ := json.Marshal(out)
			plan, err = protocol.Compile(string(raw), kind, false, clientPort, freePort(t), "unused")
			if err != nil {
				t.Fatal(err)
			}
			json.Unmarshal([]byte(plan.Proxy), &conf)
			client := startJSON(t, conf)
			proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", clientPort))
			tr := &http.Transport{Proxy: http.ProxyURL(proxy)}
			defer tr.CloseIdleConnections()
			response, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get(target.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != "new-protocol-payload" {
				t.Fatal("payload failed", err)
			}
			tr.CloseIdleConnections()
			if strings.HasPrefix(typ, "trojan") || typ == "tuic" || typ == "anytls" {
				echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer echo.Close()
				go func() {
					buffer := make([]byte, 2048)
					n, peer, e := echo.ReadFrom(buffer)
					if e == nil {
						echo.WriteTo(buffer[:n], peer)
					}
				}()
				outbound, _ := client.instance.Outbound().Outbound("proxy")
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				destination := M.ParseSocksaddr(echo.LocalAddr().String())
				packet, err := outbound.ListenPacket(ctx, destination)
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				packet.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = packet.WriteTo([]byte("udp-payload"), destination.UDPAddr()); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 256)
				n, _, err := packet.ReadFrom(buffer)
				if err != nil || string(buffer[:n]) != "udp-payload" {
					t.Fatal("UDP failed", err)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			for _, failure := range []string{"password", "certificate"} {
				t.Run(failure, func(t *testing.T) {
					if failure == "certificate" && typ == "http" {
						return
					}
					var bad map[string]any
					json.Unmarshal(raw, &bad)
					if failure == "password" {
						bad["password"] = "wrong-password"
					} else {
						bad["tls"].(map[string]any)["server_name"] = "wrong.example"
					}
					badRaw, _ := json.Marshal(bad)
					badPort := freePort(t)
					plan, e := protocol.Compile(string(badRaw), kind, false, badPort, freePort(t), "unused")
					if e != nil {
						t.Fatal(e)
					}
					var badConfig map[string]any
					json.Unmarshal([]byte(plan.Proxy), &badConfig)
					badClient := startJSON(t, badConfig)
					defer badClient.Close()
					proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", badPort))
					transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
					defer transport.CloseIdleConnections()
					response, e := (&http.Client{Transport: transport, Timeout: time.Second}).Get(target.URL)
					if e == nil {
						body, _ := io.ReadAll(response.Body)
						response.Body.Close()
						if string(body) == "new-protocol-payload" {
							t.Fatal("authentication/TLS failure bypassed")
						}
					}
				})
			}

		})
	}
}
