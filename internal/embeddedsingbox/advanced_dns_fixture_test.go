//go:build windows && amd64 && with_quic && with_naive_outbound && with_purego

package embeddedsingbox

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	D "github.com/miekg/dns"
	Q "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	M "github.com/sagernet/sing/common/metadata"
)

type dnsQUICFixture struct {
	port        int
	certificate string
	queries     atomic.Int64
}

func newDNSQUICFixture(t *testing.T, kind string) *dnsQUICFixture {
	t.Helper()
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := fixture.TLS.Certificates[0]
	fixture.Close()
	f := &dnsQUICFixture{certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))}
	answer := func(raw []byte) ([]byte, error) {
		q := new(D.Msg)
		if err := q.Unpack(raw); err != nil {
			return nil, err
		}
		f.queries.Add(1)
		r := new(D.Msg)
		r.SetReply(q)
		if len(q.Question) > 0 && q.Question[0].Qtype == D.TypeA {
			r.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 120}, A: net.IPv4(127, 0, 0, 1)}}
		}
		return r.Pack()
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw []byte
		var e error
		if r.Method == "POST" {
			raw, e = io.ReadAll(io.LimitReader(r.Body, 65536))
		} else {
			raw, e = DFromURL(r.URL)
		}
		if e != nil {
			http.Error(w, "bad DNS", 400)
			return
		}
		reply, e := answer(raw)
		if e != nil {
			http.Error(w, "bad DNS", 400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(reply)
	})
	if kind == "https" {
		server := httptest.NewUnstartedServer(handler)
		server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		server.StartTLS()
		t.Cleanup(server.Close)
		f.port = server.Listener.Addr().(*net.TCPAddr).Port
	} else if kind == "quic" {
		listener, err := Q.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"doq"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		f.port = listener.Addr().(*net.UDPAddr).Port
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go func() {
			for {
				c, err := listener.Accept(ctx)
				if err != nil {
					return
				}
				go func() {
					defer c.CloseWithError(0, "")
					for {
						s, e := c.AcceptStream(ctx)
						if e != nil {
							return
						}
						go func() {
							defer s.Close()
							var size uint16
							if binary.Read(s, binary.BigEndian, &size) != nil {
								return
							}
							raw := make([]byte, size)
							if _, e := io.ReadFull(s, raw); e != nil {
								return
							}
							reply, e := answer(raw)
							if e == nil {
								_ = binary.Write(s, binary.BigEndian, uint16(len(reply)))
								_, _ = s.Write(reply)
							}
						}()
					}
				}()
			}
		}()
	} else {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		f.port = socket.LocalAddr().(*net.UDPAddr).Port
		server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var raw []byte
			var e error
			if r.Method == "POST" {
				raw, e = io.ReadAll(io.LimitReader(r.Body, 65536))
			} else {
				raw, e = DFromURL(r.URL)
			}
			if e != nil {
				http.Error(w, "bad DNS", 400)
				return
			}
			reply, e := answer(raw)
			if e != nil {
				http.Error(w, "bad DNS", 400)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(reply)
		})}
		go func() { _ = server.Serve(socket) }()
		t.Cleanup(func() { server.Close(); socket.Close() })
	}
	return f
}

func DFromURL(u *url.URL) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(u.Query().Get("dns"))
}

func newDNSPolicyClient(t *testing.T, source string, kind int, options *protocol.NetworkOptions, certificate string, badName bool) (int, *Engine, *Engine) {
	t.Helper()
	local := freePort(t)
	plan, err := protocol.CompileWithNetwork(source, kind, true, local, freePort(t), "unused", nil, options)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err = json.Unmarshal([]byte(plan.Proxy), &config); err != nil {
		t.Fatal(err)
	}
	inbounds := []any{}
	for _, in := range config["inbounds"].([]any) {
		if in.(map[string]any)["type"] != "tun" {
			inbounds = append(inbounds, in)
		}
	}
	config["inbounds"] = inbounds
	for _, raw := range config["dns"].(map[string]any)["servers"].([]any) {
		server := raw.(map[string]any)
		if server["type"] == "fakeip" {
			continue
		}
		tls := server["tls"].(map[string]any)
		tls["certificate"] = []string{certificate}
		if badName {
			tls["server_name"] = "wrong.fixture"
		}
	}
	engine := startJSON(t, config)
	ingress := startJSON(t, map[string]any{"outbounds": []any{map[string]any{"type": "socks", "tag": "query", "server": "127.0.0.1", "server_port": local, "version": "5"}}})
	return local, ingress, engine
}
func queryPolicyDNS(t *testing.T, ingress *Engine, name string, kind uint16, want bool) *D.Msg {
	t.Helper()
	q := new(D.Msg)
	q.SetQuestion(D.Fqdn(name), kind)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	out, _ := ingress.instance.Outbound().Outbound("query")
	dest := M.ParseSocksaddr("1.1.1.1:53")
	packet, err := out.ListenPacket(ctx, dest)
	var reply *D.Msg
	if err == nil {
		defer packet.Close()
		_ = packet.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		raw, _ := q.Pack()
		_, err = packet.WriteTo(raw, dest.UDPAddr())
		if err == nil {
			b := make([]byte, 65535)
			var n int
			n, _, err = packet.ReadFrom(b)
			if err == nil {
				reply = new(D.Msg)
				err = reply.Unpack(b[:n])
			}
		}
	}
	success := err == nil && reply != nil && reply.Rcode == D.RcodeSuccess
	if success != want {
		t.Fatalf("DNS %s expected %v, reply=%v err=%v", name, want, reply, err)
	}
	return reply
}

func TestDoQAndDoH3ThroughProxyCacheAndTLS(t *testing.T) {
	for _, kind := range []string{"quic", "h3"} {
		t.Run(kind, func(t *testing.T) {
			f := newDNSQUICFixture(t, kind)
			serverPort := freePort(t)
			startJSON(t, map[string]any{"inbounds": []any{map[string]any{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": serverPort, "method": "chacha20-ietf-poly1305", "password": "dns-fixture"}}, "outbounds": []any{map[string]any{"type": "direct"}}})
			gatePort, gate := newUDPChainGate(t, serverPort)
			source := fmt.Sprintf("ss://chacha20-ietf-poly1305:dns-fixture@127.0.0.1:%d", gatePort)
			options := &protocol.NetworkOptions{DNS: &protocol.DNSOptions{Transport: kind, ServerIP: "127.0.0.1", ServerName: "example.com", Port: f.port}, DNSCache: &protocol.DNSCacheOptions{Capacity: 128}}
			_, port, _ := newDNSPolicyClient(t, source, 5, options, f.certificate, false)
			for i := 0; i < 2; i++ {
				r := queryPolicyDNS(t, port, "cached.fixture", D.TypeA, true)
				if len(r.Answer) != 1 {
					t.Fatal("missing DNS answer")
				}
			}
			if f.queries.Load() != 1 || gate.sent.Load() == 0 {
				t.Fatal("cache or encrypted proxy path not used", f.queries.Load(), gate.sent.Load())
			}
			options.DNSCache.Disabled = true
			_, uncached, _ := newDNSPolicyClient(t, source, 5, options, f.certificate, false)
			before := f.queries.Load()
			for i := 0; i < 2; i++ {
				queryPolicyDNS(t, uncached, "uncached.fixture", D.TypeA, true)
			}
			if f.queries.Load() != before+2 {
				t.Fatal("disabled cache retained responses")
			}
			_, bad, _ := newDNSPolicyClient(t, source, 5, options, f.certificate, true)
			before = f.queries.Load()
			queryPolicyDNS(t, bad, "bad-cert.fixture", D.TypeA, false)
			if f.queries.Load() != before {
				t.Fatal("TLS mismatch bypassed")
			}
			gate.online.Store(false)
			before = f.queries.Load()
			queryPolicyDNS(t, uncached, "offline.fixture", D.TypeA, false)
			if f.queries.Load() != before {
				t.Fatal("DNS bypassed unavailable proxy")
			}
			gate.online.Store(true)
		})
	}
}

func TestFakeIPRoutesAndDomainRejection(t *testing.T) {
	f := newDNSQUICFixture(t, "https")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "fakeip-payload") }))
	t.Cleanup(target.Close)
	targetURL, _ := url.Parse(target.URL)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address := r.Host
		if strings.HasPrefix(address, "echo.fixture:") {
			address = targetURL.Host
		}
		up, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			http.Error(w, "upstream", 502)
			return
		}
		defer up.Close()
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = rw.Flush()
		done := make(chan struct{})
		go func() { _, _ = io.Copy(up, rw); up.Close(); close(done) }()
		_, _ = io.Copy(c, up)
		c.Close()
		<-done
	}))
	t.Cleanup(proxy.Close)
	// FakeIP A/AAAA answers are local; non-address queries use HTTPS.
	// The router must preserve domain and IP rejection before dialing.
	options := &protocol.NetworkOptions{FakeIP: true, DNS: &protocol.DNSOptions{Transport: "https", ServerIP: "127.0.0.1", ServerName: "example.com", Port: f.port}}
	local, port, _ := newDNSPolicyClient(t, proxy.URL, protocol.HTTP, options, f.certificate, false)
	r := queryPolicyDNS(t, port, "echo.fixture", D.TypeA, true)
	if len(r.Answer) != 1 {
		t.Fatal("missing FakeIP")
	}
	fake := r.Answer[0].(*D.A).A.String()
	if !strings.HasPrefix(fake, "198.18.") && !strings.HasPrefix(fake, "198.19.") {
		t.Fatal("not a synthetic address", fake)
	}
	r6 := queryPolicyDNS(t, port, "echo.fixture", D.TypeAAAA, true)
	if len(r6.Answer) != 1 || !strings.HasPrefix(r6.Answer[0].(*D.AAAA).AAAA.String(), "fc") {
		t.Fatal("missing FakeIPv6")
	}
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", local))
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	_, portText, _ := net.SplitHostPort(targetURL.Host)
	response, err := client.Get("http://" + net.JoinHostPort(fake, portText) + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "fakeip-payload" {
		t.Fatal("FakeIP domain mapping lost")
	}
	for _, rule := range []protocol.NetworkRule{{Kind: "domain", Value: "echo.fixture", Action: "reject"}, {Kind: "cidr", Value: "127.0.0.0/8", Action: "reject"}} {
		options.Rules = []protocol.NetworkRule{rule}
		blockedLocal, blockedDNS, _ := newDNSPolicyClient(t, proxy.URL, protocol.HTTP, options, f.certificate, false)
		blocked := queryPolicyDNS(t, blockedDNS, "echo.fixture", D.TypeA, true).Answer[0].(*D.A).A.String()
		p, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", blockedLocal))
		transport := &http.Transport{Proxy: http.ProxyURL(p)}
		defer transport.CloseIdleConnections()
		response, err = (&http.Client{Transport: transport, Timeout: time.Second}).Get("http://" + net.JoinHostPort(blocked, portText) + "/")
		if err == nil {
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if string(body) == "fakeip-payload" {
				t.Fatal("FakeIP hid domain from reject rule")
			}
		}
	}
	before := f.queries.Load()
	queryPolicyDNS(t, port, ".", D.TypeNS, true)
	if f.queries.Load() != before+1 {
		t.Fatal("non-address health query answered by FakeIP/cache")
	}

}
