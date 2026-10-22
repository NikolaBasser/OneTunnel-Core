package platform

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestGeneratedTransportDialerSharesUplink(t *testing.T) {
	stream := jsonObject{"network": "tcp", "sockopt": jsonObject{"dialerProxy": "onetunnel-transport"}}
	dialer := jsonObject{"protocol": "freedom", "tag": "onetunnel-transport", "streamSettings": jsonObject{"sockopt": jsonObject{}}}
	out := jsonObject{"protocol": "vless", "settings": jsonObject{"vnext": []any{jsonObject{"address": "127.0.0.1", "port": 443}}}, "streamSettings": stream}
	config := jsonObject{"outbounds": []any{out, dialer}}
	if err := prepareXray(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	uplink := jString(jObject(stream["sockopt"])["interface"])
	if uplink == "" || jString(jObject(jObject(dialer["streamSettings"])["sockopt"])["interface"]) != uplink {
		t.Fatal("generated socket dialer lost upstream interface binding")
	}
	if jString(jObject(stream["sockopt"])["dialerProxy"]) != "onetunnel-transport" || first(config["outbounds"])["protocol"] != "vless" {
		t.Fatal("binding changed authenticated route")
	}
}

func TestHTTPSProbeFallbackRejectsLoginPage(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/secondary" {
			w.WriteHeader(204)
			return
		}
		w.Write([]byte("Login page"))
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.CloseIdleConnections()
	err := checkHTTPSProbes(context.Background(), transport, []httpsProbe{{server.URL + "/primary", 200, "Example Domain"}, {server.URL + "/secondary", 204, ""}, {server.URL + "/unused", 200, "Success"}})
	if err != nil || calls.Load() != 2 {
		t.Fatal("fallback must accept verified TLS/204, reject login content and stop after success", err)
	}
	if err = checkHTTPSProbes(context.Background(), transport, []httpsProbe{{server.URL + "/primary", 200, "Example Domain"}}); err == nil {
		t.Fatal("login page was accepted as working access")
	}
}

func TestHTTPSProbeCancellationAndTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := checkHTTPSProbes(ctx, transport, []httpsProbe{{server.URL, 200, ""}}); err == nil || ctx.Err() == nil {
		t.Fatal("probe ignored cancellation")
	}
	if err := checkHTTPSProbes(context.Background(), transport, []httpsProbe{{"http://127.0.0.1", 200, ""}}); err == nil {
		t.Fatal("plaintext probe accepted")
	}
	untrusted := &http.Transport{}
	defer untrusted.CloseIdleConnections()
	if err := checkHTTPSProbes(context.Background(), untrusted, []httpsProbe{{server.URL, 200, ""}}); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
}

func TestInterfaceBoundProbe(t *testing.T) {
	name, err := routeInterface("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := interfaceDialer(name)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.CloseIdleConnections()
	if err := checkHTTPSProbes(context.Background(), transport, []httpsProbe{{server.URL, 204, ""}}); err != nil {
		t.Fatal("bound probe failed", err)
	}
	if _, err := interfaceDialer("OneTunnelMissingFixtureInterface"); err == nil {
		t.Fatal("missing interface must not fall back to direct access")
	}
}
