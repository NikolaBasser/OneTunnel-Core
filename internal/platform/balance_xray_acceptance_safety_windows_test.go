//go:build windows && onetunnel_safety_test && embeddedawg && embeddedsingbox && embeddedtun && embeddedxray

package platform

import (
	"context"
	"fmt"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedxray"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBalanceLiveXrayCandidateLifecycle(t *testing.T) {
	balanceVMonly(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "pooled-vless-ok") }))
	defer target.Close()
	port, e := freePort()
	if e != nil {
		t.Fatal(e)
	}
	id := "11111111-1111-4111-8111-111111111111"
	server, e := embeddedxray.Start([]byte(fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[{"id":%q}],"decryption":"none"},"streamSettings":{"network":"tcp"}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8","::1/128"]}]}}]}`, port, id)))
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	r := &Runtime{}
	r.captureQualityUplinks()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	candidate, e := r.buildBalanceNode(ctx, control.Profile{ID: id, Protocol: 2, Source: fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp", id, port)})
	if e != nil {
		t.Fatal(e)
	}
	defer candidate.Close()
	address := strings.TrimPrefix(target.URL, "http://")
	c, e := candidate.DialContext(ctx, "tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(8 * time.Second))
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
	body, e := io.ReadAll(c)
	c.Close()
	if e != nil || !strings.Contains(string(body), "pooled-vless-ok") {
		t.Fatal("VLESS candidate traffic", e, string(body))
	}
	proxy := candidate.(*balanceProxy)
	if proxy.xray == nil {
		t.Fatal("Xray engine not used")
	}
	if e = proxy.xray.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-candidate.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Xray failure not reflected in candidate lifecycle")
	}
	if e = candidate.Close(); e != nil {
		t.Fatal(e)
	}

}
