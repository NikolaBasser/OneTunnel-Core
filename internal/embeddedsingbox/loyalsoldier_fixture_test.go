//go:build windows && amd64 && with_naive_outbound && with_purego

package embeddedsingbox

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestLoyalCompiledIPRouting(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		for _, action := range []string{"direct", "reject"} {
			t.Run(family+"/"+action, func(t *testing.T) {
				address, prefix := "127.0.0.1:0", "127.0.0.0/8"
				if family == "tcp6" {
					address, prefix = "[::1]:0", "::1/128"
				}
				listener, e := net.Listen(family, address)
				if e != nil {
					t.Fatal(e)
				}
				var calls atomic.Int64
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, "loyal-route") }))
				server.Listener.Close()
				server.Listener = listener
				server.Start()
				defer server.Close()
				data, e := protocol.ImportLoyalsoldier("clash-ipcidr", "", []byte("payload:\n - '"+prefix+"'\n"))
				if e != nil {
					t.Fatal(e)
				}
				local := freePort(t)
				plan, e := protocol.CompileWithNetwork("socks5://127.0.0.1:1", 3, true, local, freePort(t), "unused", nil, &protocol.NetworkOptions{RuleSets: []protocol.RuleSet{{Name: "loyal-ip", Data: data}}, Rules: []protocol.NetworkRule{{Kind: "rule-set", Value: "loyal-ip", Action: action}}})
				if e != nil {
					t.Fatal(e)
				}
				var config map[string]any
				if e = json.Unmarshal([]byte(plan.Proxy), &config); e != nil {
					t.Fatal(e)
				}
				// This test exercises the compiled router through SOCKS without modifying OS routes.
				inbounds := []any{}
				for _, v := range config["inbounds"].([]any) {
					if v.(map[string]any)["type"] != "tun" {
						inbounds = append(inbounds, v)
					}
				}
				config["inbounds"] = inbounds
				startJSON(t, config)
				proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", local))
				transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				response, e := client.Get(server.URL)
				if action == "reject" {
					if response != nil {
						response.Body.Close()
					}
					if e == nil || calls.Load() != 0 {
						t.Fatal("reject delivered traffic")
					}
					return
				}
				if e != nil {
					t.Fatal(e)
				}
				response.Body.Close()
				if calls.Load() != 1 || response.StatusCode != 200 {
					t.Fatal("direct rule missed")
				}
			})
		}
	}
}
