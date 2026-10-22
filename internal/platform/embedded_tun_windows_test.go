//go:build windows && embeddedtun && embeddedxray && embeddedsingbox

package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows/svc"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"onetunnel/core/internal/control"
	"onetunnel/core/internal/embeddedsingbox"
	"onetunnel/core/internal/protocol"
	"os"
	"testing"
	"time"
)

func TestEmbeddedFullDevicePlans(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{directory: t.TempDir()}
	for _, fixture := range []struct {
		kind   int
		source string
	}{
		{2, "vless://6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a@127.0.0.1:443?security=none&type=tcp"},
		{3, "socks5://127.0.0.1:1080"},
		{4, "hy2://fixture@127.0.0.1:443?sni=example.com"},
		{5, "ss://YWVzLTEyOC1nY206Zml4dHVyZQ@127.0.0.1:443"},
	} {
		t.Run(fmt.Sprint(fixture.kind), func(t *testing.T) {
			identity, err := r.xrayIdentity(true)
			if err != nil || identity != executable {
				t.Fatal("wrong embedded transport identity", err)
			}
			plan, err := protocol.CompileWithOptions(fixture.source, fixture.kind, true, 43001, 43002, identity, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = embeddedsingbox.Validate([]byte(plan.Proxy)); err != nil {
				t.Fatal(err)
			}
			paths, err := r.transportProcesses(fixture.kind, true, plan.NeedsXray)
			if err != nil || len(paths) != 1 || paths[0] != executable {
				t.Fatal("WFP must permit only service transport process", paths, err)
			}
			var config map[string]any
			json.Unmarshal([]byte(plan.Proxy), &config)
			rules := jArray(jObject(config["route"])["rules"])
			if plan.NeedsXray {
				path := jArray(jObject(rules[0])["process_path"])
				if len(path) != 1 || path[0] != executable {
					t.Fatal("routing exception does not match embedded transport")
				}
			}
		})
	}
	paths, err := r.transportProcesses(0, true, false)
	if err != nil || len(paths) != 1 || (paths[0] == executable) != embeddedAWGEnabled() {
		t.Fatal("native Amnezia bypass changed")
	}
}

func TestEmbeddedFullDeviceMissingRoutesRetainsLock(t *testing.T) {
	v4, _ := routeInterface("1.1.1.1")
	v6, _ := routeInterface("2606:4700:4700::1111")
	if v4 == "OneTunnel" && v6 == "OneTunnel" {
		t.Skip("existing whole-device session left untouched")
	}
	root := t.TempDir()
	lock := trafficLock{root: root}
	if err := os.WriteFile(lock.marker(), []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Runtime{root: root, lock: lock, session: &Session{Kind: "proxy", FullDevice: true}, update: func(control.State) {}}
	r.poll()
	r.publish("")
	state := r.snapshot()
	if state.Active || !state.NeedsRecovery || !state.TrafficLocked || !lock.needed() {
		t.Fatal("missing TUN routes must retain fail-closed recovery")
	}
}

// Called only from the isolated SYSTEM fixture. Only two synthetic host routes
// are installed; default routes, DNS interception and WFP are unchanged.
func testEmbeddedTunSCM(t *testing.T) {
	system, err := svc.IsWindowsService()
	if err != nil || !system {
		t.Skip("isolated SCM worker required")
	}
	const name = "OneTunnelEmbeddedFixture"
	before, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, adapter := range before {
		if adapter.Name == name {
			t.Fatal("fixture adapter already exists; left untouched")
		}
	}
	before4, err4 := routeInterface("1.1.1.1")
	before6, err6 := routeInterface("2606:4700:4700::1111")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "isolated-tun-ok") }))
	defer target.Close()
	targetURL, _ := url.Parse(target.URL)
	_, targetPort, _ := net.SplitHostPort(targetURL.Host)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	data := []byte(fmt.Sprintf(`{"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":%d},{"type":"tun","tag":"fixture-tun","interface_name":%q,"address":["198.18.253.1/30","fdfe:dcba:ffff::1/126"],"auto_route":true,"route_address":["198.18.254.2/32","fdfe:dcba:fffe::2/128"],"strict_route":false,"dns_mode":"disabled","stack":"gvisor"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct","auto_detect_interface":true,"rules":[{"inbound":["fixture-tun"],"action":"route","outbound":"direct","override_address":"127.0.0.1","override_port":%s}]}}`, port, name, targetPort))
	engine, err := embeddedsingbox.Start(data)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	adapters, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, adapter := range adapters {
		found = found || adapter.Name == name
	}
	if !found {
		t.Fatal("isolated TUN not created")
	}
	proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	tr := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer tr.CloseIdleConnections()
	response, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "isolated-tun-ok" {
		t.Fatal("fixture proxy unavailable", err)
	}
	directTransport := &http.Transport{Proxy: nil}
	defer directTransport.CloseIdleConnections()
	for _, ip := range []string{"198.18.254.2", "fdfe:dcba:fffe::2"} {
		interfaceName, routeErr := routeInterface(ip)
		if routeErr != nil || interfaceName != name {
			t.Fatal("isolated host route missing", routeErr)
		}
		response, err := (&http.Client{Transport: directTransport, Timeout: 5 * time.Second}).Get("http://" + net.JoinHostPort(ip, targetPort))
		if err != nil {
			t.Fatal("isolated TUN payload failed", err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "isolated-tun-ok" {
			t.Fatal("isolated TUN payload mismatch", err)
		}
	}
	if err = engine.Close(); err != nil {
		t.Fatal(err)
	}
	after4, afterErr4 := routeInterface("1.1.1.1")
	after6, afterErr6 := routeInterface("2606:4700:4700::1111")
	if before4 != after4 || before6 != after6 || (err4 == nil) != (afterErr4 == nil) || (err6 == nil) != (afterErr6 == nil) {
		t.Fatal("default route changed by isolated TUN fixture")
	}
	// A new owner closes the Wintun adapter; wait briefly for Windows enumeration.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		adapters, err = net.Interfaces()
		if err != nil {
			t.Fatal(err)
		}
		found = false
		for _, adapter := range adapters {
			found = found || adapter.Name == name
		}
		if !found {
			return
		}
		if delay(ctx, 100*time.Millisecond) != nil {
			t.Fatal("isolated adapter still present")
		}
	}
}
