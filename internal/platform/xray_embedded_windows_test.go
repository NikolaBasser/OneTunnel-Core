//go:build windows && embeddedxray

package platform

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"onetunnel/core/internal/control"
	"onetunnel/core/internal/embeddedxray"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEmbeddedXrayScope(t *testing.T) {
	if !embeddedXrayAllowed(false) || embeddedXrayAllowed(true) != fullDeviceEmbeddingEnabled() {
		t.Fatal("embedded Xray must be restricted to proxy mode")
	}
}

func TestEmbeddedRuntimeLocalTraffic(t *testing.T) {
	directory := os.Getenv("ONETUNNEL_TEST_APP_DIRECTORY")
	if directory == "" {
		if embeddedSingBoxAllowed(false, false) {
			directory = t.TempDir()
		} else {
			t.Skip("set ONETUNNEL_TEST_APP_DIRECTORY to the local engine fixture directory")
		}
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "runtime"), 0700); err != nil {
		t.Fatal(err)
	}
	r := &Runtime{root: root, directory: directory, lock: trafficLock{root: root}, update: func(control.State) {}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	defer func() {
		if err := r.disconnect(ctx); err != nil {
			t.Error(err)
		}
	}()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "runtime-embedded-ok") }))
	defer target.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	id := "6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a"
	server, err := embeddedxray.Start([]byte(fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[{"id":%q}],"decryption":"none"}}],"outbounds":[{"protocol":"freedom"}]}`, port, id)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	profile := &control.Profile{ID: id, Name: "synthetic", Protocol: 2, Source: fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp", id, port)}
	if err = r.start(ctx, control.Request{Version: 1, Command: "start", Profile: profile}); err != nil {
		t.Fatal(err)
	}
	if r.xray != nil || r.embeddedXray == nil || r.session.XrayPid != 0 || r.lock.needed() {
		t.Fatal("unexpected external Xray or traffic lock")
	}
	if embeddedSingBoxAllowed(false, false) && (r.engine != nil || r.embeddedProxy == nil || r.session.Pid != 0) {
		t.Fatal("external sing-box unexpectedly created")
	}
	proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", r.snapshot().LocalPort))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "runtime-embedded-ok" {
		t.Fatal("runtime traffic failed", err)
	}
	// A bridge can close while its frontend remains listening. This must be
	// visible to the runtime, without discarding recovery state.
	if err = r.embeddedXray.Close(); err != nil {
		t.Fatal(err)
	}
	r.poll()
	if !r.transportFailed || !r.recovery() || r.embeddedProxy == nil {
		t.Fatal("closed embedded bridge was not detected")
	}
	if err = r.disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if r.session != nil || r.embeddedXray != nil || r.recovery() {
		t.Fatal("runtime cleanup incomplete")
	}
	// A service stop closes engines without pretending that an explicit user
	// disconnect happened. The next process must see the recovery journal.
	if err = r.start(ctx, control.Request{Version: 1, Command: "start", Profile: profile}); err != nil {
		t.Fatal(err)
	}
	address := fmt.Sprintf("127.0.0.1:%d", r.snapshot().LocalPort)
	r.stop = make(chan struct{})
	r.monitorDone = make(chan struct{})
	close(r.monitorDone)
	r.Close()
	r.Close()
	if r.Alive() || r.embeddedXray != nil || r.embeddedProxy != nil || !r.recovery() || r.lock.needed() {
		t.Fatal("service stop lost recovery state or engines")
	}
	connection, dialErr := net.DialTimeout("tcp4", address, time.Second)
	if dialErr == nil {
		connection.Close()
		t.Fatal("service stop left frontend listening")
	}
}
