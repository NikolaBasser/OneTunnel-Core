package platform

import (
	"context"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestQualityBootstrapUsesExplicitEncryptedDialer(t *testing.T) {
	var calls atomic.Int32
	_, err := secureBootstrapLookupWithDial(context.Background(), "example.com", func(_ context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		if network != "tcp" || (address != "1.1.1.1:443" && address != "8.8.8.8:443") {
			t.Errorf("unexpected bootstrap destination: %s %s", network, address)
		}
		return nil, errors.New("synthetic bound-dial rejection")
	})
	if err == nil || calls.Load() == 0 {
		t.Fatal("encrypted bootstrap ignored the explicit physical dialer")
	}
}

func TestStartCannotReplaceActiveReconnect(t *testing.T) {
	f := newRetryFixture(t)
	f.r.retrying = true
	reply, err := f.r.Call(context.Background(), control.Request{Version: 1, Command: "start"})
	if err != nil || reply.Error == nil || !f.r.retrying || len(f.r.retry.targets) != 2 {
		t.Fatal("external start replaced retry ownership")
	}
}

func TestTerminalRetryClosesProxyWatchdogEndpoint(t *testing.T) {
	f := newRetryFixture(t)
	front, err := newProxyFront()
	if err != nil {
		t.Fatal(err)
	}
	defer front.close()
	f.r.front = front
	f.r.retry.attempt = 9
	f.r.maintainConnectionWith(f.effects)
	if f.r.front != nil || probeLoopbackListener(net.JoinHostPort("127.0.0.1", itoa(front.port())), time.Second) == nil {
		t.Fatal("terminal retry retained accepting proxy endpoint")
	}
}

func TestProxyFrontStableAcrossVerifiedBackends(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			c, e := backend.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	f, err := newProxyFront()
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	address := net.JoinHostPort("127.0.0.1", itoa(f.port()))
	f.setBackend(backend.Addr().(*net.TCPAddr).Port)
	c, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte("test"))
	body := make([]byte, 4)
	if _, err = io.ReadFull(c, body); err != nil || string(body) != "test" {
		t.Fatal("front did not forward", err)
	}
	f.setBackend(0)
	if _, err = c.Read(body); err == nil {
		t.Fatal("old flow survived removal")
	}
	if err = probeLoopbackListener(address, time.Second); err != nil {
		t.Fatal("watchdog endpoint disappeared during reconnect")
	}
	c2, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c2.SetDeadline(time.Now().Add(time.Second))
	_, _ = c2.Write([]byte("blocked"))
	if _, err = c2.Read(body); err == nil {
		t.Fatal("offline front forwarded traffic")
	}
	_ = c2.Close()
	f.setBackend(backend.Addr().(*net.TCPAddr).Port)
	c3, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	_ = c3.SetDeadline(time.Now().Add(time.Second))
	_, _ = c3.Write([]byte("next"))
	if _, err = io.ReadFull(c3, body); err != nil || string(body) != "next" {
		t.Fatal("same port did not resume", err)
	}
}

func TestQualityConfigHasNoOSIngressOrDirectProof(t *testing.T) {
	config := jsonObject{"inbounds": []any{jsonObject{"type": "mixed"}, jsonObject{"type": "tun", "auto_route": true}}, "route": jsonObject{"auto_detect_interface": true, "rules": []any{jsonObject{"outbound": "direct", "action": "route"}, jsonObject{"outbound": "xray-uplink", "action": "route"}}}, "outbounds": []any{jsonObject{"server": "203.0.113.1"}}}
	if err := prepareQualityConfig(config, func(string) (string, error) { return "Ethernet", nil }); err != nil {
		t.Fatal(err)
	}
	if len(jArray(config["inbounds"])) != 1 || jObject(config["route"])["auto_detect_interface"] != false || jString(first(config["outbounds"])["bind_interface"]) != "Ethernet" {
		t.Fatal("probe changed network boundary")
	}
	rules := jArray(jObject(config["route"])["rules"])
	if len(rules) != 1 || jString(jObject(rules[0])["action"]) != "reject" {
		t.Fatal("bypass could qualify primary quality")
	}
}
