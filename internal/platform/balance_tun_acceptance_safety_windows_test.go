//go:build windows && onetunnel_safety_test && embeddedawg && embeddedsingbox && embeddedtun && embeddedxray

package platform

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

func TestBalanceTUNRecovery(t *testing.T) {
	balanceVMonly(t)
	root, owner := os.Getenv("ONETUNNEL_BALANCE_ROOT"), os.Getenv("ONETUNNEL_BALANCE_OWNER")
	if root == "" || owner == "" {
		t.Fatal("isolated root required")
	}
	if !exists(root) {
		return
	}
	r, e := OpenSafetyTestRuntime(t.TempDir(), owner, root, func(control.State) {})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reply, e := r.Call(ctx, control.Request{Version: 1, Command: "recover"})
	if e != nil || reply.Error != nil || reply.State.TrafficLocked || reply.State.NeedsRecovery {
		t.Fatal("independent recovery", e, reply.Error)
	}
	if !removeEmptyAcceptanceRuntime(root, owner) {
		t.Fatal("recovery root not removed")
	}
}

func TestBalanceLiveSharedTUN(t *testing.T) {
	balanceVMonly(t)
	root, owner := os.Getenv("ONETUNNEL_BALANCE_ROOT"), os.Getenv("ONETUNNEL_BALANCE_OWNER")
	if root == "" || owner == "" {
		t.Fatal("independent recovery identity required")
	}
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	probeIP, err := (&Runtime{}).secureQualityBootstrap(probeCtx, "www.gstatic.com")
	probeCancel()
	if err != nil {
		t.Fatal(err)
	}
	wg, _ := balanceTestNative(t, 1, "wg", probeIP)
	awg, _ := balanceTestNative(t, 0, "awg", probeIP)
	wg.Source = strings.Replace(wg.Source, "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 172.16.0.0/24", 1)
	awg.Source = strings.Replace(awg.Source, "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 172.16.0.0/24", 1)
	r, e := NewSafetyTestRuntime(t.TempDir(), owner, root, func(control.State) {})
	if e != nil {
		t.Fatal(e)
	}
	r.captureQualityUplinks()
	r.balanceProbeIP = probeIP
	r.forceSecureBootstrap = true
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		reply, e := r.Call(ctx, control.Request{Version: 1, Command: "stop"})
		if e != nil || reply.Error != nil || reply.State.TrafficLocked || reply.State.NeedsRecovery {
			t.Error("TUN/WFP cleanup", e, reply.Error)
		}
		r.Close()
		if !removeEmptyAcceptanceRuntime(root, owner) {
			t.Error("isolated root cleanup")
		}
	}()
	gateway, e := newAcceptanceGateway()
	if e != nil {
		t.Fatal(e)
	}
	defer gateway.stop()
	gateway.mu.Lock()
	gateway.allowConnect = func(string) bool { return true }
	gateway.dialConnect = func(ctx context.Context, address string) (net.Conn, error) {
		if address == "10.77.0.1:19090" {
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				line, e := bufio.NewReader(b).ReadString('\n')
				if e == nil {
					io.WriteString(b, "proxy:"+line)
				}
			}()
			return a, nil
		}
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		if net.ParseIP(host) == nil {
			host, e = r.secureQualityBootstrap(ctx, host)
			if e != nil {
				return nil, e
			}
		}
		name, e := r.qualityInterface(host)
		if e != nil {
			return nil, e
		}
		d, e := interfaceDialer(name)
		if e != nil {
			return nil, e
		}
		return d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}
	gateway.mu.Unlock()
	p := control.Profile{ID: "33333333-3333-4333-8333-333333333333", Name: "proxy", Group: "manual", Protocol: 6, Source: "http://" + gateway.address}
	wg.Reliability = &control.ReliabilityOptions{AutoReconnect: true}
	request := control.Request{Version: 1, Command: "start", Profile: &wg, FullDevice: true, Balance: &control.Balance{Mode: "balanced", Best: 3, Interval: 30, MaxRTT: 10000, Members: []control.Profile{func() control.Profile { p := wg; p.Reliability = nil; return p }(), awg, p}}}
	request.Balance.Automatic = true
	if code := control.Validate(request); code != "" {
		t.Fatal(code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	reply, e := r.Call(ctx, request)
	if e != nil || reply.Error != nil {
		t.Fatal("full pool start", e, reply.Error)
	}
	if !reply.State.Active || !reply.State.TrafficLocked || !reply.State.FullDeviceMode {
		t.Fatal("TUN/WFP protection missing")
	}
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		c, e := (&net.Dialer{Timeout: 12 * time.Second}).DialContext(ctx, "tcp", "10.77.0.1:19090")
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(12 * time.Second))
		io.WriteString(c, "tun\n")
		line, e := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if e != nil {
			t.Fatal("actual TUN TCP", e)
		}
		for _, label := range []string{"wg", "awg", "proxy"} {
			if line == label+":tun\n" {
				seen[label] = true
			}
		}
	}
	if len(seen) != 3 {
		t.Fatal("actual TUN did not distribute all protocols", seen)
	}
	if !strings.Contains(wg.Source, "AllowedIPs = 172.16.0.0/24") || !strings.Contains(awg.Source, "AllowedIPs = 172.16.0.0/24") {
		t.Fatal("original native sources changed")
	}
	for i := 0; i < 2; i++ {
		c, e := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("10.77.0.1"), Port: 19091})
		if e != nil {
			t.Fatal(e)
		}
		first := ""
		for j := 0; j < 3; j++ {
			c.SetDeadline(time.Now().Add(8 * time.Second))
			payload := fmt.Sprintf("flow-%d", i)
			c.Write([]byte(payload))
			b := make([]byte, 128)
			n, e := c.Read(b)
			if e != nil {
				c.Close()
				t.Fatal("actual TUN UDP", e)
			}
			value := string(b[:n])
			if j == 0 {
				first = value
			} else if first != value {
				t.Fatal("UDP flow moved between native peers")
			}
		}
		c.Close()
	}
	if e = r.connectionHealth(ctx); e != nil {
		t.Fatal("pooled encrypted DNS health", e)
	}
	t.Log("real shared TUN: TCP across WG/AWG/proxy, UDP session affinity, encrypted DNS and WFP verified")
}
