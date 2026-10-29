//go:build windows && onetunnel_safety_test && embeddedawg && embeddedsingbox && embeddedtun && embeddedxray

package platform

import (
	"bufio"
	"context"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNativePolicyLiveTUNExpandedCopy(t *testing.T) {
	balanceVMonly(t)
	root, owner := os.Getenv("ONETUNNEL_BALANCE_ROOT"), os.Getenv("ONETUNNEL_BALANCE_OWNER")
	if root == "" || owner == "" {
		t.Fatal("independent recovery identity required")
	}
	for _, kind := range []int{1, 0} {
		t.Run(protocol.Names[kind], func(t *testing.T) {
			bootstrap, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			ip, err := (&Runtime{}).secureQualityBootstrap(bootstrap, "www.gstatic.com")
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			profile, _ := balanceTestNative(t, kind, "native", ip)
			profile.Source = strings.Replace(profile.Source, "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 172.16.0.0/24", 1)
			original := profile.Source
			profile.Network = &protocol.NetworkOptions{DNS: &protocol.DNSOptions{Transport: "https", ServerIP: "1.1.1.1", ServerName: "cloudflare-dns.com", Path: "/dns-query"}}
			r, err := NewSafetyTestRuntime(t.TempDir(), owner, root, func(control.State) {})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				reply, err := r.Call(ctx, control.Request{Version: 1, Command: "stop"})
				if err != nil || reply.Error != nil || reply.State.TrafficLocked || reply.State.NeedsRecovery {
					t.Error("native recovery", err, reply.Error)
				}
				r.Close()
				if !removeEmptyAcceptanceRuntime(root, owner) {
					t.Error("native test root cleanup")
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			reply, err := r.Call(ctx, control.Request{Version: 1, Command: "start", Profile: &profile, FullDevice: true})
			if err != nil || reply.Error != nil || !reply.State.Active || !reply.State.TrafficLocked {
				t.Fatal("native settings start", err, reply.Error)
			}
			c, err := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", "10.77.0.1:19090")
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(8 * time.Second))
			io.WriteString(c, "copy\n")
			line, err := bufio.NewReader(c).ReadString('\n')
			c.Close()
			if err != nil || line != "native:copy\n" {
				t.Fatal("TUN TCP outside imported AllowedIPs", line, err)
			}
			udp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("10.77.0.1"), Port: 19091})
			if err != nil {
				t.Fatal(err)
			}
			udp.SetDeadline(time.Now().Add(8 * time.Second))
			udp.Write([]byte("copy"))
			data := make([]byte, 64)
			n, err := udp.Read(data)
			udp.Close()
			if err != nil || string(data[:n]) != "native:copy" {
				t.Fatal("TUN UDP outside imported AllowedIPs", err)
			}
			if err = r.connectionHealth(ctx); err != nil {
				t.Fatal("encrypted DNS outside imported AllowedIPs", err)
			}
			if profile.Source != original {
				t.Fatal("imported source changed")
			}
			t.Log("real WG/AWG shared TUN: TCP, UDP and encrypted DNS outside 172.16.0.0/24; original source unchanged")
		})
	}
}
