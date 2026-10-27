package embeddedxray

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	N "github.com/xtls/xray-core/common/net"
	X "github.com/xtls/xray-core/core"
)

func TestVlessXUDPAndUDP443Policies(t *testing.T) {
	serverPort := freePort(t)
	id := "11111111-1111-4111-8111-111111111111"
	server, err := Start([]byte(fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[{"id":%q}],"decryption":"none"},"streamSettings":{"network":"tcp"}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}`, serverPort, id)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	echo, err := net.ListenPacket("udp4", "127.0.0.1:443")
	if err != nil {
		t.Fatal("VM UDP443 fixture required", err)
	}
	defer echo.Close()
	var received atomic.Int64
	go func() {
		b := make([]byte, 4096)
		for {
			n, from, e := echo.ReadFrom(b)
			if e != nil {
				return
			}
			received.Add(1)
			_, _ = echo.WriteTo(b[:n], from)
		}
	}()
	for _, policy := range []string{"allow", "skip", "reject"} {
		t.Run(policy, func(t *testing.T) {
			options := &protocol.TransportOptions{FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20", Mux: true, MuxConcurrency: 8, XUDPConcurrency: 4, UDP443Policy: policy}
			source := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none", id, serverPort)
			plan, e := protocol.CompileWithOptions(source, 2, false, freePort(t), freePort(t), "unused", options)
			if e != nil {
				t.Fatal(e)
			}
			client, e := Start([]byte(plan.Xray))
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			c, e := X.Dial(ctx, client.instance, N.UDPDestination(N.LocalHostIP, 443))
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			payload := []byte("xudp-" + policy)
			before := received.Load()
			if _, e = c.Write(payload); e != nil && policy != "reject" {
				t.Fatal(e)
			}
			done := make(chan bool, 1)
			go func() {
				b := make([]byte, len(payload))
				n, e := io.ReadFull(c, b)
				done <- e == nil && string(b[:n]) == string(payload)
			}()
			success := false
			select {
			case success = <-done:
			case <-ctx.Done():
				c.Close()
			}
			if policy == "reject" {
				if success || received.Load() != before {
					t.Fatal("UDP443 reject bypassed")
				}
			} else if !success || received.Load() != before+1 {
				t.Fatal("XUDP payload failed", policy)
			}
		})
	}
}
