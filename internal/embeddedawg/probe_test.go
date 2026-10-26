package embeddedawg

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestProbeDNSAddressPreservesRoutesFamiliesAndSource(t *testing.T) {
	for _, tc := range []struct{ dns, routes, address, want string }{
		{"10.77.0.2", "10.77.0.2/32", "10.77.0.1/32", "10.77.0.2"},
		{"10.77.0.3", "10.77.0.2/32", "10.77.0.1/32", ""},
		{"fd00::2", "::/0", "10.77.0.1/32", ""},
		{"fd00::2", "fd00::/64", "fd00::1/128", "fd00::2"},
		{"127.0.0.1", "0.0.0.0/0", "10.77.0.1/32", ""},
		{"169.254.0.1", "0.0.0.0/0", "10.77.0.1/32", ""},
		{"224.0.0.1", "0.0.0.0/0", "10.77.0.1/32", ""},
		{"0.0.0.0", "0.0.0.0/0", "10.77.0.1/32", ""},
	} {
		p := &Plan{DNS: []net.IP{net.ParseIP(tc.dns)}, Routes: []netip.Prefix{netip.MustParsePrefix(tc.routes)}, Addresses: []netip.Prefix{netip.MustParsePrefix(tc.address)}, values: map[string]string{"ilistenport": "51820"}}
		got, ok := p.ProbeDNSAddress()
		if ok != (tc.want != "") || ok && got.String() != tc.want {
			t.Fatalf("%+v => %v %v", tc, got, ok)
		}
		p.UseEphemeralListenPort()
		if _, exists := p.values["ilistenport"]; exists {
			t.Fatal("fixed listen port retained")
		}
		if p.Routes[0].String() != tc.routes {
			t.Fatal("probe expanded routes")
		}
	}
}

func TestProbeDNSPairedWGAndAWG(t *testing.T) {
	for _, awg := range []bool{false, true} {
		for _, mode := range []string{"success", "id", "question", "query", "opcode", "truncated", "refused", "malformed", "cancel", "timeout"} {
			t.Run(strings.Join([]string{map[bool]string{false: "WG", true: "AWG"}[awg], mode}, "/"), func(t *testing.T) {
				a, b := startPair(t, awg)
				server, err := b.stack.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.2:53"))
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				if mode == "timeout" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				}
				defer cancel()
				done := make(chan struct{})
				go func() {
					defer close(done)
					buf := make([]byte, 4096)
					_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
					n, from, e := server.ReadFrom(buf)
					if e != nil {
						return
					}
					if mode == "cancel" {
						cancel()
						return
					}
					if mode == "timeout" {
						return
					}
					var response dnsmessage.Message
					if response.Unpack(buf[:n]) != nil {
						return
					}
					if len(response.Questions) != 1 || response.Questions[0].Name.String() != "." || response.Questions[0].Type != dnsmessage.TypeSOA || response.Questions[0].Class != dnsmessage.ClassINET {
						t.Error("probe must use a small root SOA question")
						cancel()
						return
					}
					response.Response = true
					switch mode {
					case "id":
						response.ID++
					case "question":
						response.Questions[0].Type = dnsmessage.TypeA
					case "query":
						response.Response = false
					case "opcode":
						response.OpCode = 1
					case "truncated":
						response.Truncated = true
					case "refused":
						response.RCode = dnsmessage.RCodeRefused
					}
					data, _ := response.Pack()
					if mode == "malformed" {
						data = []byte{1, 2, 3}
					}
					_, _ = server.WriteTo(data, from)
				}()
				latency, err := a.ProbeDNS(ctx, netip.MustParseAddr("10.77.0.2"))
				if (err == nil) != (mode == "success") || err == nil && latency < 0 {
					t.Fatalf("latency %v error %v", latency, err)
				}
				<-done
			})
		}
	}
}
