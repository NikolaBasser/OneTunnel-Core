package protocol

import "testing"

func TestBundleBoundaryKeepsNewProxyCompilers(t *testing.T) {
	cases := []struct {
		kind   int
		source string
	}{
		{HTTP, "http://user:synthetic@proxy.example:8080"},
		{HTTP, "https://user:synthetic@proxy.example:443"},
		{Trojan, "trojan://synthetic@proxy.example:443?sni=proxy.example"},
		{TUIC, "tuic://11111111-1111-4111-8111-111111111111:synthetic@proxy.example:443?congestion_control=bbr&udp_relay_mode=quic"},
		{AnyTLS, "anytls://synthetic@proxy.example:443"},
		{Naive, "naive+https://user:synthetic@proxy.example:443"},
	}
	for _, c := range cases {
		for _, full := range []bool{false, true} {
			plan, err := Compile(c.source, c.kind, full, 18734, 18735, "xray.exe")
			if err != nil || plan.Proxy == "" {
				t.Fatalf("kind %d full-device %v: proxy configuration unavailable: %v", c.kind, full, err)
			}
		}
	}
}
