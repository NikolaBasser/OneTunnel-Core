package profiles

import (
	"encoding/base64"
	"encoding/json"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"strings"
	"testing"
)

func TestNewProtocolImport(t *testing.T) {
	links := []string{"http://user:password@proxy.example:8080#HTTP", "https://user:password@proxy.example:443#HTTPS", "trojan://secret@proxy.example:443?sni=proxy.example#Trojan", "tuic://11111111-1111-4111-8111-111111111111:secret@proxy.example:443?congestion_control=bbr&udp_relay_mode=quic#TUIC", "anytls://secret@proxy.example:443#AnyTLS", "naive+https://user:secret@proxy.example:443#Naive"}
	for _, link := range links {
		t.Run(link[:strings.Index(link, ":")], func(t *testing.T) {
			p, err := Parse("", link, nil)
			if err != nil {
				t.Fatal(err)
			}
			if p.Protocol != protocol.LinkKind(link) || Validate(p) != nil || IsURL(link) {
				t.Fatal("wrong classification")
			}
			out, err := protocol.Outbound(link, p.Protocol)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(out)
			raw, err := Parse(p.Name, string(data), nil)
			if err != nil {
				t.Fatal(err)
			}
			a, _ := Identity(p)
			b, _ := Identity(raw)
			if a != b {
				t.Fatal("identity changed")
			}
		})
	}
	payload := strings.Join(links, "\n")
	for _, source := range []string{payload, base64.StdEncoding.EncodeToString([]byte(payload))} {
		batch, err := ParseSubscription(source)
		if err != nil || len(batch.Profiles) != len(links) {
			t.Fatal("subscription failed", err)
		}
		var outs []any
		for _, p := range batch.Profiles {
			out, _ := protocol.Outbound(p.Source, p.Protocol)
			outs = append(outs, out)
		}
		data, _ := json.Marshal(map[string]any{"outbounds": outs})
		result, err := ParseSubscription(string(data))
		if err != nil || len(result.Profiles) != len(links) {
			t.Fatal("JSON subscription failed", err)
		}
	}
	for _, web := range []string{"https://sub.example/token", "https://sub.example:8443/subs/token", "https://sub.example/"} {
		if !IsURL(web) {
			t.Fatal("lost subscription", web)
		}
	}
}

func TestNewProxyUnsafeImport(t *testing.T) {
	for _, link := range []string{"trojan://secret@proxy.example:443?allowInsecure=1", "anytls://secret@proxy.example:443?congestion_control=bbr", "tuic://bad:secret@proxy.example:443", "naive+https://user:secret@proxy.example:443?alpn=h2", `{"type":"trojan","server":"proxy.example","server_port":443,"password":"p","tls":{"enabled":true,"insecure":true}}`, `{"type":"http","server":"proxy.example","server_port":8080,"detour":"direct"}`, `{"type":"http","server":"proxy.example","server_port":8080,"tls":{"certificate_path":"C:/secret"}}`} {
		if _, err := Parse("bad", link, nil); err == nil {
			t.Fatal("unsafe import accepted")
		}
	}
}
