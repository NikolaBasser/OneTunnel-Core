package protocol

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestCSharpParity(t *testing.T) {
	data, e := os.ReadFile("testdata/parity.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct {
		Kind                                       int
		Source                                     string
		Full                                       bool
		NativeSource                               string
		NativeShadowsocks, NeedsXray, AccurateTime bool
		Proxy, Xray                                json.RawMessage
	}
	if e = json.Unmarshal(data, &cases); e != nil {
		t.Fatal(e)
	}
	if len(cases) < 100 {
		t.Fatal("incomplete parity corpus")
	}
	for i, c := range cases {
		p, e := Compile(c.Source, c.Kind, c.Full, 18734, 18735, `C:\OneTunnel\engines\xray.exe`)
		if e != nil {
			t.Fatalf("case %d kind %d full %v rejected", i, c.Kind, c.Full)
		}
		if p.NativeSource != c.NativeSource || p.NativeShadowsocks != c.NativeShadowsocks || p.NeedsXray != c.NeedsXray || p.AccurateTime != c.AccurateTime {
			t.Fatalf("case %d plan differs", i)
		}
		for _, pair := range [][2]string{{p.Proxy, string(c.Proxy)}, {p.Xray, string(c.Xray)}} {
			if pair[0] == "" && pair[1] == "null" {
				continue
			}
			var a, b any
			if json.Unmarshal([]byte(pair[0]), &a) != nil || json.Unmarshal([]byte(pair[1]), &b) != nil || !reflect.DeepEqual(a, b) {
				t.Fatalf("case %d generated configuration differs", i)
			}
		}
	}
	t.Logf("%d C# parity configurations passed", len(cases))
}
func TestRejectUnsafeAndMalformed(t *testing.T) {
	base := "vless://6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a@example.com:443?"
	for _, q := range []string{"type=quic", "type=ws&security=reality&pbk=test", "type=tcp&security=reality", "type=tcp&TYPE=ws", "type=kcp&seed=old", "type=ws&ed=-1", "security=tls&allowInsecure=true", "unknown=yes", "type=ws&flow=xtls-rprx-vision", "type=hysteria"} {
		if _, e := Compile(base+q, 2, true, 18734, 18735, "xray.exe"); e == nil {
			t.Fatalf("accepted %s", q)
		}
	}
	for _, source := range []string{`{"protocol":"vless","settings":{},"settings":{}}`, `{} garbage`, `{"settings":{"keyFile":"secret"}}`, strings.Repeat(`{"x":`, 50) + `{}` + strings.Repeat("}", 50)} {
		if _, e := Outbound(source, 2); e == nil {
			t.Fatal("accepted malformed JSON")
		}
	}
	for _, item := range []struct {
		kind   int
		source string
	}{{3, "socks5://host:0"}, {3, "socks5://host:1080?tls=true"}, {4, "hy2://auth@host?insecure=1"}, {5, "ss://aes-128-gcm:pass@host:443?plugin=bad"}, {1, "[Interface]\nPostUp=calc.exe"}} {
		if _, e := Compile(item.source, item.kind, true, 18734, 18735, "xray.exe"); e == nil {
			t.Fatal("accepted unsafe source")
		}
	}
}
func TestFullDeviceAndClockPolicy(t *testing.T) {
	p, e := Compile("ss://2022-blake3-aes-128-gcm:test@example.com:443", 5, true, 18734, 18735, "xray.exe")
	if e != nil || !p.AccurateTime || !p.NativeShadowsocks || p.NeedsXray {
		t.Fatal("SS2022 clock/native policy")
	}
	var config object
	json.Unmarshal([]byte(p.Proxy), &config)
	in := arr(config["inbounds"])
	tun := obj(in[1])
	if len(arr(tun["route_address"])) != 4 || tun["dns_mode"] != "hijack" || tun["strict_route"] != true || s(obj(config["dns"])["final"]) != "remote-dns" {
		t.Fatal("full device DNS/IPv6 policy lost")
	}
	if _, e := Compile("socks5://host:1080", 3, false, 0, 18735, "xray.exe"); e == nil {
		t.Fatal("invalid runtime port")
	}
}

func FuzzCompile(f *testing.F) {
	for _, seed := range []string{`{"protocol":"vless","settings":{"vnext":[null]}}`, `{"protocol":"shadowsocks","settings":{"servers":[{"address":[],"port":{},"method":true}]}}`, `ss://YWVzLTEyOC1nY206cGFzcw@host:443`, `socks5://user:pass@[::1]:1080`, `hy2://auth@host:443`, `[Interface]`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 131072 {
			t.Skip()
		}
		for kind := 0; kind < 6; kind++ {
			_, _ = Compile(source, kind, true, 18734, 18735, "xray.exe")
		}
	})
}
