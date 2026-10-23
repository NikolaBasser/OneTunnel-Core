package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func transportDefaults() *TransportOptions {
	return &TransportOptions{FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20", MuxConcurrency: 8}
}

const optionVless = "vless://6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a@127.0.0.1:443?security=tls&sni=localhost"

func TestTransportOptions(t *testing.T) {
	imported, _ := Outbound(optionVless, 2)
	imported["mux"] = object{"enabled": true, "concurrency": 8}
	encoded, _ := json.Marshal(imported)
	cleared, err := CompileWithOptions(string(encoded), 2, false, 18100, 18101, "xray.exe", transportDefaults())
	if err != nil {
		t.Fatal(err)
	}
	cx, _ := decodeObject(cleared.Xray)
	if obj(one(cx["outbounds"])["mux"])["enabled"] == true {
		t.Fatal("explicit off failed to disable imported MUX")
	}
	for _, full := range []bool{false, true} {
		plain, e := Compile(optionVless, 2, full, 18100, 18101, "xray.exe")
		if e != nil {
			t.Fatal(e)
		}
		off, e := CompileWithOptions(optionVless, 2, full, 18100, 18101, "xray.exe", transportDefaults())
		if e != nil || !reflect.DeepEqual(plain, off) {
			t.Fatal("off changes legacy configuration")
		}
		o := transportDefaults()
		o.Fragment = true
		o.Mux = true
		p, e := CompileWithOptions(optionVless, 2, full, 18100, 18101, "xray.exe", o)
		if e != nil {
			t.Fatal(e)
		}
		x, _ := decodeObject(p.Xray)
		outs := arr(x["outbounds"])
		if len(outs) != 2 || s(obj(outs[0])["protocol"]) != "vless" || s(obj(outs[1])["tag"]) != "onetunnel-transport" || s(obj(obj(obj(outs[0])["streamSettings"])["sockopt"])["dialerProxy"]) != "onetunnel-transport" || obj(obj(outs[0])["mux"])["enabled"] != true {
			t.Fatal("missing isolated transport dialer or mux")
		}
		if p.Proxy != plain.Proxy {
			t.Fatal("transport options changed DNS/routing/bridge")
		}
	}
	cases := []struct {
		source string
		kind   int
		change func(*TransportOptions)
	}{
		{optionVless, 2, func(o *TransportOptions) { o.Noise = true }},
		{optionVless + "&flow=xtls-rprx-vision", 2, func(o *TransportOptions) { o.Mux = true }},
		{optionVless + "&type=xhttp", 2, func(o *TransportOptions) { o.Mux = true }},
		{"hy2://test@127.0.0.1:443?sni=localhost", 4, func(o *TransportOptions) { o.Fragment = true }},
		{"socks5://127.0.0.1:1080", 3, func(o *TransportOptions) { o.Mux = true }},
		{optionVless, 2, func(o *TransportOptions) { o.FragmentLength = "200-100" }},
		{optionVless, 2, func(o *TransportOptions) { o.NoiseLength = "1-999999999" }},
		{optionVless, 2, func(o *TransportOptions) { o.MuxConcurrency = 129 }},
		{optionVless, 2, func(o *TransportOptions) { o.FragmentInterval = "-1" }},
	}
	for i, c := range cases {
		o := transportDefaults()
		c.change(o)
		if _, e := CompileWithOptions(c.source, c.kind, false, 18100, 18101, "xray.exe", o); e == nil {
			t.Fatalf("accepted invalid options %d", i)
		}
	}
	o := transportDefaults()
	o.Noise = true
	p, e := CompileWithOptions("hy2://test@127.0.0.1:443?sni=localhost", 4, false, 18100, 18101, "xray.exe", o)
	if e != nil {
		t.Fatal(e)
	}
	x, _ := decodeObject(p.Xray)
	if len(arr(obj(obj(arr(x["outbounds"])[1])["settings"])["noises"])) != 1 {
		t.Fatal("missing UDP noise")
	}
}
