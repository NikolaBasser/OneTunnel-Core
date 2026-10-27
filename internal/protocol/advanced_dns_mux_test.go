package protocol

import (
	"encoding/json"
	"testing"
)

func TestAdvancedDNSCompileAndClone(t *testing.T) {
	for _, transport := range []string{"quic", "h3"} {
		options := &NetworkOptions{DNS: &DNSOptions{Transport: transport, ServerIP: "1.1.1.1", ServerName: "dns.example"}, FakeIP: true, DNSCache: &DNSCacheOptions{Capacity: 512}, Resolvers: []DNSOptions{{Transport: "tls", ServerIP: "8.8.8.8", ServerName: "dns.google"}}, DNSRules: []DNSRule{{Kind: "domain", Value: "real.example", ResolverIndex: 0}}}
		normalized, err := NormalizeNetworkOptions(options)
		if err != nil {
			t.Fatal(err)
		}
		wantPort := 853
		if transport == "h3" {
			wantPort = 443
		}
		if normalized.DNS.Port != wantPort || transport == "h3" && normalized.DNS.Path != "/dns-query" {
			t.Fatal("incorrect DNS defaults")
		}
		cloned := CloneNetworkOptions(normalized)
		cloned.DNSCache.Capacity = 1024
		if normalized.DNSCache.Capacity != 512 || NetworkOptionsEquivalent(normalized, cloned) {
			t.Fatal("cache preferences aliased or ignored")
		}
		plan, err := CompileWithNetwork("socks5://127.0.0.1:18080", 3, true, 18001, 18002, "", nil, options)
		if err != nil {
			t.Fatal(err)
		}
		config, err := decodeObject(plan.Proxy)
		if err != nil {
			t.Fatal(err)
		}
		dns := obj(config["dns"])
		if obj(arr(dns["servers"])[2])["inet6_range"] != "fc00::/112" {
			t.Fatal("unbounded FakeIPv6 memory pool")
		}
		rules := arr(dns["rules"])
		if len(arr(dns["servers"])) != 3 || dns["cache_capacity"].(json.Number).String() != "512" || dns["final"] != "remote-dns" || obj(config["route"])["default_domain_resolver"] != "remote-dns" || obj(rules[len(rules)-1])["server"] != "onetunnel-fakeip" || obj(rules[0])["server"] != "onetunnel-policy-dns-0" {
			t.Fatal("DNS policy/default resolver precedence lost")
		}
	}
	for _, bad := range []*NetworkOptions{
		{DNSCache: &DNSCacheOptions{Capacity: 127}}, {DNSCache: &DNSCacheOptions{Capacity: 65537}},
		{DNS: &DNSOptions{Transport: "quic", ServerIP: "1.1.1.1", ServerName: "dns.example", Path: "/bad"}},
		{DNS: &DNSOptions{Transport: "h3", ServerIP: "1.1.1.1", ServerName: "dns.example", Path: "//bad"}},
	} {
		if _, err := NormalizeNetworkOptions(bad); err == nil {
			t.Fatal("invalid DNS options accepted")
		}
	}
}

func TestAdvancedMultiplexCompilation(t *testing.T) {
	for _, mode := range []string{"h2mux", "smux", "yamux"} {
		options := transportDefaults()
		options.Mux = true
		options.MuxProtocol = mode
		options.MuxPadding = true
		options.MuxMaxConnections = 1
		plan, err := CompileWithOptions("ss://chacha20-ietf-poly1305:fixture@127.0.0.1:18080", 5, false, 18001, 18002, "", options)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := decodeObject(plan.Proxy)
		mux := obj(one(c["outbounds"])["multiplex"])
		if mux["protocol"] != mode || mux["padding"] != true || plan.NeedsXray {
			t.Fatal("native mux configuration missing")
		}
		if mux["max_streams"] != nil {
			t.Fatal("inactive stream policy emitted beside connection policy")
		}
		if _, err = CompileWithOptions(optionVless, 2, false, 18001, 18002, "", options); err == nil {
			t.Fatal("sing mux accepted for Xray")
		}
		options.XUDPConcurrency = 2
		if _, err = CompileWithOptions("ss://chacha20-ietf-poly1305:fixture@127.0.0.1:18080", 5, false, 18001, 18002, "", options); err == nil {
			t.Fatal("XUDP silently ignored for sing mux")
		}
	}
	options := transportDefaults()
	options.Mux = true
	options.XUDPConcurrency = 4
	options.UDP443Policy = "reject"
	p, err := CompileWithOptions(optionVless, 2, false, 18001, 18002, "", options)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := decodeObject(p.Xray)
	mux := obj(one(c["outbounds"])["mux"])
	if mux["xudpConcurrency"].(json.Number).String() != "4" || mux["xudpProxyUDP443"] != "reject" {
		t.Fatal("XUDP options missing")
	}
	for _, change := range []func(*TransportOptions){func(o *TransportOptions) { o.XUDPConcurrency = 129 }, func(o *TransportOptions) { o.UDP443Policy = "direct" }, func(o *TransportOptions) { o.MuxProtocol = "unknown" }, func(o *TransportOptions) { o.MuxMaxConnections = 33 }, func(o *TransportOptions) { o.MuxMinStreams = 129 }} {
		bad := *options
		change(&bad)
		if ValidateOptions(optionVless, 2, &bad) == nil {
			t.Fatal("unbounded mux option accepted")
		}
	}
}
