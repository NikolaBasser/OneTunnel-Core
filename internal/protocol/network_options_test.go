package protocol

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestNetworkOptionsNormalizeAndCompile(t *testing.T) {
	options := &NetworkOptions{DNS: &DNSOptions{Transport: " HTTPS ", ServerIP: "1.1.1.1", ServerName: "DNS.Example.COM."}, Rules: []NetworkRule{
		{Kind: " DOMAIN ", Action: " PROXY ", Value: "Example.COM."},
		{Kind: "CIDR", Action: " DIRECT ", Value: "10.2.3.4/8"},
		{Kind: "PROCESS", Action: " REJECT ", Value: `C:\Windows\System32\blocked.EXE`},
		{Kind: "cidr", Action: "proxy", Value: "0.0.0.0/0"},
	}}
	normalized, err := NormalizeNetworkOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.DNS.Port != 443 || normalized.DNS.Path != "/dns-query" || normalized.DNS.ServerName != "dns.example.com" || normalized.Rules[0].Value != "example.com" || normalized.Rules[1].Value != "10.0.0.0/8" || normalized.Rules[2].Value != `c:\windows\system32\blocked.exe` {
		t.Fatalf("unexpected normalization: %+v", normalized)
	}
	legacy, err := CompileWithOptions(optionVless, 2, true, 18100, 18101, "xray.exe", nil)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := CompileWithNetwork(optionVless, 2, true, 18100, 18101, "xray.exe", nil, nil)
	if err != nil || !reflect.DeepEqual(legacy, unchanged) {
		t.Fatal("nil policy changed legacy output")
	}
	plan, err := CompileWithNetwork(optionVless, 2, true, 18100, 18101, "xray.exe", nil, normalized)
	if err != nil {
		t.Fatal(err)
	}
	rawPlan, err := CompileWithNetwork(optionVless, 2, true, 18100, 18101, "xray.exe", nil, options)
	if err != nil || !reflect.DeepEqual(plan, rawPlan) {
		t.Fatalf("raw policy bypassed normalization: %v", err)
	}
	config, err := decodeObject(plan.Proxy)
	if err != nil {
		t.Fatal(err)
	}
	dns := obj(config["dns"])
	server := obj(arr(dns["servers"])[0])
	if server["type"] != "https" || server["server"] != "1.1.1.1" || n(server["server_port"]) != 443 || server["path"] != "/dns-query" || dns["reverse_mapping"] != true {
		t.Fatalf("custom DNS missing: %v", dns)
	}
	rules := arr(obj(config["route"])["rules"])
	if len(rules) != 8 {
		t.Fatalf("infrastructure/user rules order: %v", rules)
	}
	infraRegex := s(arr(obj(rules[0])["process_path_regex"])[0])
	if infraRegex != `(?i)^xray\.exe$` || obj(rules[1])["inbound"] == nil || obj(rules[2])["port"] == nil || obj(rules[3])["protocol"] == nil || obj(rules[4])["domain"] == nil || obj(rules[5])["ip_cidr"] == nil || obj(rules[6])["process_path_regex"] == nil || obj(rules[7])["ip_cidr"] == nil {
		t.Fatalf("unexpected routing order: %v", rules)
	}
	if matched, _ := regexp.MatchString(infraRegex, "XrAy.EXE"); !matched {
		t.Fatal("embedded engine identity regex lost Windows case-insensitive matching")
	}
	if obj(rules[4])["action"] != "route" || obj(rules[4])["outbound"] != "proxy" || obj(rules[5])["outbound"] != "direct" || obj(rules[6])["action"] != "reject" {
		t.Fatalf("user action compile mismatch: %v", rules)
	}
	if len(arr(config["outbounds"])) != 3 || obj(arr(config["outbounds"])[2])["tag"] != "direct" {
		t.Fatal("direct outbound not added explicitly")
	}
	if _, err := CompileWithNetwork(optionVless, 2, false, 18100, 18101, "xray.exe", nil, normalized); err == nil {
		t.Fatal("local mode accepted policy")
	}
	rulesOnly, err := CompileWithNetwork(optionVless, 2, true, 18100, 18101, "xray.exe", nil, &NetworkOptions{Rules: []NetworkRule{{Kind: "domain", Action: "proxy", Value: "example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	defaultDNS, _ := decodeObject(rulesOnly.Proxy)
	if obj(defaultDNS["dns"])["reverse_mapping"] != true {
		t.Fatal("rules-only domain matching did not enable reverse mapping")
	}
}

func TestNetworkOptionsValidationBoundaries(t *testing.T) {
	validDNS := &DNSOptions{Transport: "https", ServerIP: "1.1.1.1", ServerName: "dns.example"}
	for _, path := range []string{"//host/path", "/../dns", "/dns?q=x", "/dns#x", "/https:%2f%2fhost", "/dns%2f.."} {
		options := &NetworkOptions{DNS: DNSOptionsPtr(validDNS)}
		options.DNS.Path = path
		if _, err := NormalizeNetworkOptions(options); err == nil {
			t.Errorf("accepted unsafe DNS path %q", path)
		}
	}
	for _, path := range []string{`C:relative.exe`, `\\server\share\a.exe`, `\\?\C:\a.exe`, `C:\a\..\x.exe`, `C:\a\b.exe:stream`, `C:\%APP%\a.exe`, `C:\a\*.exe`, `C:\a\b.txt`, `C:\Windows.\app.exe`, `C:\Windows \app.exe`, ` C:\Windows\app.exe`} {
		if _, ok := normalizeProcessPath(path); ok {
			t.Errorf("accepted process path %q", path)
		}
	}
	for _, rule := range []NetworkRule{{"domain", "*.example.com", "proxy"}, {"domain", "https://example.com", "proxy"}, {"cidr", "fe80::1%1/64", "direct"}, {"domain-suffix", "münich.example", "direct"}, {"process", `C:\a.exe`, "oops"}, {"process", ` C:\Windows\app.exe`, "reject"}} {
		if _, err := NormalizeNetworkOptions(&NetworkOptions{Rules: []NetworkRule{rule}}); err == nil {
			t.Errorf("accepted invalid rule %+v", rule)
		}
	}
	tooMany := make([]NetworkRule, MaxNetworkRules+1)
	for i := range tooMany {
		tooMany[i] = NetworkRule{Kind: "domain", Action: "proxy", Value: "example.com"}
	}
	if _, err := NormalizeNetworkOptions(&NetworkOptions{Rules: tooMany}); err == nil {
		t.Fatal("accepted over-limit rules")
	}
	if got, err := NormalizeNetworkOptions(&NetworkOptions{DNS: validDNS}); err != nil || got.DNS.Port != 443 || got.DNS.Path != "/dns-query" {
		t.Fatal("DoH defaults missing")
	}
	if got, err := NormalizeNetworkOptions(&NetworkOptions{DNS: &DNSOptions{Transport: "tls", ServerIP: "8.8.8.8", ServerName: "dns.example"}}); err != nil || got.DNS.Port != 853 || got.DNS.Path != "" {
		t.Fatal("DoT defaults missing")
	}
}

func TestNetworkOptionsProfileJSONAndPrivacy(t *testing.T) {
	profile := struct {
		Network *NetworkOptions `json:"Network,omitempty"`
	}{&NetworkOptions{Rules: []NetworkRule{{Kind: "domain", Action: "proxy", Value: "synthetic.example"}}}}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"Network"`) || !strings.Contains(string(data), "synthetic.example") {
		t.Fatal("network policy did not serialize")
	}
	if _, err := CompileWithNetwork(optionVless, 2, true, 18100, 18101, "xray.exe", nil, profile.Network); err != nil {
		t.Fatal("routing-only policy rejected:", err)
	}
}

func TestNetworkPolicyCompilesForEveryProxyProtocol(t *testing.T) {
	cases := []struct {
		kind   int
		source string
	}{
		{2, optionVless}, {3, "socks5://127.0.0.1:1080"}, {4, "hy2://test@127.0.0.1:443?sni=localhost"},
		{5, "ss://aes-128-gcm:synthetic@127.0.0.1:443"}, {HTTP, "http://user:synthetic@127.0.0.1:8080"},
		{Trojan, "trojan://synthetic@127.0.0.1:443?sni=localhost"},
		{TUIC, "tuic://11111111-1111-4111-8111-111111111111:synthetic@127.0.0.1:443?congestion_control=bbr&udp_relay_mode=quic"},
		{AnyTLS, "anytls://synthetic@127.0.0.1:443"}, {Naive, "naive+https://user:synthetic@127.0.0.1:443"},
	}
	policy := &NetworkOptions{Rules: []NetworkRule{{Kind: "domain-suffix", Value: "example.com", Action: "proxy"}}}
	for _, item := range cases {
		plan, err := CompileWithNetwork(item.source, item.kind, true, 18100, 18101, "xray.exe", nil, policy)
		if err != nil || plan.Proxy == "" {
			t.Errorf("protocol %d policy not compiled: %v", item.kind, err)
		}
	}
	for _, kind := range []int{0, 1} {
		if ValidateNetworkOptions(policy, kind, true) == nil {
			t.Errorf("native protocol %d accepted proxy policy", kind)
		}
	}
}

func DNSOptionsPtr(options *DNSOptions) *DNSOptions { copy := *options; return &copy }

func BenchmarkNetworkNormalizeCompile64Rules(b *testing.B) {
	rules := make([]NetworkRule, MaxNetworkRules)
	for i := range rules {
		rules[i] = NetworkRule{Kind: "domain-suffix", Action: "proxy", Value: "example.com"}
	}
	options := &NetworkOptions{DNS: &DNSOptions{Transport: "https", ServerIP: "1.1.1.1", ServerName: "dns.example"}, Rules: rules}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := CompileWithNetwork(optionVless, 2, true, 18100, 18101, "xray.exe", nil, options); err != nil {
			b.Fatal(err)
		}
	}
}
