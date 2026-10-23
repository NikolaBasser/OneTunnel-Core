package protocol

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func BenchmarkNativeSharedPolicyCompile(b *testing.B) {
	policy := &NetworkOptions{AllowLAN: true}
	for i := 0; i < MaxNetworkRules; i++ {
		policy.Rules = append(policy.Rules, NetworkRule{Kind: "domain", Value: fmt.Sprintf("host%d.example", i), Action: "proxy"})
	}
	source := nativePolicySource()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CompileWithNetwork(source, 1, true, 18101, 18102, "unused", nil, policy); err != nil {
			b.Fatal(err)
		}
	}
}

func nativePolicySource() string {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return "[Interface]\nPrivateKey = " + key + "\nAddress = 10.17.0.2/32\nDNS = 10.17.0.1\n[Peer]\nPublicKey = " + key + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n"
}

func TestNativeSharedPolicyPlanAndLegacyParity(t *testing.T) {
	for _, kind := range []int{0, 1} {
		source := nativePolicySource()
		if kind == 0 {
			source = strings.Replace(source, "[Peer]", "Jc = 3\nJmin = 10\nJmax = 30\nS1 = 21\nS2 = 22\nH1 = 100\nH2 = 101\nH3 = 102\nH4 = 103\n[Peer]", 1)
		}
		legacy, err := CompileWithOptions(source, kind, true, 18101, 18102, "unused", nil)
		if err != nil {
			t.Fatal(err)
		}
		empty, err := CompileWithNetwork(source, kind, true, 18101, 18102, "unused", nil, &NetworkOptions{})
		if err != nil || !reflect.DeepEqual(legacy, empty) {
			t.Fatal("empty policy changed native behavior")
		}
		policy := &NetworkOptions{AllowLAN: true, Rules: []NetworkRule{{Kind: "domain", Value: "example.com", Action: "reject"}}}
		plan, err := CompileWithNetwork(source, kind, true, 18101, 18102, "unused", nil, policy)
		if err != nil {
			t.Fatal(err)
		}
		if !plan.SharedNative || plan.NeedsXray || plan.LocalPort != 18101 || !strings.Contains(plan.NativeSource, "DNS = 10.17.0.1") || strings.Contains(plan.NativeSource, "::/0") {
			t.Fatal("shared topology or imported peer scope changed")
		}
		if kind == 0 && !strings.Contains(plan.NativeSource, "Jc = 3") {
			t.Fatal("AWG options lost")
		}
		config, err := decodeObject(plan.Proxy)
		if err != nil {
			t.Fatal(err)
		}
		out := obj(arr(config["outbounds"])[0])
		if len(out) != 2 || out["type"] != "onetunnel-native" || out["tag"] != "proxy" || strings.Contains(plan.Proxy, "PrivateKey") {
			t.Fatal("invalid typed outbound or leaked native config")
		}
		if _, err := CompileWithNetwork(source, kind, false, 18101, 18102, "unused", nil, policy); err == nil {
			t.Fatal("local policy accepted")
		}
	}
}

func TestNativePolicyResolverCoverageFailsClosed(t *testing.T) {
	source := strings.Replace(nativePolicySource(), "0.0.0.0/0", "10.0.0.0/8", 1)
	if _, err := CompileWithNetwork(source, 1, true, 18101, 18102, "unused", nil, &NetworkOptions{AllowLAN: true}); err == nil {
		t.Fatal("uncovered default resolver accepted")
	}
	policy := &NetworkOptions{DNS: &DNSOptions{Transport: "tls", ServerIP: "10.17.0.1", ServerName: "dns.example"}}
	plan, err := CompileWithNetwork(source, 1, true, 18101, 18102, "unused", nil, policy)
	if err != nil || !strings.Contains(plan.NativeSource, "10.0.0.0/8") {
		t.Fatal("covered resolver failed or AllowedIPs expanded", err)
	}
	policy.DNS.ServerIP = "2606:4700:4700::1111"
	if _, err := CompileWithNetwork(nativePolicySource(), 1, true, 18101, 18102, "unused", nil, policy); err == nil {
		t.Fatal("missing IPv6 family accepted")
	}
}

func TestNativePolicyPreservesValidInlineComments(t *testing.T) {
	source := strings.Replace(nativePolicySource(), "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0 # imported peer scope", 1)
	if _, err := CompileWithNetwork(source, 1, true, 18101, 18102, "unused", nil, &NetworkOptions{AllowLAN: true}); err != nil {
		t.Fatal("valid native comments rejected", err)
	}
}
