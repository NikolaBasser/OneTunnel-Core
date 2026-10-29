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

func TestNativePolicyRuntimeCopyExpandsRoutes(t *testing.T) {
	source := strings.Replace(nativePolicySource(), "0.0.0.0/0", "10.0.0.0/8", 1)
	if p, err := CompileWithNetwork(source, 1, true, 18101, 18102, "unused", nil, &NetworkOptions{AllowLAN: true}); err != nil || !strings.Contains(p.NativeSource, "AllowedIPs = 0.0.0.0/0") {
		t.Fatal("runtime copy did not expand for policy DNS", err)
	}
	policy := &NetworkOptions{DNS: &DNSOptions{Transport: "tls", ServerIP: "10.17.0.1", ServerName: "dns.example"}}
	plan, err := CompileWithNetwork(source, 1, true, 18101, 18102, "unused", nil, policy)
	if err != nil || !strings.Contains(plan.NativeSource, "0.0.0.0/0") || !strings.Contains(source, "10.0.0.0/8") {
		t.Fatal("runtime copy or original source incorrect", err)
	}
	policy.DNS.ServerIP = "2606:4700:4700::1111"
	if _, err := CompileWithNetwork(nativePolicySource(), 1, true, 18101, 18102, "unused", nil, policy); err == nil {
		t.Fatal("missing IPv6 family accepted")
	}
}

func TestNativeRoutingCopyPreservesOriginalAndFamilies(t *testing.T) {
	for _, kind := range []int{0, 1} {
		for _, entry := range []struct{ address, routes string }{{"10.17.0.2/32", "0.0.0.0/0"}, {"fd00::2/128", "::/0"}, {"10.17.0.2/32, fd00::2/128", "0.0.0.0/0, ::/0"}} {
			source := strings.Replace(nativePolicySource(), "Address = 10.17.0.2/32", "Address = "+entry.address, 1)
			source = strings.ReplaceAll(strings.Replace(source, "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 172.16.0.0/24", 1), "DNS = 10.17.0.1\n", "")
			if kind == 0 {
				source = strings.Replace(source, "[Peer]", "Jc = 3\nJmin = 10\nJmax = 30\n[Peer]", 1)
			}
			full, err := FullNativeRoutingSource(source, kind)
			if err != nil || !strings.Contains(full, "AllowedIPs = "+entry.routes) {
				t.Fatal("families", kind, entry, err)
			}
			legacy, err := CompileWithOptions(source, kind, false, 18101, 18102, "unused", nil)
			if err != nil || legacy.NativeSource != strings.TrimSpace(source) {
				t.Fatal("AllowedIPs mode changed imported source", err)
			}
			if !strings.Contains(source, "AllowedIPs = 172.16.0.0/24") || strings.Replace(full, "AllowedIPs = "+entry.routes, "AllowedIPs = 172.16.0.0/24", 1) != strings.TrimSpace(source) {
				t.Fatal("keys, endpoint or AWG options changed")
			}
		}
	}
}

func TestNativePolicyPreservesValidInlineComments(t *testing.T) {
	source := strings.Replace(nativePolicySource(), "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0 # imported peer scope", 1)
	if _, err := CompileWithNetwork(source, 1, true, 18101, 18102, "unused", nil, &NetworkOptions{AllowLAN: true}); err != nil {
		t.Fatal("valid native comments rejected", err)
	}
}

func TestNativeRuntimeCopyKeepsMultiPeerOwnership(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	source := nativePolicySource() + "[Peer] # private peer\nPublicKey = " + key + "\nEndpoint = 192.0.2.2:51820\nAllowedIPs = 10.20.0.0/16\n"
	copy, err := FullNativeRoutingSource(source, 1)
	if err != nil || copy != strings.TrimSpace(source) {
		t.Fatal("existing default peer ownership changed", err)
	}
	narrow := strings.Replace(source, "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 172.16.0.0/24", 1)
	if _, err = FullNativeRoutingSource(narrow, 1); err == nil {
		t.Fatal("ambiguous default assigned to multiple peers")
	}
}
