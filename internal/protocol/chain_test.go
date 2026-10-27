package protocol

import (
	"encoding/json"
	"testing"
)

func TestProxyChainCompileAndCycleValidation(t *testing.T) {
	n := &NetworkOptions{Targets: []PolicyTarget{{Name: "exit", Protocol: 6, Source: "http://127.0.0.1:18082", Via: " Middle "}, {Name: "middle", Protocol: 3, Source: "socks5://127.0.0.1:18081", Via: " @PRIMARY "}}, Rules: []NetworkRule{{Kind: "domain", Value: "example.com", Action: "proxy", Outbound: "exit"}}}
	plan, err := CompileWithNetwork("socks5://127.0.0.1:18080", 3, true, 18001, 18002, "unused", nil, n)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if json.Unmarshal([]byte(plan.Proxy), &config) != nil {
		t.Fatal("invalid compiled JSON")
	}
	outs := map[string]map[string]any{}
	for _, raw := range config["outbounds"].([]any) {
		out := raw.(map[string]any)
		outs[out["tag"].(string)] = out
	}
	if outs["onetunnel-target-exit"]["detour"] != "onetunnel-target-middle" || outs["onetunnel-target-middle"]["detour"] != "proxy" {
		t.Fatal("chain links missing")
	}
	if n.Targets[0].Via != " Middle " {
		t.Fatal("normalization mutated saved options")
	}
	for _, via := range []string{"exit", "missing", "direct", "proxy"} {
		bad := CloneNetworkOptions(n)
		bad.Targets[1].Via = via
		if _, err := NormalizeNetworkOptions(bad); err == nil {
			t.Fatalf("invalid link accepted: %s", via)
		}
	}
	bad := CloneNetworkOptions(n)
	bad.Targets[0].Via = "exit"
	if _, err := NormalizeNetworkOptions(bad); err == nil {
		t.Fatal("self-cycle accepted")
	}
}

func TestProxyChainLegacyTargetsStayDirect(t *testing.T) {
	n := policyFixture()
	plan, err := CompileWithNetwork("socks5://127.0.0.1:18081", 3, true, 18001, 18002, "unused", nil, n)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	_ = json.Unmarshal([]byte(plan.Proxy), &c)
	for _, raw := range c["outbounds"].([]any) {
		out := raw.(map[string]any)
		if out["tag"] == "onetunnel-target-work" && out["detour"] != nil {
			t.Fatal("legacy target silently chained")
		}
	}
}
