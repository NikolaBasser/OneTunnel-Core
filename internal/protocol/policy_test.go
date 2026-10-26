package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func policyFixture() *NetworkOptions {
	return &NetworkOptions{
		Targets:  []PolicyTarget{{Name: "work", Protocol: 3, Source: "socks5://127.0.0.1:18080"}},
		RuleSets: []RuleSet{{Name: "work-sites", Members: []NetworkRule{{Kind: "domain-suffix", Value: "example.com"}, {Kind: "cidr", Value: "203.0.113.0/24"}}}},
		Rules:    []NetworkRule{{Kind: "rule-set", Value: "work-sites", Action: "proxy", Outbound: "work", Network: "tcp", Port: "443", Process: `C:\Apps\Browser.exe`}, {Kind: "network", Value: "udp", Action: "reject"}},
	}
}
func TestPolicyCompileAndPredict(t *testing.T) {
	n := policyFixture()
	p, e := CompileWithNetwork("socks5://127.0.0.1:18081", 3, true, 18001, 18002, "unused", nil, n)
	if e != nil {
		t.Fatal(e)
	}
	var c map[string]any
	if json.Unmarshal([]byte(p.Proxy), &c) != nil {
		t.Fatal("bad config")
	}
	if !strings.Contains(p.Proxy, `"outbound":"onetunnel-target-work"`) || !strings.Contains(p.Proxy, `"rule_set":["onetunnel-set-work-sites"]`) {
		t.Fatal("missing compiled reference")
	}
	for _, tc := range []struct {
		q             RouteQuery
		decision, out string
		rule          int
	}{
		{RouteQuery{Domain: "api.example.com", IP: "198.51.100.2", Process: `C:\Apps\Browser.exe`, Network: "tcp", Port: 443}, "proxy", "work", 0},
		{RouteQuery{Domain: "else.test", IP: "203.0.113.1", Process: `C:\Apps\Browser.exe`, Network: "tcp", Port: 443}, "proxy", "work", 0},
		{RouteQuery{Domain: "api.example.com", IP: "198.51.100.2", Process: `C:\Apps\Other.exe`, Network: "tcp", Port: 443}, "proxy", "proxy", -1},
		{RouteQuery{Network: "udp", Port: 443}, "reject", "reject", 1},
		{RouteQuery{Network: "tcp", Port: 443}, "unknown", "", 0},
		{RouteQuery{Network: "udp", Port: 53}, "dns", "configured-resolver", -1},
	} {
		v, e := ExplainRoute(n, tc.q)
		if e != nil || v.Decision != tc.decision || v.Outbound != tc.out || v.Rule != tc.rule || !v.PredictionOnly {
			t.Fatalf("prediction=%+v error=%v", v, e)
		}
	}
	copy := CloneNetworkOptions(n)
	copy.RuleSets[0].Members[0].Value = "changed.test"
	copy.Targets[0].Source = "changed"
	if n.RuleSets[0].Members[0].Value != "example.com" || n.Targets[0].Source == "changed" {
		t.Fatal("clone aliases secret policy")
	}
	if NetworkOptionsEquivalent(n, copy) {
		t.Fatal("different policies considered compatible")
	}
}
func TestPolicyRejectsUnsafeOrUnresolvedInput(t *testing.T) {
	cases := []func(*NetworkOptions){
		func(n *NetworkOptions) { n.Targets = append(n.Targets, n.Targets[0]) },
		func(n *NetworkOptions) { n.Targets[0].Name = "proxy"; n.Rules[0].Outbound = "missing" },
		func(n *NetworkOptions) { n.Targets[0].Source = "socks5://bad" },
		func(n *NetworkOptions) { n.Targets[0].Protocol = 0 },
		func(n *NetworkOptions) { n.Rules[0].Port = "443-1" },
		func(n *NetworkOptions) { n.Rules[0].Port = "0" },
		func(n *NetworkOptions) { n.Rules[0].Network = "icmp" },
		func(n *NetworkOptions) { n.Rules[0].Process = `\\server\a.exe` },
		func(n *NetworkOptions) { n.Rules[0].Value = "missing" },
		func(n *NetworkOptions) { n.Rules[0].Action = "direct" },
		func(n *NetworkOptions) { n.RuleSets[0].Members[0].Kind = "rule-set" },
		func(n *NetworkOptions) { n.RuleSets[0].Members[0].Action = "direct" },
		func(n *NetworkOptions) { n.RuleSets[0].Members = nil },
		func(n *NetworkOptions) { n.RuleSets = append(n.RuleSets, n.RuleSets[0]) },
		func(n *NetworkOptions) { n.Targets = make([]PolicyTarget, MaxPolicyTargets+1) },
		func(n *NetworkOptions) { n.RuleSets[0].Members = make([]NetworkRule, MaxRuleSetMembers+1) },
	}
	for i, change := range cases {
		n := policyFixture()
		change(n)
		if _, e := NormalizeNetworkOptions(n); e == nil {
			t.Fatalf("accepted unsafe case %d", i)
		}
	}
}
func TestPolicyAnalysisDoesNotExposeCredentials(t *testing.T) {
	n := policyFixture()
	n.Targets[0].Source = "socks5://user:secret@127.0.0.1:18080"
	n.Rules = append(n.Rules, n.Rules[0])
	a, e := AnalyzeNetwork(n)
	if e != nil || len(a.Warnings) != 1 || a.Warnings[0].Rule != 2 {
		t.Fatalf("analysis=%+v error=%v", a, e)
	}
	data, _ := json.Marshal(a)
	if strings.Contains(string(data), "secret") || strings.Contains(string(data), "127.0.0.1") {
		t.Fatal("analysis leaked target")
	}
}

func TestPolicyAdditionalTargetEngines(t *testing.T) {
	for _, source := range []string{
		"socks5://127.0.0.1:1080",
		"http://user:password@127.0.0.1:8080",
		"ss://YWVzLTEyOC1nY206c2VjcmV0@127.0.0.1:8388",
		"trojan://secret@127.0.0.1:443?sni=example.com",
		"tuic://11111111-1111-4111-8111-111111111111:secret@127.0.0.1:443",
		"anytls://secret@127.0.0.1:443?sni=example.com",
		"naive+https://user:secret@127.0.0.1:443",
	} {
		n := policyFixture()
		n.Targets[0] = PolicyTarget{Name: "work", Protocol: LinkKind(source), Source: source}
		if _, err := CompileWithNetwork("socks5://127.0.0.1:18081", 3, true, 18001, 18002, "unused", nil, n); err != nil {
			t.Fatalf("target kind %d: %v", n.Targets[0].Protocol, err)
		}
	}
	n := policyFixture()
	n.Targets[0] = PolicyTarget{Name: "work", Protocol: 2, Source: optionVless}
	if _, err := NormalizeNetworkOptions(n); err == nil || !strings.Contains(err.Error(), "policy_target_requires_separate_engine") {
		t.Fatal("missing explicit separate-engine rejection", err)
	}
}
