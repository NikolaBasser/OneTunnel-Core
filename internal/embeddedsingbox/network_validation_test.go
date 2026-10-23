package embeddedsingbox

import (
	"encoding/json"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"github.com/sagernet/sing-box/adapter"
	boxrule "github.com/sagernet/sing-box/route/rule"
)

func TestValidateCustomDoTWithoutStartingEngine(t *testing.T) {
	plan, err := protocol.CompileWithNetwork("vless://6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a@127.0.0.1:443?security=tls&sni=localhost", 2, true, 18001, 18002, "C:\\OneTunnel\\xray.exe", nil,
		&protocol.NetworkOptions{DNS: &protocol.DNSOptions{Transport: "tls", ServerIP: "8.8.8.8", ServerName: "dns.example"}, Rules: []protocol.NetworkRule{
			{Kind: "domain-suffix", Value: "example.com", Action: "proxy"},
			{Kind: "cidr", Value: "0.0.0.0/0", Action: "direct"},
			{Kind: "process", Value: `C:\Windows\System32\blocked.exe`, Action: "reject"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(plan.Proxy), &config); err != nil {
		t.Fatal(err)
	}
	// Validate the generated full-device policy without registering or starting TUN.
	inbounds := config["inbounds"].([]any)
	config["inbounds"] = inbounds[:1]
	route := config["route"].(map[string]any)
	rules := route["rules"].([]any)
	route["rules"] = rules[4:]
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data); err != nil {
		t.Fatalf("embedded network-free DoT validation failed: %v", err)
	}
}

func TestGeneratedProcessRegexUsesWindowsCaseInsensitiveExactPath(t *testing.T) {
	plan, err := protocol.CompileWithNetwork("vless://6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a@127.0.0.1:443?security=tls&sni=localhost", 2, true, 18001, 18002, "C:\\Program Files\\OneTunnel\\xray.exe", nil, &protocol.NetworkOptions{Rules: []protocol.NetworkRule{{Kind: "process", Value: `C:\Windows\System32\blocked.exe`, Action: "reject"}}})
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(plan.Proxy), &config); err != nil {
		t.Fatal(err)
	}
	routes := config["route"].(map[string]any)["rules"].([]any)
	infra := routes[0].(map[string]any)["process_path_regex"].([]any)[0].(string)
	process := routes[4].(map[string]any)["process_path_regex"].([]any)[0].(string)
	for _, test := range []struct {
		pattern, path string
		want          bool
	}{
		{infra, `c:\PROGRAM FILES\ONETUNNEL\XRAY.EXE`, true},
		{process, `c:\WINDOWS\system32\BLOCKED.EXE`, true},
		{process, `c:\WINDOWS\system32\other.exe`, false},
	} {
		matcher, err := boxrule.NewProcessPathRegexItem([]string{test.pattern})
		if err != nil {
			t.Fatal(err)
		}
		metadata := &adapter.InboundContext{ProcessInfo: &adapter.ConnectionOwner{ProcessPath: test.path}}
		if got := matcher.Match(metadata); got != test.want {
			t.Fatalf("%q matched %q=%v, want %v", test.pattern, test.path, got, test.want)
		}
	}
}
