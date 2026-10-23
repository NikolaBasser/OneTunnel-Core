package platform

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestNetworkPolicyProfileCheckIsConfigOnly(t *testing.T) {
	runtime := &Runtime{root: t.TempDir()}
	profile := &control.Profile{ID: "11111111-1111-4111-8111-111111111111", Name: "synthetic", Group: "manual", Protocol: 2,
		Source:  "vless://6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a@127.0.0.1:443?security=tls&sni=localhost",
		Network: &protocol.NetworkOptions{DNS: &protocol.DNSOptions{Transport: "tls", ServerIP: "8.8.8.8", ServerName: "dns.example"}, Rules: []protocol.NetworkRule{{Kind: "cidr", Value: "192.0.2.0/24", Action: "direct"}}}}
	result, err := runtime.checkProfile(context.Background(), profile)
	if err != nil || result == nil {
		t.Fatalf("check: %v %v", result, err)
	}
	var check control.ProfileCheck
	if err := json.Unmarshal([]byte(*result), &check); err != nil {
		t.Fatal(err)
	}
	if !check.Success || check.NetworkTest || check.Milliseconds < 0 || check.Message == "" {
		t.Fatalf("policy profile was not config-only: %+v", check)
	}
}
