package control

import (
	"context"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestManagerTracksBackendFallbackIdentity(t *testing.T) {
	m, all := fakeManager(t)
	reply := m.Dispatch(context.Background(), start())
	if reply.Error != nil {
		t.Fatal(reply.Error)
	}
	id := "33333333-3333-4333-8333-333333333333"
	(*all)[0].update(State{Active: true, TrafficLocked: true, ProfileID: &id})
	reply = m.Dispatch(context.Background(), command("status"))
	if reply.State.ProfileID == nil || *reply.State.ProfileID != id {
		t.Fatal("fallback identity was replaced by old selection")
	}
}

func TestFallbackRequestBoundsAndGroup(t *testing.T) {
	request := start()
	request.Profile.Reliability = &ReliabilityOptions{AutoReconnect: true, UseFallbacks: true}
	request.Profile.Group = "group"
	candidate := *request.Profile
	candidate.ID = "33333333-3333-4333-8333-333333333333"
	candidate.Group = "other"
	request.Fallbacks = []Profile{candidate}
	if Validate(request) == "" {
		t.Fatal("cross-group fallback accepted")
	}
	request.Fallbacks[0].Group = "group"
	if Validate(request) != "" {
		t.Fatal("valid fallback rejected")
	}
	request.Command = "stop"
	if Validate(request) == "" {
		t.Fatal("fallbacks accepted outside start")
	}
	request = start()
	request.Profile.Reliability = &ReliabilityOptions{UseFallbacks: true}
	if Validate(request) == "" {
		t.Fatal("fallback without reconnect accepted")
	}
}

func TestFallbackPreservesRoutingMode(t *testing.T) {
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	source := "[Interface]\nPrivateKey = " + key + "\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + key + "\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 10.0.0.0/8\n"
	first := Profile{Protocol: 1, Source: source}
	backup := first
	proxy := Profile{Protocol: 3}
	if CompatibleFallback(first, proxy, false) || CompatibleFallback(proxy, first, false) {
		t.Fatal("local proxy and native routes mixed")
	}
	if !CompatibleFallback(first, backup, false) || !CompatibleFallback(first, proxy, true) {
		t.Fatal("compatible fallback rejected")
	}
	backup.Source = strings.Replace(source, "AllowedIPs = 10.0.0.0/8", "AllowedIPs = 0.0.0.0/0", 1)
	if CompatibleFallback(first, backup, false) {
		t.Fatal("backup silently widened native routes")
	}
}

func TestFallbackRequiresEquivalentNetworkPolicy(t *testing.T) {
	primary := Profile{ID: "11111111-1111-4111-8111-111111111111", Name: "primary", Protocol: 2, Source: "vless://6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a@127.0.0.1:443?security=tls&sni=localhost", Group: "test", Network: &protocol.NetworkOptions{Rules: []protocol.NetworkRule{{Kind: "cidr", Value: "10.0.0.0/8", Action: "direct"}}}}
	backup := primary
	if !CompatibleFallback(primary, backup, true) {
		t.Fatal("equivalent policy rejected")
	}
	backup.Network = &protocol.NetworkOptions{Rules: []protocol.NetworkRule{{Kind: "cidr", Value: "0.0.0.0/0", Action: "direct"}}}
	if CompatibleFallback(primary, backup, true) {
		t.Fatal("different full-device policy accepted")
	}
	if Validate(Request{Version: Version, Command: "start", FullDevice: false, Profile: &primary}) == "" {
		t.Fatal("local-mode start accepted policy")
	}
	if Validate(Request{Version: Version, Command: "start", FullDevice: true, Profile: &primary}) != "" {
		t.Fatal("full-device start rejected policy")
	}
	if Validate(Request{Version: Version, Command: "check-profile", Profile: &primary}) != "" {
		t.Fatal("config-only group check rejected proxy policy")
	}
	native := primary
	native.Protocol = 1
	if Validate(Request{Version: Version, Command: "check-profile", Profile: &native}) == "" {
		t.Fatal("config-only check accepted policy on native tunnel")
	}
}
