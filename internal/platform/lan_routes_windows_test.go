package platform

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestLANCaptureMakesConnectedRoutesMoreSpecific(t *testing.T) {
	inputs := []netip.Prefix{netip.MustParsePrefix("192.168.10.44/24"), netip.MustParsePrefix("192.168.10.67/24"), netip.MustParsePrefix("fc12:3456:789a::44/64")}
	got, err := lanCapturePrefixes(inputs)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("192.168.10.0/25"), netip.MustParsePrefix("192.168.10.128/25"), netip.MustParsePrefix("fc12:3456:789a::/65"), netip.MustParsePrefix("fc12:3456:789a:0:8000::/65")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capture prefixes=%v want=%v", got, want)
	}
	for _, parent := range inputs {
		children := 0
		for _, child := range got {
			if parent.Masked().Contains(child.Addr()) {
				if child.Bits() != parent.Bits()+1 {
					t.Fatalf("capture %s does not outrank connected %s", child, parent)
				}
				children++
			}
		}
		if children != 2 {
			t.Fatalf("connected prefix %s has %d children", parent, children)
		}
	}
}

func TestLANCaptureRejectsBroadPublicPointToPointAndOwnedPrefixes(t *testing.T) {
	for _, text := range []string{"10.1.2.3/7", "172.16.0.1/11", "192.168.1.1/15", "fc00::1/6", "8.8.8.8/24", "100.64.0.1/24", "127.0.0.1/8", "fe80::1/64", "192.168.1.1/31", "192.168.1.1/32", "fc12::1/127", "fc12::1/128", "172.30.19.1/30", "172.30.19.44/24", "fdfe:dcba:9876::1/126", "::ffff:192.168.1.1/120"} {
		t.Run(text, func(t *testing.T) {
			got, err := lanCapturePrefixes([]netip.Prefix{netip.MustParsePrefix(text)})
			if err != nil || len(got) != 0 {
				t.Fatalf("unsafe/unusable prefix %s captured as %v: %v", text, got, err)
			}
		})
	}
}

func TestLANCapturePrefixBudget(t *testing.T) {
	var inputs []netip.Prefix
	for i := 0; i < 33; i++ {
		inputs = append(inputs, netip.MustParsePrefix(fmt.Sprintf("10.20.%d.1/24", i)))
	}
	if _, err := lanCapturePrefixes(inputs); err == nil {
		t.Fatal("unbounded LAN prefix expansion accepted")
	}
}

func TestLANRouteAppendPreservesPolicyOrderAndExistingRoutes(t *testing.T) {
	rules := []any{jsonObject{"ip_cidr": []any{"192.168.10.67/32"}, "action": "reject"}, jsonObject{"ip_cidr": []any{"192.168.0.0/16"}, "action": "route", "outbound": "direct"}}
	outbounds := []any{jsonObject{"type": "socks", "tag": "proxy"}, jsonObject{"type": "direct", "tag": "direct"}}
	config := jsonObject{"inbounds": []any{jsonObject{"type": "mixed", "listen": "127.0.0.1"}, jsonObject{"type": "tun", "route_address": []any{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}}}, "route": jsonObject{"rules": rules}, "outbounds": outbounds}
	beforeRules, _ := json.Marshal(config["route"])
	beforeOutbounds, _ := json.Marshal(config["outbounds"])
	prefixes := []netip.Prefix{netip.MustParsePrefix("192.168.10.44/24")}
	for i := 0; i < 2; i++ {
		if err := appendLANRoutes(config, prefixes); err != nil {
			t.Fatal(err)
		}
	}
	got := jArray(jObject(jArray(config["inbounds"])[1])["route_address"])
	want := []any{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "192.168.10.0/25", "192.168.10.128/25"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TUN routes=%v want=%v", got, want)
	}
	afterRules, _ := json.Marshal(config["route"])
	afterOutbounds, _ := json.Marshal(config["outbounds"])
	if string(beforeRules) != string(afterRules) || string(beforeOutbounds) != string(afterOutbounds) {
		t.Fatal("LAN capture changed ordered policy or outbound configuration")
	}
}

func TestLANRoutePreparationIsGatedBeforeDiscovery(t *testing.T) {
	for _, tc := range []struct {
		full   bool
		policy *protocol.NetworkOptions
	}{{false, &protocol.NetworkOptions{AllowLAN: true}}, {true, nil}, {true, &protocol.NetworkOptions{AllowLAN: false}}} {
		if err := prepareLANRoutes(nil, tc.full, tc.policy); err != nil {
			t.Fatalf("inactive LAN capture touched discovery/configuration: %v", err)
		}
	}
}

func TestLANRouteAppendFailsClosedForMalformedTUN(t *testing.T) {
	for _, config := range []jsonObject{nil, {"inbounds": []any{jsonObject{"type": "tun"}}}, {"inbounds": []any{jsonObject{"type": "tun", "route_address": []any{1}}}}, {"inbounds": []any{jsonObject{"type": "tun"}, jsonObject{"type": "tun"}}}} {
		if err := appendLANRoutes(config, nil); err == nil {
			t.Fatal("malformed LAN TUN configuration accepted")
		}
	}
}
