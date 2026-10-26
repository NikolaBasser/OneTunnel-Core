package platform

import (
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

// Connected physical routes outrank the TUN's default /1 routes. Capture their
// private subnets with two more-specific routes so ordered reject/direct rules run.
func prepareLANRoutes(config jsonObject, full bool, policy *protocol.NetworkOptions) error {
	if !full || policy == nil || !policy.AllowLAN {
		return nil
	}
	name, err := routeInterface("1.1.1.1")
	if err != nil {
		name, err = routeInterface("2606:4700:4700::1111")
	}
	if err != nil {
		return errors.New("LAN physical uplink unavailable")
	}
	nic, err := net.InterfaceByName(name)
	if err != nil || nic.Flags&net.FlagLoopback != 0 || strings.HasPrefix(strings.ToLower(nic.Name), "onetunnel") {
		return errors.New("LAN uplink is not a physical interface")
	}
	addresses, err := nic.Addrs()
	if err != nil {
		return errors.New("LAN physical addresses unavailable")
	}
	prefixes := make([]netip.Prefix, 0, len(addresses))
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	return appendLANRoutes(config, prefixes)
}

func lanCapturePrefixes(connected []netip.Prefix) ([]netip.Prefix, error) {
	private := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7")}
	owned := []netip.Prefix{netip.MustParsePrefix("172.30.19.0/30"), netip.MustParsePrefix("fdfe:dcba:9876::/126")}
	seen := map[netip.Prefix]bool{}
	for _, prefix := range connected {
		if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Is4() && prefix.Bits() >= 31 || prefix.Addr().Is6() && prefix.Bits() >= 127 {
			continue
		}
		prefix = prefix.Masked()
		contained := false
		for _, block := range private {
			if prefix.Addr().BitLen() == block.Addr().BitLen() && prefix.Bits() >= block.Bits() && block.Contains(prefix.Addr()) {
				contained = true
				break
			}
		}
		if !contained {
			continue
		}
		overlap := false
		for _, block := range owned {
			if block.Contains(prefix.Addr()) || prefix.Contains(block.Addr()) {
				overlap = true
			}
		}
		if overlap {
			continue
		}
		bits := prefix.Bits()
		second := prefix.Addr()
		if second.Is4() {
			bytes := second.As4()
			bytes[bits/8] |= 1 << (7 - bits%8)
			second = netip.AddrFrom4(bytes)
		} else {
			bytes := second.As16()
			bytes[bits/8] |= 1 << (7 - bits%8)
			second = netip.AddrFrom16(bytes)
		}
		seen[netip.PrefixFrom(prefix.Addr(), bits+1)] = true
		seen[netip.PrefixFrom(second, bits+1)] = true
		if len(seen) > 64 {
			return nil, errors.New("LAN capture prefix limit exceeded")
		}
	}
	result := make([]netip.Prefix, 0, len(seen))
	for prefix := range seen {
		result = append(result, prefix)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Addr() == result[j].Addr() {
			return result[i].Bits() < result[j].Bits()
		}
		return result[i].Addr().Compare(result[j].Addr()) < 0
	})
	return result, nil
}

func appendLANRoutes(config jsonObject, connected []netip.Prefix) error {
	prefixes, err := lanCapturePrefixes(connected)
	if err != nil {
		return err
	}
	var tun jsonObject
	for _, inbound := range jArray(config["inbounds"]) {
		candidate := jObject(inbound)
		if jString(candidate["type"]) == "tun" {
			if tun != nil {
				return errors.New("LAN capture requires one TUN inbound")
			}
			tun = candidate
		}
	}
	if tun == nil {
		return errors.New("LAN capture TUN inbound missing")
	}
	routes, ok := tun["route_address"].([]any)
	if !ok {
		return errors.New("LAN capture base routes missing")
	}
	result := append([]any(nil), routes...)
	seen := map[string]bool{}
	for _, value := range routes {
		text, ok := value.(string)
		if !ok {
			return errors.New("LAN capture base route invalid")
		}
		seen[text] = true
	}
	for _, prefix := range prefixes {
		text := prefix.String()
		if !seen[text] {
			result = append(result, text)
			seen[text] = true
		}
	}
	tun["route_address"] = result
	return nil
}
