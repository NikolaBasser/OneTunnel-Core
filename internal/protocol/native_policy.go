package protocol

import (
	"encoding/json"
	"net/netip"
	"strings"
)

func nativePolicyPlan(source string, kind, localPort int, transport *TransportOptions, network *NetworkOptions) (Plan, error) {
	if localPort < 1 || localPort > 65535 {
		return Plan{}, ErrConfiguration
	}
	p, err := CompileWithOptions(source, kind, false, localPort, 0, "", transport)
	if err != nil {
		return Plan{}, err
	}
	if err = validateNativePolicyDNS(p.NativeSource, network); err != nil {
		return Plan{}, err
	}
	config := proxyConfig(object{"type": "onetunnel-native", "tag": "proxy"}, true, localPort, "", false)
	data, err := json.Marshal(config)
	if err != nil {
		return Plan{}, err
	}
	p.SharedNative, p.LocalPort, p.Proxy = true, localPort, string(data)
	return p, nil
}

// Policy DNS must be reachable through the peer; there is no direct fallback.
func validateNativePolicyDNS(source string, network *NetworkOptions) error {
	var addresses, routes []netip.Prefix
	for _, line := range strings.Split(source, "\n") {
		line = strings.SplitN(strings.SplitN(line, "#", 2)[0], ";", 2)[0]
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "address" && key != "allowedips" {
			continue
		}
		for _, entry := range strings.Split(value, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(entry))
			if err != nil {
				return ErrConfiguration
			}
			if key == "address" {
				addresses = append(addresses, prefix)
			} else {
				routes = append(routes, prefix)
			}
		}
	}
	servers := []string{"1.1.1.1"}
	if network.DNS != nil {
		servers[0] = network.DNS.ServerIP
	}
	for _, resolver := range network.Resolvers {
		servers = append(servers, resolver.ServerIP)
	}
	for _, server := range servers {
		ip, err := netip.ParseAddr(server)
		if err != nil {
			return ErrConfiguration
		}
		family, covered := false, false
		for _, address := range addresses {
			family = family || address.Addr().Is4() == ip.Is4()
		}
		for _, route := range routes {
			covered = covered || route.Contains(ip)
		}
		if !family || !covered {
			return ErrConfiguration
		}
	}
	return nil
}
