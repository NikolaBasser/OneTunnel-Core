package protocol

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
)

// FullNativeRoutingSource returns a validated runtime copy, never a store edit.
// Policy DNS is supplied separately, so imported DNS is optional here.
func FullNativeRoutingSource(source string, kind int) (string, error) {
	if kind != 0 && kind != 1 {
		return "", ErrConfiguration
	}
	copy, err := tunnel(strings.TrimSpace(source), kind, false)
	if err != nil {
		return "", err
	}
	var routes []string
	peers := 0
	defaults := map[string]bool{}
	for _, line := range strings.Split(copy, "\n") {
		key, value, ok := strings.Cut(strings.SplitN(line, "#", 2)[0], "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "AllowedIPs") {
			peers++
			for _, raw := range strings.Split(value, ",") {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
				if err != nil {
					return "", ErrConfiguration
				}
				defaults[prefix.Masked().String()] = true
			}
		}
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "Address") {
			continue
		}
		v4, v6 := false, false
		for _, raw := range strings.Split(value, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil {
				return "", ErrConfiguration
			}
			v4 = v4 || prefix.Addr().Is4()
			v6 = v6 || prefix.Addr().Is6()
		}
		if v4 {
			routes = append(routes, "0.0.0.0/0")
		}
		if v6 {
			routes = append(routes, "::/0")
		}
	}
	if len(routes) == 0 {
		return "", ErrConfiguration
	}
	// A multi-peer config must already name the owner of each default route.
	if peers > 1 {
		for _, route := range routes {
			if !defaults[route] {
				return "", ErrConfiguration
			}
		}
		return copy, nil
	}
	re := regexp.MustCompile(`(?mi)^([ \t]*AllowedIPs[ \t]*=)[^\r\n]+`)
	return re.ReplaceAllString(copy, "${1} "+strings.Join(routes, ", ")), nil
}

func nativePolicyPlan(source string, kind, localPort int, transport *TransportOptions, network *NetworkOptions) (Plan, error) {
	if localPort < 1 || localPort > 65535 {
		return Plan{}, ErrConfiguration
	}
	p, err := CompileWithOptions(source, kind, false, localPort, 0, "", transport)
	if err != nil {
		return Plan{}, err
	}
	p.NativeSource, err = FullNativeRoutingSource(p.NativeSource, kind)
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
