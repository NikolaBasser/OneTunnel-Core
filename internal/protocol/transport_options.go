package protocol

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// TransportOptions is a bounded, profile-local preference, never an imported
// executable, arbitrary outbound chain, or a replacement routing policy.
type TransportOptions struct {
	Fragment          bool
	FragmentLength    string
	FragmentInterval  string
	Noise             bool
	NoiseLength       string
	NoiseDelay        string
	Mux               bool
	MuxConcurrency    int
	MuxProtocol       string `json:"MuxProtocol,omitempty"`
	MuxMaxConnections int    `json:"MuxMaxConnections,omitempty"`
	MuxMinStreams     int    `json:"MuxMinStreams,omitempty"`
	MuxPadding        bool   `json:"MuxPadding,omitempty"`
	XUDPConcurrency   int    `json:"XUDPConcurrency,omitempty"`
	UDP443Policy      string `json:"UDP443Policy,omitempty"`
}

func boundedRange(value string, min, max int) bool {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	previous := min
	for _, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}
		v, err := strconv.Atoi(part)
		if err != nil || v < previous || v > max {
			return false
		}
		previous = v
	}
	return true
}

func ValidateOptions(source string, kind int, o *TransportOptions) error {
	if o == nil {
		return nil
	}
	if !has(o.MuxProtocol, " xray h2mux smux yamux") || o.MuxMaxConnections < 0 || o.MuxMaxConnections > 32 || o.MuxMinStreams < 0 || o.MuxMinStreams > 128 || o.XUDPConcurrency < 0 || o.XUDPConcurrency > 128 || !has(o.UDP443Policy, " skip reject allow") {
		return ErrConfiguration
	}
	if !boundedRange(o.FragmentLength, 1, 1400) || !boundedRange(o.FragmentInterval, 0, 100) ||
		!boundedRange(o.NoiseLength, 1, 1400) || !boundedRange(o.NoiseDelay, 0, 100) || o.MuxConcurrency < 1 || o.MuxConcurrency > 128 {
		return ErrConfiguration
	}
	if !o.Fragment && !o.Noise && !o.Mux {
		return nil
	}
	if o.Mux && o.MuxProtocol != "" && o.MuxProtocol != "xray" {
		if o.MuxMaxConnections == 0 && o.MuxMinStreams != 0 {
			return ErrConfiguration
		}
		if o.Fragment || o.Noise || kind != 5 && kind != Trojan || o.XUDPConcurrency != 0 || o.UDP443Policy != "" {
			return ErrConfiguration
		}
		plan, err := Compile(source, kind, false, 18001, 18002, "")
		if err != nil || plan.NeedsXray {
			return ErrConfiguration
		}
		return nil
	}
	if o.Mux && (o.MuxMaxConnections != 0 || o.MuxMinStreams != 0 || o.MuxPadding) {
		return ErrConfiguration
	}
	if kind != 2 && kind != 4 {
		return ErrConfiguration
	}
	out, err := Outbound(source, kind)
	if err != nil {
		return err
	}
	stream := obj(out["streamSettings"])
	network := s(stream["network"])
	if network == "" {
		network = "tcp"
	}
	udp := kind == 4 || has(network, "kcp mkcp hysteria")
	if o.Fragment && (kind != 2 || udp || !has(s(stream["security"]), "tls reality")) {
		return ErrConfiguration
	}
	// Separate XHTTP download legs need their own endpoint-bound dialer. Refuse
	// rather than silently fragment only one leg of an imported split transport.
	if o.Fragment && obj(obj(stream["xhttpSettings"])["extra"])["downloadSettings"] != nil {
		return ErrConfiguration
	}
	if o.Noise && !udp {
		return ErrConfiguration
	}
	if o.Mux && (kind != 2 || !has(network, "tcp raw ws websocket httpupgrade") || s(one(one(obj(out["settings"])["vnext"])["users"])["flow"]) != "") {
		return ErrConfiguration
	}
	return nil
}

func CompileWithOptions(source string, kind int, tun bool, localPort, bridgePort int, xrayPath string, options *TransportOptions) (Plan, error) {
	if err := ValidateOptions(source, kind, options); err != nil {
		return Plan{}, err
	}
	p, err := Compile(source, kind, tun, localPort, bridgePort, xrayPath)
	if err != nil || options == nil || (!options.Fragment && !options.Noise && !options.Mux) {
		return p, err
	}
	if options.Mux && !p.NeedsXray {
		config, e := decodeObject(p.Proxy)
		if e != nil {
			return Plan{}, ErrConfiguration
		}
		mux := object{"enabled": true, "protocol": options.MuxProtocol, "padding": options.MuxPadding}
		if options.MuxMaxConnections > 0 {
			mux["max_connections"] = options.MuxMaxConnections
		} else {
			mux["max_streams"] = options.MuxConcurrency
		}
		if options.MuxMinStreams > 0 {
			mux["min_streams"] = options.MuxMinStreams
		}
		one(config["outbounds"])["multiplex"] = mux
		b, e := json.Marshal(config)
		p.Proxy = string(b)
		return p, e
	}
	x, err := decodeObject(p.Xray)
	if err != nil {
		return Plan{}, ErrConfiguration
	}
	out := one(x["outbounds"])
	if options.Mux {
		policy := options.UDP443Policy
		if policy == "" {
			policy = "skip"
		}
		out["mux"] = object{"enabled": true, "concurrency": options.MuxConcurrency, "xudpConcurrency": options.XUDPConcurrency, "xudpProxyUDP443": policy}
	}
	if options.Fragment || options.Noise {
		stream := obj(out["streamSettings"])
		sock := obj(stream["sockopt"])
		sock["dialerProxy"] = "onetunnel-transport"
		stream["sockopt"] = sock
		out["streamSettings"] = stream
		settings := object{}
		if options.Fragment {
			settings["fragment"] = object{"packets": "tlshello", "length": options.FragmentLength, "interval": options.FragmentInterval}
		}
		if options.Noise {
			settings["noises"] = []any{object{"type": "rand", "packet": options.NoiseLength, "delay": options.NoiseDelay, "applyTo": "ip"}}
		}
		// Keep the authenticated proxy FIRST: no user traffic can default to
		// freedom. This dialer is reachable only by the generated tag above.
		x["outbounds"] = append(arr(x["outbounds"]), object{"tag": "onetunnel-transport", "protocol": "freedom", "settings": settings, "streamSettings": object{"sockopt": object{}}})
	}
	b, err := json.Marshal(x)
	p.Xray = string(b)
	return p, err
}

// CompileWithNetwork adds profile-local DNS and routing only to full-device
// sing-box plans. Empty preferences take the legacy compiler path unchanged.
func CompileWithNetwork(source string, kind int, tun bool, localPort, bridgePort int, xrayPath string, transport *TransportOptions, network *NetworkOptions) (Plan, error) {
	if NetworkOptionsEmpty(network) {
		return CompileWithOptions(source, kind, tun, localPort, bridgePort, xrayPath, transport)
	}
	if !tun || kind < 0 || kind > MaxKind {
		return Plan{}, ErrConfiguration
	}
	normalized, err := NormalizeNetworkOptions(network)
	if err != nil {
		return Plan{}, err
	}
	if kind == HTTP || kind == Naive {
		resolvers := append([]DNSOptions(nil), normalized.Resolvers...)
		if normalized.DNS != nil {
			resolvers = append(resolvers, *normalized.DNS)
		}
		for _, resolver := range resolvers {
			if resolver.Transport == "quic" || resolver.Transport == "h3" {
				return Plan{}, fmt.Errorf("%w: DNS_transport_requires_UDP_capable_profile", ErrConfiguration)
			}
		}
	}
	var p Plan
	if kind < 2 {
		p, err = nativePolicyPlan(source, kind, localPort, transport, normalized)
	} else {
		p, err = CompileWithOptions(source, kind, tun, localPort, bridgePort, xrayPath, transport)
	}
	if err != nil {
		return Plan{}, err
	}
	config, err := decodeObject(p.Proxy)
	if err != nil {
		return Plan{}, ErrConfiguration
	}
	if kind == Naive {
		// Naive requires an explicit resolver once the policy DNS registry has
		// multiple transports. Use the same fixed-IP final resolver as all other
		// unmatched lookups.
		outbounds := arr(config["outbounds"])
		if len(outbounds) == 0 {
			return Plan{}, ErrConfiguration
		}
		obj(outbounds[0])["domain_resolver"] = "remote-dns"
	}
	if normalized.DNS != nil {
		config["dns"] = object{"servers": []any{dnsServer(*normalized.DNS, "remote-dns")}, "final": "remote-dns"}
	}
	if len(normalized.Resolvers) > 0 {
		dns := obj(config["dns"])
		servers := arr(dns["servers"])
		dnsRules := make([]any, 0, len(normalized.DNSRules))
		for i, resolver := range normalized.Resolvers {
			tag := fmt.Sprintf("onetunnel-policy-dns-%d", i)
			servers = append(servers, dnsServer(resolver, tag))
		}
		for _, rule := range normalized.DNSRules {
			matcher := "domain"
			if rule.Kind == "domain-suffix" {
				matcher = "domain_suffix"
			}
			dnsRules = append(dnsRules, object{matcher: []any{rule.Value}, "action": "route", "server": fmt.Sprintf("onetunnel-policy-dns-%d", rule.ResolverIndex)})
		}
		dns["servers"] = servers
		if len(dnsRules) > 0 {
			dns["rules"] = dnsRules
		}
		config["dns"] = dns
	}
	if normalized.DNSCache != nil || normalized.FakeIP {
		dns := obj(config["dns"])
		if normalized.DNSCache != nil {
			dns["disable_cache"] = normalized.DNSCache.Disabled
			dns["cache_capacity"] = normalized.DNSCache.Capacity
		}
		if normalized.FakeIP {
			dns["servers"] = append(arr(dns["servers"]), object{"type": "fakeip", "tag": "onetunnel-fakeip", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/112"})
			dns["rules"] = append(arr(dns["rules"]), object{"query_type": []any{"A", "AAAA"}, "action": "route", "server": "onetunnel-fakeip"})
			// Internal endpoint/domain lookups must use the real resolver, not FakeIP.
			obj(config["route"])["default_domain_resolver"] = "remote-dns"
		}
		config["dns"] = dns
	}
	route := obj(obj(config["route"]))
	rules := arr(route["rules"])
	// Windows process paths are case-insensitive; the engine's exact path
	// matcher is case-sensitive, so express validated paths as anchored regexes.
	if len(rules) > 0 {
		if paths := arr(obj(rules[0])["process_path"]); len(paths) > 0 {
			entry := obj(rules[0])
			patterns := make([]any, len(paths))
			for i, path := range paths {
				patterns[i] = windowsProcessRegex(s(path))
			}
			delete(entry, "process_path")
			entry["process_path_regex"] = patterns
		}
	}
	resolvedFakeIP := false
	resolveForIPRules := func() {
		if normalized.FakeIP && !resolvedFakeIP {
			rules = append(rules, object{"action": "resolve", "server": "remote-dns"})
			resolvedFakeIP = true
		}
	}
	for _, rule := range normalized.Rules {
		if rule.Kind == "cidr" || rule.Kind == "rule-set" {
			resolveForIPRules()
		}
		entry := matcher(rule)
		if rule.Action == "reject" {
			entry["action"] = "reject"
		} else {
			entry["action"], entry["outbound"] = "route", rule.Action
			if rule.Outbound != "" {
				entry["outbound"] = policyTag(rule.Outbound)
			}
		}
		rules = append(rules, entry)
	}
	if normalized.AllowLAN {
		resolveForIPRules()
		rules = append(rules, object{"ip_cidr": []any{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}, "action": "route", "outbound": "direct"})
	}
	if len(normalized.Rules) > 0 || normalized.AllowLAN {
		route["rules"] = rules
	}
	config["route"] = route
	if normalized.AllowLAN || hasDirectRule(normalized.Rules) {
		outbounds := arr(config["outbounds"])
		outbounds = append(outbounds, object{"type": "direct", "tag": "direct"})
		config["outbounds"] = outbounds
	}
	if hasDomainRule(normalized.Rules) || len(normalized.RuleSets) > 0 || len(normalized.DNSRules) > 0 {
		dns := obj(config["dns"])
		dns["reverse_mapping"] = true
		config["dns"] = dns
	}
	if err := appendPolicy(config, &p, normalized); err != nil {
		return Plan{}, err
	}
	data, err := json.Marshal(config)
	if err != nil {
		return Plan{}, ErrConfiguration
	}
	p.Proxy = string(data)
	return p, nil
}

func dnsServer(dns DNSOptions, tag string) object {
	server := object{"type": dns.Transport, "tag": tag, "server": dns.ServerIP, "server_port": dns.Port, "detour": "proxy", "tls": object{"enabled": true, "server_name": dns.ServerName}}
	if dns.Transport == "https" || dns.Transport == "h3" {
		server["path"] = dns.Path
	}
	return server
}

func windowsProcessRegex(path string) string { return `(?i)^` + regexp.QuoteMeta(path) + `$` }

func hasDirectRule(rules []NetworkRule) bool {
	for _, rule := range rules {
		if rule.Action == "direct" {
			return true
		}
	}
	return false
}

func hasDomainRule(rules []NetworkRule) bool {
	for _, rule := range rules {
		if rule.Kind == "domain" || rule.Kind == "domain-suffix" {
			return true
		}
	}
	return false
}
