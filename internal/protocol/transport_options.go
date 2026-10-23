package protocol

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// TransportOptions is a bounded, profile-local preference, never an imported
// executable, arbitrary outbound chain, or a replacement routing policy.
type TransportOptions struct {
	Fragment         bool
	FragmentLength   string
	FragmentInterval string
	Noise            bool
	NoiseLength      string
	NoiseDelay       string
	Mux              bool
	MuxConcurrency   int
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
	if !boundedRange(o.FragmentLength, 1, 1400) || !boundedRange(o.FragmentInterval, 0, 100) ||
		!boundedRange(o.NoiseLength, 1, 1400) || !boundedRange(o.NoiseDelay, 0, 100) || o.MuxConcurrency < 1 || o.MuxConcurrency > 128 {
		return ErrConfiguration
	}
	if !o.Fragment && !o.Noise && !o.Mux {
		return nil
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
	x, err := decodeObject(p.Xray)
	if err != nil {
		return Plan{}, ErrConfiguration
	}
	out := one(x["outbounds"])
	if options.Mux {
		out["mux"] = object{"enabled": true, "concurrency": options.MuxConcurrency, "xudpConcurrency": 0, "xudpProxyUDP443": "skip"}
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
	if !tun || kind < 2 || kind > MaxKind {
		return Plan{}, ErrConfiguration
	}
	normalized, err := NormalizeNetworkOptions(network)
	if err != nil {
		return Plan{}, err
	}
	p, err := CompileWithOptions(source, kind, tun, localPort, bridgePort, xrayPath, transport)
	if err != nil {
		return Plan{}, err
	}
	config, err := decodeObject(p.Proxy)
	if err != nil {
		return Plan{}, ErrConfiguration
	}
	if normalized.DNS != nil {
		dns := normalized.DNS
		server := object{"type": dns.Transport, "tag": "remote-dns", "server": dns.ServerIP, "server_port": dns.Port, "detour": "proxy", "tls": object{"enabled": true, "server_name": dns.ServerName}}
		if dns.Transport == "https" {
			server["path"] = dns.Path
		}
		config["dns"] = object{"servers": []any{server}, "final": "remote-dns"}
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
	for _, rule := range normalized.Rules {
		var matcher string
		switch rule.Kind {
		case "domain":
			matcher = "domain"
		case "domain-suffix":
			matcher = "domain_suffix"
		case "cidr":
			matcher = "ip_cidr"
		case "process":
			matcher = "process_path_regex"
		}
		matchValue := rule.Value
		if rule.Kind == "process" {
			matchValue = windowsProcessRegex(rule.Value)
		}
		value := []any{matchValue}
		entry := object{matcher: value}
		if rule.Action == "reject" {
			entry["action"] = "reject"
		} else {
			entry["action"], entry["outbound"] = "route", rule.Action
		}
		rules = append(rules, entry)
	}
	if len(normalized.Rules) > 0 {
		route["rules"] = rules
	}
	config["route"] = route
	if hasDirectRule(normalized.Rules) {
		outbounds := arr(config["outbounds"])
		outbounds = append(outbounds, object{"type": "direct", "tag": "direct"})
		config["outbounds"] = outbounds
	}
	if hasDomainRule(normalized.Rules) {
		dns := obj(config["dns"])
		dns["reverse_mapping"] = true
		config["dns"] = dns
	}
	data, err := json.Marshal(config)
	if err != nil {
		return Plan{}, ErrConfiguration
	}
	p.Proxy = string(data)
	return p, nil
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
