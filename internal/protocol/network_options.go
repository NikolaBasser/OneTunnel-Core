package protocol

import (
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"unicode"
)

const (
	MaxNetworkRules = 64
	MaxDNSResolvers = 8
	MaxDNSRules     = 64
)

type NetworkOptions struct {
	Targets   []PolicyTarget `json:"Targets,omitempty"`
	RuleSets  []RuleSet      `json:"RuleSets,omitempty"`
	DNS       *DNSOptions
	Rules     []NetworkRule
	Resolvers []DNSOptions `json:"Resolvers,omitempty"`
	DNSRules  []DNSRule    `json:"DNSRules,omitempty"`
	AllowLAN  bool         `json:"AllowLAN,omitempty"`
}

type DNSOptions struct {
	Transport  string
	ServerIP   string
	ServerName string
	Port       int
	Path       string
}

type NetworkRule struct {
	Port     string `json:"Port,omitempty"`
	Network  string `json:"Network,omitempty"`
	Process  string `json:"Process,omitempty"`
	Outbound string `json:"Outbound,omitempty"`
	Kind     string
	Value    string
	Action   string
}

type DNSRule struct {
	Kind          string `json:"Kind"`
	Value         string `json:"Value"`
	ResolverIndex int    `json:"ResolverIndex"`
}

var windowsProcessPath = regexp.MustCompile(`(?i)^[a-z]:\\`)

func NetworkOptionsEmpty(options *NetworkOptions) bool {
	return options == nil || options.DNS == nil && len(options.Rules) == 0 && len(options.Resolvers) == 0 && len(options.DNSRules) == 0 && !options.AllowLAN && len(options.Targets) == 0 && len(options.RuleSets) == 0
}

// CloneNetworkOptions detaches persisted preferences from the profile slice.
func CloneNetworkOptions(options *NetworkOptions) *NetworkOptions {
	if options == nil {
		return nil
	}
	copy := *options
	if options.DNS != nil {
		dns := *options.DNS
		copy.DNS = &dns
	}
	copy.Targets = append([]PolicyTarget(nil), options.Targets...)
	copy.RuleSets = append([]RuleSet(nil), options.RuleSets...)
	for i := range copy.RuleSets {
		copy.RuleSets[i].Members = append([]NetworkRule(nil), options.RuleSets[i].Members...)
	}
	copy.Rules = append([]NetworkRule(nil), options.Rules...)
	copy.Resolvers = append([]DNSOptions(nil), options.Resolvers...)
	copy.DNSRules = append([]DNSRule(nil), options.DNSRules...)
	return &copy
}

func NormalizeNetworkOptions(options *NetworkOptions) (*NetworkOptions, error) {
	if NetworkOptionsEmpty(options) {
		return nil, nil
	}
	out := CloneNetworkOptions(options)
	if out.DNS != nil {
		dns, ok := normalizeDNSOptions(*out.DNS)
		if !ok {
			return nil, ErrConfiguration
		}
		out.DNS = &dns
	}
	if len(out.Resolvers) > MaxDNSResolvers || len(out.DNSRules) > MaxDNSRules {
		return nil, ErrConfiguration
	}
	for i := range out.Resolvers {
		dns, ok := normalizeDNSOptions(out.Resolvers[i])
		if !ok {
			return nil, ErrConfiguration
		}
		out.Resolvers[i] = dns
	}
	for i := range out.DNSRules {
		rule := &out.DNSRules[i]
		rule.Kind = strings.ToLower(strings.TrimSpace(rule.Kind))
		if rule.Kind != "domain" && rule.Kind != "domain-suffix" {
			return nil, ErrConfiguration
		}
		name, ok := normalizeHostname(rule.Value)
		if !ok || rule.ResolverIndex < 0 || rule.ResolverIndex >= len(out.Resolvers) {
			return nil, ErrConfiguration
		}
		rule.Value = name
	}
	if len(out.Resolvers) == 0 {
		out.Resolvers = nil
	}
	if len(out.DNSRules) == 0 {
		out.DNSRules = nil
	}
	if len(out.Rules) > MaxNetworkRules {
		return nil, ErrConfiguration
	}
	for i := range out.Rules {
		rule := &out.Rules[i]
		rule.Kind = strings.ToLower(strings.TrimSpace(rule.Kind))
		rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
		if rule.Kind == "process" && rule.Value != strings.TrimSpace(rule.Value) {
			return nil, ErrConfiguration
		}
		rule.Value = strings.TrimSpace(rule.Value)
		if rule.Action != "proxy" && rule.Action != "direct" && rule.Action != "reject" {
			return nil, ErrConfiguration
		}
		switch rule.Kind {
		case "domain", "domain-suffix":
			name, ok := normalizeHostname(rule.Value)
			if !ok {
				return nil, ErrConfiguration
			}
			rule.Value = name
		case "cidr":
			prefix, err := netip.ParsePrefix(rule.Value)
			if err == nil {
				if prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
					return nil, ErrConfiguration
				}
				rule.Value = prefix.Masked().String()
			} else {
				address, parseErr := netip.ParseAddr(rule.Value)
				if parseErr != nil || address.Zone() != "" || address.Is4In6() {
					return nil, ErrConfiguration
				}
				bits := 128
				if address.Is4() {
					bits = 32
				}
				rule.Value = netip.PrefixFrom(address, bits).String()
			}
		case "port":
			p, ok := normalizePort(rule.Value)
			if !ok {
				return nil, ErrConfiguration
			}
			rule.Value = p
		case "network":
			rule.Value = strings.ToLower(rule.Value)
			if !has(rule.Value, "tcp udp") {
				return nil, ErrConfiguration
			}
		case "rule-set":
			rule.Value = strings.ToLower(rule.Value)
			if !policyName.MatchString(rule.Value) {
				return nil, ErrConfiguration
			}
		case "process":
			path, ok := normalizeProcessPath(rule.Value)
			if !ok {
				return nil, ErrConfiguration
			}
			rule.Value = path
		default:
			return nil, ErrConfiguration
		}
	}
	if len(out.Rules) == 0 {
		out.Rules = nil
	}
	if err := normalizePolicy(out); err != nil {
		return nil, err
	}
	return out, nil
}

func ValidateNetworkOptions(options *NetworkOptions, kind int, fullDevice bool) error {
	if NetworkOptionsEmpty(options) {
		return nil
	}
	if !fullDevice || kind < 0 || kind > MaxKind {
		return ErrConfiguration
	}
	_, err := NormalizeNetworkOptions(options)
	return err
}

func NetworkOptionsEquivalent(a, b *NetworkOptions) bool {
	first, err1 := NormalizeNetworkOptions(a)
	second, err2 := NormalizeNetworkOptions(b)
	if err1 != nil || err2 != nil {
		return false
	}
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	if (first.DNS == nil) != (second.DNS == nil) || len(first.Rules) != len(second.Rules) {
		return false
	}
	if first.DNS != nil && *first.DNS != *second.DNS {
		return false
	}
	if !reflect.DeepEqual(first.Targets, second.Targets) || !reflect.DeepEqual(first.RuleSets, second.RuleSets) {
		return false
	}
	if first.AllowLAN != second.AllowLAN || !reflect.DeepEqual(first.Resolvers, second.Resolvers) || !reflect.DeepEqual(first.DNSRules, second.DNSRules) {
		return false
	}
	for i := range first.Rules {
		if first.Rules[i] != second.Rules[i] {
			return false
		}
	}
	return true
}

func normalizeDNSOptions(dns DNSOptions) (DNSOptions, bool) {
	dns.Transport = strings.ToLower(strings.TrimSpace(dns.Transport))
	if dns.Transport != "https" && dns.Transport != "tls" {
		return DNSOptions{}, false
	}
	ipText := strings.TrimSpace(dns.ServerIP)
	ip := net.ParseIP(ipText)
	if ip == nil || strings.Contains(ipText, "%") {
		return DNSOptions{}, false
	}
	dns.ServerIP = ip.String()
	serverName, ok := normalizeHostname(dns.ServerName)
	if !ok {
		return DNSOptions{}, false
	}
	dns.ServerName = serverName
	if dns.Port == 0 {
		if dns.Transport == "https" {
			dns.Port = 443
		} else {
			dns.Port = 853
		}
	}
	if dns.Port < 1 || dns.Port > 65535 {
		return DNSOptions{}, false
	}
	if dns.Transport == "https" {
		if dns.Path == "" {
			dns.Path = "/dns-query"
		}
		if !validDNSPath(dns.Path) {
			return DNSOptions{}, false
		}
	} else if dns.Path != "" {
		return DNSOptions{}, false
	}
	return dns, true
}

func normalizeHostname(value string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(value))
	if strings.HasSuffix(name, ".") {
		name = strings.TrimSuffix(name, ".")
	}
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", false
			}
		}
	}
	return name, true
}

func validDNSPath(path string) bool {
	if len(path) > 2048 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#@\\%:") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	for _, r := range path {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func normalizeProcessPath(value string) (string, bool) {
	if len(value) < 7 || len(value) > 32767 || !windowsProcessPath.MatchString(value) || strings.ContainsAny(value, "/<>\"|?*%$~") || strings.Contains(value[2:], ":") {
		return "", false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	parts := strings.Split(value[3:], `\`)
	if len(parts) == 0 {
		return "", false
	}
	filename := parts[len(parts)-1]
	if len(filename) <= 4 || !strings.EqualFold(filename[len(filename)-4:], ".exe") {
		return "", false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part || strings.TrimRight(part, ". ") != part {
			return "", false
		}
	}
	return strings.ToLower(value), true
}
