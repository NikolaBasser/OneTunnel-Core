package protocol

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const MaxPolicyTargets = 8
const MaxRuleSets = 16
const MaxRuleSetMembers = 4096

var policyName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Targets are explicit profile snapshots, never references to mutable library IDs.
type PolicyTarget struct {
	Name     string
	Protocol int
	Source   string
}
type RuleSet struct {
	Name    string
	Members []NetworkRule
}

func normalizePort(value string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) < 1 || len(parts) > 2 {
		return "", false
	}
	first, last := 0, 0
	for i, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return "", false
		}
		v, e := strconv.Atoi(p)
		if e != nil || v < 1 || v > 65535 {
			return "", false
		}
		if i == 0 {
			first = v
		}
		last = v
	}
	if last < first {
		return "", false
	}
	if first == last {
		return strconv.Itoa(first), true
	}
	return fmt.Sprintf("%d-%d", first, last), true
}
func targetPlan(target PolicyTarget) (Plan, error) {
	if len(target.Source) > 131072 || target.Protocol < 2 || target.Protocol > MaxKind {
		return Plan{}, ErrConfiguration
	}
	p, e := Compile(target.Source, target.Protocol, false, 18001, 18002, "")
	if e != nil {
		return Plan{}, ErrConfiguration
	}
	if p.NeedsXray || p.SharedNative {
		return Plan{}, fmt.Errorf("%w: policy_target_requires_separate_engine", ErrConfiguration)
	}
	return p, nil
}
func normalizePolicy(options *NetworkOptions) error {
	if len(options.Targets) > MaxPolicyTargets || len(options.RuleSets) > MaxRuleSets {
		return ErrConfiguration
	}
	targets, sets := map[string]bool{}, map[string]bool{}
	for i := range options.Targets {
		t := &options.Targets[i]
		t.Name = strings.ToLower(strings.TrimSpace(t.Name))
		if !policyName.MatchString(t.Name) || targets[t.Name] {
			return ErrConfiguration
		}
		targets[t.Name] = true
		if _, e := targetPlan(*t); e != nil {
			return e
		}
	}
	total := 0
	for i := range options.RuleSets {
		set := &options.RuleSets[i]
		set.Name = strings.ToLower(strings.TrimSpace(set.Name))
		total += len(set.Members)
		if !policyName.MatchString(set.Name) || sets[set.Name] || len(set.Members) == 0 || len(set.Members) > MaxRuleSetMembers || total > 8192 {
			return ErrConfiguration
		}
		sets[set.Name] = true
		for j, member := range set.Members {
			if !has(member.Kind, "domain domain-suffix cidr") || member.Port != "" || member.Network != "" || member.Process != "" || member.Outbound != "" || member.Action != "" {
				return ErrConfiguration
			}
			member.Action = "proxy"
			v, e := NormalizeNetworkOptions(&NetworkOptions{Rules: []NetworkRule{member}})
			if e != nil {
				return e
			}
			member = v.Rules[0]
			member.Action = ""
			set.Members[j] = member
		}
	}
	for i := range options.Rules {
		rule := &options.Rules[i]
		if rule.Kind == "rule-set" && !sets[rule.Value] {
			return ErrConfiguration
		}
		rule.Outbound = strings.ToLower(strings.TrimSpace(rule.Outbound))
		if rule.Outbound != "" && (rule.Action != "proxy" || !targets[rule.Outbound]) {
			return ErrConfiguration
		}
		if rule.Port != "" {
			p, ok := normalizePort(rule.Port)
			if !ok {
				return ErrConfiguration
			}
			rule.Port = p
		}
		rule.Network = strings.ToLower(strings.TrimSpace(rule.Network))
		if rule.Network != "" && !has(rule.Network, "tcp udp") {
			return ErrConfiguration
		}
		if rule.Process != "" {
			p, ok := normalizeProcessPath(rule.Process)
			if !ok {
				return ErrConfiguration
			}
			rule.Process = p
		}
		if rule.Kind == "port" && rule.Port != "" || rule.Kind == "network" && rule.Network != "" || rule.Kind == "process" && rule.Process != "" {
			return ErrConfiguration
		}
	}
	return nil
}
func policyTag(name string) string { return "onetunnel-target-" + name }
func setTag(name string) string    { return "onetunnel-set-" + name }
func matcher(rule NetworkRule) object {
	entry := object{}
	switch rule.Kind {
	case "domain":
		entry["domain"] = []any{rule.Value}
	case "domain-suffix":
		entry["domain_suffix"] = []any{rule.Value}
	case "cidr":
		entry["ip_cidr"] = []any{rule.Value}
	case "process":
		entry["process_path_regex"] = []any{windowsProcessRegex(rule.Value)}
	case "rule-set":
		entry["rule_set"] = []any{setTag(rule.Value)}
	case "network":
		entry["network"] = []any{rule.Value}
	case "port":
		putPort(entry, rule.Value)
	}
	if rule.Port != "" {
		putPort(entry, rule.Port)
	}
	if rule.Network != "" {
		entry["network"] = []any{rule.Network}
	}
	if rule.Process != "" {
		entry["process_path_regex"] = []any{windowsProcessRegex(rule.Process)}
	}
	return entry
}
func putPort(entry object, value string) {
	if strings.Contains(value, "-") {
		entry["port_range"] = []any{strings.ReplaceAll(value, "-", ":")}
	} else {
		v, _ := strconv.Atoi(value)
		entry["port"] = []any{v}
	}
}
func appendPolicy(config object, p *Plan, options *NetworkOptions) error {
	outbounds := arr(config["outbounds"])
	for _, target := range options.Targets {
		plan, e := targetPlan(target)
		if e != nil {
			return e
		}
		c, e := decodeObject(plan.Proxy)
		if e != nil {
			return e
		}
		out := one(c["outbounds"])
		if len(out) == 0 {
			return ErrConfiguration
		}
		out["tag"] = policyTag(target.Name)
		if target.Protocol == Naive {
			out["domain_resolver"] = "remote-dns"
		}
		outbounds = append(outbounds, out)
		if plan.AccurateTime {
			p.AccurateTime = true
			p.Clock = plan.Clock
		}
	}
	config["outbounds"] = outbounds
	sets := []any{}
	for _, set := range options.RuleSets {
		members := []any{}
		for _, member := range set.Members {
			members = append(members, matcher(member))
		}
		sets = append(sets, object{"type": "inline", "tag": setTag(set.Name), "rules": []any{object{"type": "logical", "mode": "or", "rules": members}}})
	}
	if len(sets) > 0 {
		route := obj(config["route"])
		route["rule_set"] = sets
		config["route"] = route
	}
	return nil
}

type PolicyWarning struct {
	Rule int
	Code string
}
type PolicyAnalysis struct {
	Rules, Targets, RuleSets int
	Warnings                 []PolicyWarning
}

func AnalyzeNetwork(options *NetworkOptions) (PolicyAnalysis, error) {
	n, e := NormalizeNetworkOptions(options)
	if e != nil {
		return PolicyAnalysis{}, e
	}
	a := PolicyAnalysis{Warnings: []PolicyWarning{}}
	if n == nil {
		return a, nil
	}
	a.Rules, a.Targets, a.RuleSets = len(n.Rules), len(n.Targets), len(n.RuleSets)
	seen := map[string]bool{}
	for i, r := range n.Rules {
		r.Action = ""
		r.Outbound = ""
		b, _ := json.Marshal(r)
		if seen[string(b)] {
			a.Warnings = append(a.Warnings, PolicyWarning{i, "shadowed-identical-match"})
		}
		seen[string(b)] = true
	}
	return a, nil
}

type RouteQuery struct {
	Domain, IP, Process, Network string
	Port                         uint16
}
type RoutePrediction struct {
	Decision, Outbound, Reason string
	Rule                       int
	PredictionOnly             bool
}

// Missing metadata is unknown, never guessed from a DNS or socket side effect.
func ExplainRoute(options *NetworkOptions, q RouteQuery) (RoutePrediction, error) {
	n, e := NormalizeNetworkOptions(options)
	if e != nil {
		return RoutePrediction{}, e
	}
	q.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(q.Domain), "."))
	if q.Domain != "" {
		if _, ok := normalizeHostname(q.Domain); !ok {
			return RoutePrediction{}, ErrConfiguration
		}
	}
	if q.IP != "" {
		ip, e := netip.ParseAddr(q.IP)
		if e != nil || ip.Is4In6() || ip.Zone() != "" {
			return RoutePrediction{}, ErrConfiguration
		}
		q.IP = ip.String()
	}
	if q.Process != "" {
		p, ok := normalizeProcessPath(q.Process)
		if !ok {
			return RoutePrediction{}, ErrConfiguration
		}
		q.Process = p
	}
	q.Network = strings.ToLower(q.Network)
	if q.Network != "" && !has(q.Network, "tcp udp") {
		return RoutePrediction{}, ErrConfiguration
	}
	result := RoutePrediction{Decision: "proxy", Outbound: "proxy", Rule: -1, Reason: "default-policy", PredictionOnly: true}
	if q.Port == 0 {
		result.Decision, result.Outbound, result.Reason = "unknown", "", "required-metadata-missing"
		return result, nil
	}
	if q.Port == 53 {
		result.Decision = "dns"
		result.Outbound = "configured-resolver"
		result.Reason = "tun-dns-hijack"
		return result, nil
	}
	if n == nil {
		return result, nil
	}
	for i, r := range n.Rules {
		m := matchPolicy(r, n, q)
		if m == 0 {
			continue
		}
		result.Rule = i
		if m < 0 {
			result.Decision = "unknown"
			result.Outbound = ""
			result.Reason = "required-metadata-missing"
			return result, nil
		}
		result.Decision = r.Action
		result.Outbound = r.Action
		if r.Outbound != "" {
			result.Outbound = r.Outbound
		}
		result.Reason = "first-matching-rule"
		return result, nil
	}
	if n.AllowLAN && q.IP == "" {
		result.Decision, result.Outbound, result.Reason = "unknown", "", "required-metadata-missing"
		return result, nil
	}
	if n.AllowLAN {
		ip, _ := netip.ParseAddr(q.IP)
		if ip.IsPrivate() {
			result.Decision = "direct"
			result.Outbound = "direct"
			result.Reason = "explicit-lan-policy"
		}
	}
	return result, nil
}
func matchPolicy(r NetworkRule, n *NetworkOptions, q RouteQuery) int {
	m := matchPrimitive(r, q)
	if r.Kind == "rule-set" {
		m = 0
		for _, set := range n.RuleSets {
			if set.Name != r.Value {
				continue
			}
			for _, member := range set.Members {
				x := matchPrimitive(member, q)
				if x == 1 {
					m = 1
					break
				}
				if x < 0 {
					m = -1
				}
			}
		}
	}
	if m == 0 {
		return 0
	}
	for _, condition := range []NetworkRule{{Kind: "port", Value: r.Port}, {Kind: "network", Value: r.Network}, {Kind: "process", Value: r.Process}} {
		if condition.Value == "" {
			continue
		}
		x := matchPrimitive(condition, q)
		if x == 0 {
			return 0
		}
		if x < 0 {
			m = -1
		}
	}
	return m
}
func matchPrimitive(r NetworkRule, q RouteQuery) int {
	value, ok := "", false
	switch r.Kind {
	case "domain", "domain-suffix":
		value = q.Domain
		if value == "" {
			return -1
		}
		ok = value == r.Value || r.Kind == "domain-suffix" && strings.HasSuffix(value, "."+r.Value)
	case "cidr":
		value = q.IP
		if value == "" {
			return -1
		}
		p, _ := netip.ParsePrefix(r.Value)
		ip, _ := netip.ParseAddr(value)
		ok = p.Contains(ip)
	case "process":
		value = q.Process
		if value == "" {
			return -1
		}
		ok = strings.EqualFold(value, r.Value)
	case "network":
		value = q.Network
		if value == "" {
			return -1
		}
		ok = value == r.Value
	case "port":
		if q.Port == 0 {
			return -1
		}
		parts := strings.Split(r.Value, "-")
		lo, _ := strconv.Atoi(parts[0])
		hi := lo
		if len(parts) == 2 {
			hi, _ = strconv.Atoi(parts[1])
		}
		ok = int(q.Port) >= lo && int(q.Port) <= hi
	default:
		return -1
	}
	if ok {
		return 1
	}
	return 0
}
