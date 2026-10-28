package profiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

type NetworkPreferencesView struct {
	PresetSummary                                                                                      string
	RoutingMode, CustomRulesText, PresetRulesText                                                      string
	FakeIP                                                                                             bool
	CacheMode, CacheCapacity                                                                           string
	ID, Token, Message, Mode, ServerIP, ServerName, Port, Path, RulesText, ResolversText, DNSRulesText string
	AllowLAN                                                                                           bool
	Supported, CanSave                                                                                 bool
}

type NetworkInput struct {
	RoutingMode, CustomRulesText, PresetRulesText                                  string
	FakeIP                                                                         bool
	CacheMode, CacheCapacity                                                       string
	Mode, ServerIP, ServerName, Port, Path, RulesText, ResolversText, DNSRulesText string
	AllowLAN                                                                       bool
}

func (input NetworkInput) Parse() (*protocol.NetworkOptions, error) {
	if input.RoutingMode != "" {
		state, e := input.routingPreferences()
		if e != nil {
			return nil, e
		}
		input.RulesText = ""
		if state.Mode == "custom" {
			input.RulesText = state.CustomRulesText
		}
		if state.Mode == "preset" {
			input.RulesText = state.PresetRulesText
		}
	}
	mode := strings.ToLower(strings.TrimSpace(input.Mode))
	if mode != "default" && mode != "https" && mode != "tls" && mode != "quic" && mode != "h3" {
		return nil, protocol.ErrConfiguration
	}
	options := &protocol.NetworkOptions{}
	options.FakeIP = input.FakeIP
	cacheMode := strings.ToLower(strings.TrimSpace(input.CacheMode))
	switch cacheMode {
	case "", "default":
		if strings.TrimSpace(input.CacheCapacity) != "" {
			return nil, protocol.ErrConfiguration
		}
	case "disabled", "bounded":
		capacity := 4096
		if strings.TrimSpace(input.CacheCapacity) != "" {
			var err error
			capacity, err = strconv.Atoi(strings.TrimSpace(input.CacheCapacity))
			if err != nil {
				return nil, protocol.ErrConfiguration
			}
		}
		options.DNSCache = &protocol.DNSCacheOptions{Disabled: cacheMode == "disabled", Capacity: capacity}
	default:
		return nil, protocol.ErrConfiguration
	}
	options.AllowLAN = input.AllowLAN
	if mode != "default" {
		port := 0
		if strings.TrimSpace(input.Port) != "" {
			parsed, err := strconv.Atoi(strings.TrimSpace(input.Port))
			if err != nil {
				return nil, protocol.ErrConfiguration
			}
			port = parsed
		}
		options.DNS = &protocol.DNSOptions{Transport: mode, ServerIP: input.ServerIP, ServerName: input.ServerName, Port: port, Path: input.Path}
	} else if input.ServerIP != "" || input.ServerName != "" || input.Port != "" || input.Path != "" {
		return nil, protocol.ErrConfiguration
	}
	if strings.HasPrefix(strings.TrimSpace(input.RulesText), "{") {
		if len(input.RulesText) > 8*1024*1024 {
			return nil, protocol.ErrConfiguration
		}
		var policy struct {
			Rules    []protocol.NetworkRule
			Targets  []protocol.PolicyTarget
			RuleSets []protocol.RuleSet
		}
		decoder := json.NewDecoder(bytes.NewBufferString(input.RulesText))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&policy) != nil {
			return nil, protocol.ErrConfiguration
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			return nil, protocol.ErrConfiguration
		}
		options.Rules, options.Targets, options.RuleSets = policy.Rules, policy.Targets, policy.RuleSets
	} else if strings.TrimSpace(input.RulesText) != "" {
		for _, raw := range strings.Split(input.RulesText, "\n") {
			line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
			if line == "" {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) != 3 {
				return nil, protocol.ErrConfiguration
			}
			options.Rules = append(options.Rules, protocol.NetworkRule{Kind: strings.TrimSpace(parts[0]), Action: strings.TrimSpace(parts[1]), Value: strings.TrimSpace(parts[2])})
			if len(options.Rules) > protocol.MaxNetworkRules {
				return nil, protocol.ErrConfiguration
			}
		}
	}
	if strings.TrimSpace(input.ResolversText) != "" {
		for _, raw := range strings.Split(input.ResolversText, "\n") {
			line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
			if line == "" {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) != 5 {
				return nil, protocol.ErrConfiguration
			}
			port := 0
			if strings.TrimSpace(parts[3]) != "" {
				parsed, err := strconv.Atoi(strings.TrimSpace(parts[3]))
				if err != nil {
					return nil, protocol.ErrConfiguration
				}
				port = parsed
			}
			options.Resolvers = append(options.Resolvers, protocol.DNSOptions{
				Transport: strings.TrimSpace(parts[0]), ServerIP: strings.TrimSpace(parts[1]),
				ServerName: strings.TrimSpace(parts[2]), Port: port, Path: strings.TrimSpace(parts[4]),
			})
			if len(options.Resolvers) > protocol.MaxDNSResolvers {
				return nil, protocol.ErrConfiguration
			}
		}
	}
	if strings.TrimSpace(input.DNSRulesText) != "" {
		for _, raw := range strings.Split(input.DNSRulesText, "\n") {
			line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
			if line == "" {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) != 3 {
				return nil, protocol.ErrConfiguration
			}
			resolver, err := strconv.Atoi(strings.TrimSpace(parts[2]))
			if err != nil || resolver < 1 {
				return nil, protocol.ErrConfiguration
			}
			options.DNSRules = append(options.DNSRules, protocol.DNSRule{Kind: strings.TrimSpace(parts[0]), Value: strings.TrimSpace(parts[1]), ResolverIndex: resolver - 1})
			if len(options.DNSRules) > protocol.MaxDNSRules {
				return nil, protocol.ErrConfiguration
			}
		}
	}
	return protocol.NormalizeNetworkOptions(options)
}

func (a *Application) networkPreferencesView(id string) (NetworkPreferencesView, error) {
	if a == nil || a.Store == nil {
		return NetworkPreferencesView{}, errors.New("profile library unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return NetworkPreferencesView{}, errors.New("profile library unavailable")
	}
	view := NetworkPreferencesView{ID: id, Token: fmtHex(a.Store.revision[:]), Mode: "default", Supported: false, CanSave: a.refreshAllowed()}
	for _, profile := range doc.Profiles {
		if profile.ID != id {
			continue
		}
		view.Supported = profile.Protocol >= 0 && profile.Protocol <= protocol.MaxKind
		view.CanSave = view.CanSave && view.Supported
		if dns := profile.Network; dns != nil {
			view.FakeIP = dns.FakeIP
			if dns.DNSCache != nil {
				view.CacheMode = "bounded"
				if dns.DNSCache.Disabled {
					view.CacheMode = "disabled"
				}
				view.CacheCapacity = strconv.Itoa(dns.DNSCache.Capacity)
			}
			view.AllowLAN = dns.AllowLAN
			if dns.DNS != nil {
				view.Mode, view.ServerIP, view.ServerName = dns.DNS.Transport, dns.DNS.ServerIP, dns.DNS.ServerName
				if dns.DNS.Port != 0 {
					view.Port = strconv.Itoa(dns.DNS.Port)
				}
				view.Path = dns.DNS.Path
			}
			for _, rule := range dns.Rules {
				view.RulesText += rule.Kind + " | " + rule.Action + " | " + rule.Value + "\n"
			}
			for _, resolver := range dns.Resolvers {
				port := ""
				if resolver.Port != 0 {
					port = strconv.Itoa(resolver.Port)
				}
				view.ResolversText += resolver.Transport + " | " + resolver.ServerIP + " | " + resolver.ServerName + " | " + port + " | " + resolver.Path + "\n"
			}
			for _, rule := range dns.DNSRules {
				view.DNSRulesText += rule.Kind + " | " + rule.Value + " | " + strconv.Itoa(rule.ResolverIndex+1) + "\n"
			}
		}
		if dns := profile.Network; dns != nil {
			advanced := len(dns.Targets) > 0 || len(dns.RuleSets) > 0
			for _, rule := range dns.Rules {
				advanced = advanced || rule.Port != "" || rule.Network != "" || rule.Process != "" || rule.Outbound != ""
			}
			if advanced {
				data, err := json.MarshalIndent(struct {
					Rules    []protocol.NetworkRule
					Targets  []protocol.PolicyTarget `json:"Targets,omitempty"`
					RuleSets []protocol.RuleSet      `json:"RuleSets,omitempty"`
				}{dns.Rules, dns.Targets, dns.RuleSets}, "", "  ")
				if err != nil {
					return NetworkPreferencesView{}, err
				}
				view.RulesText = string(data)
			}
		}
		state, stateErr := routingView(doc, profile).normalized()
		if stateErr != nil {
			return NetworkPreferencesView{}, stateErr
		}
		view.RoutingMode, view.CustomRulesText, view.PresetRulesText = state.Mode, state.CustomRulesText, state.PresetRulesText
		preset, _ := (NetworkInput{Mode: "default", RulesText: state.PresetRulesText}).Parse()
		view.PresetSummary = presetSummary(preset)
		if !view.Supported {
			view.Message = "Network preferences require a supported full-device profile."
		} else if profile.Protocol < 2 {
			view.Message = "Nonempty preferences use the shared TUN for TCP/UDP in full-device mode. Policy DNS replaces imported DNS; peer AllowedIPs are preserved. ICMP is unavailable in this mode. Reset all preferences to restore the native path."
		}
		return view, nil
	}
	return NetworkPreferencesView{}, errors.New("profile unavailable")
}

func (a *Application) saveNetworkPreferences(r Request) (Document, error) {
	if a == nil || a.Store == nil || !a.refreshAllowed() {
		return Document{}, errors.New("network preferences are unavailable while the connection is active or protected")
	}
	if r.NetworkInput == nil || r.ID == "" {
		return Document{}, protocol.ErrConfiguration
	}
	doc, err := a.Store.Load()
	if err != nil {
		return Document{}, errors.New("profile library unavailable")
	}
	if r.Token == "" || r.Token != fmtHex(a.Store.revision[:]) {
		return Document{}, errors.New("profile list changed; reload before saving")
	}
	for i := range doc.Profiles {
		if doc.Profiles[i].ID != r.ID {
			continue
		}
		if doc.Profiles[i].Protocol < 0 || doc.Profiles[i].Protocol > protocol.MaxKind {
			return Document{}, protocol.ErrConfiguration
		}
		network, parseErr := r.NetworkInput.Parse()
		if parseErr != nil {
			return Document{}, parseErr
		}
		stateChanged := false
		if r.NetworkInput.RoutingMode != "" {
			state, stateErr := r.NetworkInput.routingPreferences()
			if stateErr != nil {
				return Document{}, stateErr
			}
			stateChanged = doc.RoutingProfiles[r.ID] != state
			if doc.RoutingProfiles == nil {
				doc.RoutingProfiles = map[string]RoutingPreferences{}
			}
			doc.RoutingProfiles[r.ID] = state
		} else if _, ok := doc.RoutingProfiles[r.ID]; ok {
			state := doc.RoutingProfiles[r.ID]
			state.Mode = inferRouting(network)
			if state.Mode == "custom" {
				state.CustomRulesText = routeText(network)
			}
			if state.Mode == "preset" {
				state.PresetRulesText = routeText(network)
			}
			stateChanged = doc.RoutingProfiles[r.ID] != state
			doc.RoutingProfiles[r.ID] = state
		}
		if protocol.NetworkOptionsEquivalent(doc.Profiles[i].Network, network) && !stateChanged {
			return presentationDocument(doc), nil
		}
		doc.Profiles[i].Network = network
		if err = Validate(doc.Profiles[i]); err != nil {
			return Document{}, err
		}
		if err = a.Store.Save(doc); err != nil {
			return Document{}, err
		}
		return presentationDocument(doc), nil
	}
	return Document{}, errors.New("profile unavailable")
}

func (a *Application) analyzeNetwork(id string, query *protocol.RouteQuery) (any, error) {
	if a == nil || a.Store == nil {
		return nil, errors.New("profile library unavailable")
	}
	doc, err := a.Store.Load()
	if err != nil {
		return nil, err
	}
	for _, p := range doc.Profiles {
		if p.ID != id {
			continue
		}
		if err := Validate(p); err != nil {
			return nil, err
		}
		analysis, err := protocol.AnalyzeNetwork(p.Network)
		if err != nil {
			return nil, err
		}
		if query == nil {
			return analysis, nil
		}
		return protocol.ExplainRoute(p.Network, *query)
	}
	return nil, errors.New("profile unavailable")
}
