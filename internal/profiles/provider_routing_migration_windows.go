package profiles

import (
	"encoding/json"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func migrateProviderAddressRouting(doc *Document) error {
	for id, state := range doc.RoutingProfiles {
		var sources []presetSource
		if json.Unmarshal([]byte(state.PresetConfigText), &sources) != nil || len(sources) != 1 || sources[0].Format != "provider-xray" || (sources[0].Scope == "addresses" || sources[0].Scope == "addresses-legacy") {
			continue
		}
		n, e := (NetworkInput{Mode: "default", RulesText: state.PresetRulesText}).Parse()
		if e != nil {
			return e
		}
		if n == nil {
			n = &protocol.NetworkOptions{}
		}
		kept := []protocol.NetworkRule{}
		used := map[string]bool{}
		for _, r := range n.Rules {
			if (r.Kind == "rule-set" || r.Kind == "domain" || r.Kind == "domain-suffix" || r.Kind == "cidr") && r.Port == "" && r.Network == "" && r.Process == "" && r.Outbound == "" {
				kept = append(kept, r)
				if r.Kind == "rule-set" {
					used[r.Value] = true
				}
			}
		}
		sets := []protocol.RuleSet{}
		for _, set := range n.RuleSets {
			if used[set.Name] {
				sets = append(sets, set)
			}
		}
		n.Rules = kept
		n.RuleSets = sets
		n.Targets = nil
		state.PresetRulesText = routeText(n)
		sources[0].Scope = "addresses-legacy"
		if sources[0].Group != "" {
			sources[0].Label = sources[0].Group
		}
		sources[0].Warnings = []string{"Используются только правила по доменам и IP. Балансировщик, порты и дополнительные условия исключены. Выберите подписку заново, чтобы собрать общую маршрутизацию из всех её конфигураций."}
		state.PresetConfigText = encodePresetCatalog(sources)
		doc.RoutingProfiles[id] = state
		if state.Mode == "preset" {
			for i := range doc.Profiles {
				if doc.Profiles[i].ID == id {
					network := protocol.CloneNetworkOptions(doc.Profiles[i].Network)
					if network == nil {
						network = &protocol.NetworkOptions{}
					}
					network.Rules = kept
					network.RuleSets = sets
					network.Targets = nil
					doc.Profiles[i].Network, e = protocol.NormalizeNetworkOptions(network)
					if e != nil {
						return e
					}
				}
			}
		}
	}
	return nil
}
