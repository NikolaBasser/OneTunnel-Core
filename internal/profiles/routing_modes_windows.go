package profiles

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

// Only the selected bank is copied into Profile.Network and sent to the service.
type RoutingPreferences struct{ Mode, CustomRulesText, PresetRulesText string }

func presetSummary(n *protocol.NetworkOptions) string {
	if n == nil || len(n.Rules) == 0 {
		return "Пресеты не добавлены."
	}
	var lines []string
	for _, r := range n.Rules {
		action := map[string]string{"proxy": "Через VPN", "direct": "Напрямую", "reject": "Блокировать"}[r.Action]
		lines = append(lines, r.Value+" · "+action)
	}
	return strings.Join(lines, "\n")
}

func routeText(n *protocol.NetworkOptions) string {
	if n == nil {
		return ""
	}
	advanced := len(n.Targets) > 0 || len(n.RuleSets) > 0
	for _, r := range n.Rules {
		advanced = advanced || r.Port != "" || r.Network != "" || r.Process != "" || r.Outbound != ""
	}
	if !advanced {
		var b strings.Builder
		for _, r := range n.Rules {
			fmt.Fprintf(&b, "%s | %s | %s\n", r.Kind, r.Action, r.Value)
		}
		return b.String()
	}
	raw, _ := json.MarshalIndent(struct {
		Rules    []protocol.NetworkRule
		Targets  []protocol.PolicyTarget `json:",omitempty"`
		RuleSets []protocol.RuleSet      `json:",omitempty"`
	}{n.Rules, n.Targets, n.RuleSets}, "", "  ")
	return string(raw)
}
func presetOnly(n *protocol.NetworkOptions) bool {
	if n == nil {
		return true
	}
	if len(n.Targets) > 0 {
		return false
	}
	for _, s := range n.RuleSets {
		if s.Data == nil {
			return false
		}
	}
	for _, r := range n.Rules {
		if r.Kind != "rule-set" || r.Port != "" || r.Network != "" || r.Process != "" || r.Outbound != "" {
			return false
		}
	}
	return true
}
func inferRouting(n *protocol.NetworkOptions) string {
	if n == nil || len(n.Rules)+len(n.Targets)+len(n.RuleSets) == 0 {
		return "none"
	}
	if presetOnly(n) {
		return "preset"
	}
	return "custom"
}
func (p RoutingPreferences) normalized() (RoutingPreferences, error) {
	if p.Mode != "none" && p.Mode != "preset" && p.Mode != "custom" {
		return p, protocol.ErrConfiguration
	}
	for i, text := range []string{p.CustomRulesText, p.PresetRulesText} {
		n, e := (NetworkInput{Mode: "default", RulesText: text}).Parse()
		if e != nil {
			return p, e
		}
		if i == 1 && !presetOnly(n) {
			return p, fmt.Errorf("Пресеты содержат только импортированные наборы; ручные правила задайте в режиме «Свои правила».")
		}
		if i == 0 {
			p.CustomRulesText = routeText(n)
		} else {
			p.PresetRulesText = routeText(n)
		}
	}
	return p, nil
}
func routingView(doc Document, p Profile) RoutingPreferences {
	state, ok := doc.RoutingProfiles[p.ID]
	if !ok {
		state.Mode = inferRouting(p.Network)
	}
	// Explicit policy edits through the legacy editor remain authoritative.
	if state.Mode == "custom" {
		state.CustomRulesText = routeText(p.Network)
	}
	if state.Mode == "preset" {
		state.PresetRulesText = routeText(p.Network)
	}
	return state
}
func normalizeRoutingProfiles(doc *Document) error {
	valid := map[string]Profile{}
	for _, p := range doc.Profiles {
		valid[p.ID] = p
	}
	for id, state := range doc.RoutingProfiles {
		profile, ok := valid[id]
		if !ok {
			delete(doc.RoutingProfiles, id)
			continue
		}
		if state.Mode == "none" && inferRouting(profile.Network) != "none" || state.Mode == "preset" && !presetOnly(profile.Network) {
			state.Mode = inferRouting(profile.Network)
		}
		if state.Mode == "custom" {
			state.CustomRulesText = routeText(profile.Network)
		}
		if state.Mode == "preset" {
			state.PresetRulesText = routeText(profile.Network)
		}
		normalized, e := state.normalized()
		if e != nil {
			return e
		}
		doc.RoutingProfiles[id] = normalized
	}
	return nil
}
func (input NetworkInput) routingPreferences() (RoutingPreferences, error) {
	return (RoutingPreferences{Mode: input.RoutingMode, CustomRulesText: input.CustomRulesText, PresetRulesText: input.PresetRulesText}).normalized()
}
