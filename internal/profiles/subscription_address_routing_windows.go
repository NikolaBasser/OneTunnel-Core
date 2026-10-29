package profiles

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

// Subscription presets describe destinations, not transport or server selection.
func subscriptionAddressRouting(raw []byte) ([]byte, error) {
	var configs []providerConfig
	if json.Unmarshal(raw, &configs) != nil {
		return nil, ErrImport
	}
	var rules []json.RawMessage
	seen := map[string]bool{}
	selectors := map[string]string{}
	actions := map[string]bool{}
	var signatures []string
	for _, c := range configs {
		tags := map[string]string{}
		for _, out := range c.Outbounds {
			switch out.Protocol {
			case "freedom":
				tags[out.Tag] = "direct"
			case "blackhole":
				tags[out.Tag] = "reject"
			case "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria", "hysteria2", "wireguard":
				tags[out.Tag] = "proxy"
			}
		}
		var signature []string
		for _, r := range c.Routing.Rules {
			var fields map[string]json.RawMessage
			if json.Unmarshal(r, &fields) != nil {
				return nil, ErrImport
			}
			valid := true
			for k := range fields {
				if !slices.Contains([]string{"type", "domain", "ip", "outboundTag"}, k) {
					valid = false
				}
			}
			if !valid {
				continue
			}
			var rule struct {
				Type, OutboundTag string
				Domain, IP        []string
			}
			if json.Unmarshal(r, &rule) != nil || rule.Type != "field" || len(rule.Domain)+len(rule.IP) == 0 || len(rule.Domain) > 0 && len(rule.IP) > 0 {
				continue
			}
			action := tags[rule.OutboundTag]
			if action == "" {
				continue
			}
			actions[action] = true
			values, kind := rule.Domain, "domain"
			if len(rule.IP) > 0 {
				values, kind = rule.IP, "ip"
			}
			values = slices.Clone(values)
			slices.Sort(values)
			values = slices.Compact(values)
			for _, value := range values {
				key := kind + ":" + value
				if previous := selectors[key]; previous != "" && previous != action {
					return nil, errors.New("В подписке противоречащие действия для одного домена или IP. Используйте режим «Свои правила».")
				}
				selectors[key] = action
			}
			encoded, _ := json.Marshal(map[string]any{"type": "field", kind: values, "outboundTag": action})
			key := string(encoded)
			signature = append(signature, key)
			if !seen[key] {
				seen[key] = true
				rules = append(rules, encoded)
			}
		}
		if len(signature) > 0 {
			signatures = append(signatures, strings.Join(signature, "\n"))
		}
	}
	// Union is unambiguous for one action. Different ordered multi-action schemes
	// need personal rules rather than an implicit server configuration choice.
	if len(actions) > 1 && len(signatures) > 1 {
		for _, signature := range signatures[1:] {
			if signature != signatures[0] {
				return nil, errors.New("В подписке различаются порядок и действия правил. Используйте режим «Свои правила».")
			}
		}
	}
	if len(actions) == 1 {
		action := ""
		for a := range actions {
			action = a
		}
		byKind := map[string][]string{}
		for _, rawRule := range rules {
			var r struct{ Domain, IP []string }
			json.Unmarshal(rawRule, &r)
			byKind["domain"] = append(byKind["domain"], r.Domain...)
			byKind["ip"] = append(byKind["ip"], r.IP...)
		}
		rules = nil
		for _, kind := range []string{"domain", "ip"} {
			values := byKind[kind]
			if len(values) == 0 {
				continue
			}
			slices.Sort(values)
			values = slices.Compact(values)
			encoded, _ := json.Marshal(map[string]any{"type": "field", kind: values, "outboundTag": action})
			rules = append(rules, encoded)
		}
	}
	out := map[string]any{"remarks": "Маршрутизация подписки", "outbounds": []any{map[string]string{"tag": "direct", "protocol": "freedom"}, map[string]string{"tag": "reject", "protocol": "blackhole"}, map[string]string{"tag": "proxy", "protocol": "vless"}}, "routing": map[string]any{"rules": rules}}
	return json.Marshal([]any{out})
}
