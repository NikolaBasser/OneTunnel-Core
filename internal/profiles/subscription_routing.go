package profiles

import "encoding/json"

// Retain routing at subscription import time without copying server credentials.
func subscriptionRoutingSnapshot(configs []any) json.RawMessage {
	var policies []any
	for _, item := range configs {
		c, ok := item.(map[string]any)
		if !ok {
			continue
		}
		routing, ok := c["routing"].(map[string]any)
		if !ok {
			continue
		}
		rules, ok := routing["rules"].([]any)
		if !ok || len(rules) == 0 {
			continue
		}
		var outbounds []any
		if outs, ok := c["outbounds"].([]any); ok {
			for _, out := range outs {
				if o, ok := out.(map[string]any); ok {
					outbounds = append(outbounds, map[string]any{"tag": o["tag"], "protocol": o["protocol"]})
				}
			}
		}
		policies = append(policies, map[string]any{"remarks": c["remarks"], "outbounds": outbounds, "routing": map[string]any{"rules": rules, "domainStrategy": routing["domainStrategy"]}})
	}
	if len(policies) == 0 {
		return nil
	}
	b, _ := json.Marshal(policies)
	return b
}
