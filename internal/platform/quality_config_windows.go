package platform

import (
	"errors"
	"net"
)

var errQualityCleanup = errors.New("quality engine cleanup failed")

func prepareQualityConfig(config jsonObject, route func(string) (string, error)) error {
	// Keep saved DNS and policy, but never create a second OS adapter or route.
	inbounds := []any{}
	for _, raw := range jArray(config["inbounds"]) {
		if jString(jObject(raw)["type"]) == "mixed" {
			inbounds = append(inbounds, raw)
		}
	}
	if len(inbounds) != 1 {
		return errors.New("quality requires one loopback ingress")
	}
	config["inbounds"] = inbounds
	delete(config, "ntp")
	routing := jObject(config["route"])
	routing["auto_detect_interface"] = false
	rules := []any{}
	for _, raw := range jArray(routing["rules"]) {
		rule := jObject(raw)
		if jString(rule["outbound"]) == "xray-uplink" {
			continue
		}
		// A direct or alternate policy path cannot qualify the primary server.
		if out := jString(rule["outbound"]); out != "" && !qualityUsesPrimary(config, out) {
			delete(rule, "outbound")
			rule["action"] = "reject"
		}
		rules = append(rules, rule)
	}
	routing["rules"] = rules
	config["route"] = routing
	for _, raw := range jArray(config["outbounds"]) {
		out := jObject(raw)
		if jString(out["detour"]) != "" {
			continue
		}
		ip := net.ParseIP(jString(out["server"]))
		if ip == nil || ip.IsLoopback() {
			continue
		}
		name, err := route(ip.String())
		if err != nil {
			return err
		}
		out["bind_interface"] = name
	}
	return nil
}

func qualityUsesPrimary(config jsonObject, tag string) bool {
	seen := map[string]bool{}
	for tag != "" && !seen[tag] {
		if tag == "proxy" {
			return true
		}
		seen[tag] = true
		next := ""
		for _, raw := range jArray(config["outbounds"]) {
			out := jObject(raw)
			if jString(out["tag"]) == tag {
				next = jString(out["detour"])
				break
			}
		}
		tag = next
	}
	return false
}
