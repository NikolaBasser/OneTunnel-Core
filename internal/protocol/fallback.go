package protocol

import (
	"net/netip"
	"sort"
	"strings"
)

// A backup must not silently widen a configuration-mode native tunnel's scope.
func NativeRouteScope(source string, kind int) (string, error) {
	plan, err := Compile(source, kind, false, 0, 0, "")
	if err != nil {
		return "", err
	}
	fields := []string{}
	families := map[string]bool{}
	for _, raw := range strings.Split(plan.NativeSource, "\n") {
		parts := strings.SplitN(strings.TrimSpace(strings.SplitN(raw, "#", 2)[0]), "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		if key != "allowedips" && key != "address" {
			continue
		}
		for _, item := range strings.Split(parts[1], ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
			if err != nil {
				return "", err
			}
			if key == "allowedips" {
				fields = append(fields, prefix.Masked().String())
			} else if prefix.Addr().Is4() {
				families["ipv4"] = true
			} else {
				families["ipv6"] = true
			}
		}
	}
	for family := range families {
		fields = append(fields, family)
	}
	sort.Strings(fields)
	return strings.Join(fields, ";"), nil
}
