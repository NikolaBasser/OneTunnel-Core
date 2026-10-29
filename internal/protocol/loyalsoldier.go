package protocol

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const MaxGeoFileBytes = 64 * 1024 * 1024

// Select before decoding: the global GeoIP database need not be expanded in memory.
func geoEntry(content []byte, category string) ([]byte, error) {
	var selected []byte
	for len(content) > 0 {
		field, wire, n := protowire.ConsumeTag(content)
		if n < 0 {
			return nil, fmt.Errorf("rule_import_protobuf")
		}
		content = content[n:]
		size := protowire.ConsumeFieldValue(field, wire, content)
		if size < 0 {
			return nil, fmt.Errorf("rule_import_protobuf")
		}
		if field == 1 && wire == protowire.BytesType {
			entry, k := protowire.ConsumeBytes(content)
			if k < 0 {
				return nil, fmt.Errorf("rule_import_protobuf")
			}
			code := ""
			remaining := entry
			for len(remaining) > 0 {
				f, w, t := protowire.ConsumeTag(remaining)
				if t < 0 {
					return nil, fmt.Errorf("rule_import_protobuf")
				}
				remaining = remaining[t:]
				v := protowire.ConsumeFieldValue(f, w, remaining)
				if v < 0 {
					return nil, fmt.Errorf("rule_import_protobuf")
				}
				if f == 1 && w == protowire.BytesType {
					s, _ := protowire.ConsumeString(remaining)
					code = s
				}
				remaining = remaining[v:]
			}
			if strings.EqualFold(code, category) {
				if selected != nil {
					return nil, fmt.Errorf("rule_import_duplicate_category")
				}
				selected = entry
			}
		}
		content = content[size:]
	}
	if selected == nil || len(selected) > 8*1024*1024 {
		return nil, fmt.Errorf("rule_import_category_missing_or_too_large")
	}
	return selected, nil
}

// ImportLoyalsoldier snapshots one category; it never chooses routing actions.
func ImportLoyalsoldier(format, category string, content []byte) (*RuleSetData, error) {
	if len(content) == 0 || len(content) > MaxGeoFileBytes {
		return nil, fmt.Errorf("rule_import_size")
	}
	category = strings.ToLower(strings.TrimSpace(category))
	d := &RuleSetData{}
	switch format {
	case "geosite":
		parts := strings.Split(category, "@")
		if len(parts) > 2 || parts[0] == "" || len(parts) == 2 && parts[1] == "" {
			return nil, fmt.Errorf("rule_import_category")
		}
		entry, e := geoEntry(content, parts[0])
		if e != nil {
			return nil, e
		}
		var site geodata.GeoSite
		if e := (proto.UnmarshalOptions{DiscardUnknown: true, RecursionLimit: 32}).Unmarshal(entry, &site); e != nil {
			return nil, fmt.Errorf("rule_import_geosite")
		}
		for _, v := range site.Domain {
			if len(parts) == 2 {
				match := false
				for _, a := range v.Attribute {
					if strings.EqualFold(a.Key, parts[1]) && a.GetBoolValue() {
						match = true
					}
				}
				if !match {
					continue
				}
			}
			switch v.Type {
			case geodata.Domain_Full:
				d.Domain = append(d.Domain, v.Value)
			case geodata.Domain_Domain:
				d.DomainSuffix = append(d.DomainSuffix, v.Value)
			case geodata.Domain_Substr:
				d.DomainKeyword = append(d.DomainKeyword, v.Value)
			case geodata.Domain_Regex:
				d.DomainRegex = append(d.DomainRegex, v.Value)
			default:
				return nil, fmt.Errorf("rule_import_domain_type")
			}
		}
	case "geoip":
		selected, e := geoEntry(content, category)
		if e != nil {
			return nil, e
		}
		var entry geodata.GeoIP
		if e := (proto.UnmarshalOptions{DiscardUnknown: true, RecursionLimit: 32}).Unmarshal(selected, &entry); e != nil || entry.ReverseMatch {
			return nil, fmt.Errorf("rule_import_geoip_or_inverse")
		}
		for _, v := range entry.Cidr {
			ip, ok := netip.AddrFromSlice(v.Ip)
			if !ok || ip.Is4In6() || int(v.Prefix) > ip.BitLen() {
				return nil, fmt.Errorf("rule_import_cidr")
			}
			d.IPCIDR = append(d.IPCIDR, netip.PrefixFrom(ip, int(v.Prefix)).Masked().String())
		}
	default:
		return nil, fmt.Errorf("rule_import_format")
	}
	if e := d.normalize(); e != nil {
		return nil, fmt.Errorf("rule_import_empty_invalid_or_too_large: %w", e)
	}
	return d, nil
}
