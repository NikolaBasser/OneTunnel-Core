package protocol

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Compact snapshots keep imported lists within the control protocol's frame limit.
const MaxRuleDataBytes = 16 * 1024 * 1024
const MaxRuleSnapshotBytes = 2 * 1024 * 1024

type RuleSetData struct {
	Domain        []string `json:"Domain,omitempty"`
	DomainSuffix  []string `json:"DomainSuffix,omitempty"`
	DomainKeyword []string `json:"DomainKeyword,omitempty"`
	DomainRegex   []string `json:"DomainRegex,omitempty"`
	IPCIDR        []string `json:"IPCIDR,omitempty"`
}

type plainRuleData RuleSetData

func (d RuleSetData) MarshalJSON() ([]byte, error) {
	raw, e := json.Marshal(plainRuleData(d))
	if e != nil {
		return nil, e
	}
	if len(raw) > MaxRuleDataBytes {
		return nil, ErrConfiguration
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, e = writer.Write(raw); e != nil {
		return nil, e
	}
	if e = writer.Close(); e != nil {
		return nil, e
	}
	if buffer.Len() > MaxRuleSnapshotBytes {
		return nil, ErrConfiguration
	}
	return json.Marshal(struct{ Snapshot []byte }{buffer.Bytes()})
}
func (d *RuleSetData) UnmarshalJSON(raw []byte) error {
	// A snapshot is bounded both before and after decompression; mixed encodings fail.
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return e
	}
	if b, ok := fields["Snapshot"]; ok {
		if len(fields) != 1 || len(b) > MaxRuleSnapshotBytes*2 {
			return ErrConfiguration
		}
		var packed []byte
		if e := json.Unmarshal(b, &packed); e != nil {
			return e
		}
		if len(packed) > MaxRuleSnapshotBytes {
			return ErrConfiguration
		}
		reader, e := gzip.NewReader(bytes.NewReader(packed))
		if e != nil {
			return e
		}
		defer reader.Close()
		raw, e = io.ReadAll(io.LimitReader(reader, MaxRuleDataBytes+1))
		if e != nil || len(raw) > MaxRuleDataBytes {
			return ErrConfiguration
		}
	}
	var plain plainRuleData
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&plain); e != nil {
		return fmt.Errorf("rule_snapshot: %w", e)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return ErrConfiguration
	}
	*d = RuleSetData(plain)
	return d.normalize()
}

func (d *RuleSetData) clone() *RuleSetData {
	if d == nil {
		return nil
	}
	c := *d
	c.Domain = slices.Clone(d.Domain)
	c.DomainSuffix = slices.Clone(d.DomainSuffix)
	c.DomainKeyword = slices.Clone(d.DomainKeyword)
	c.DomainRegex = slices.Clone(d.DomainRegex)
	c.IPCIDR = slices.Clone(d.IPCIDR)
	return &c
}
func (d *RuleSetData) normalize() error {
	count, size := 0, 0
	for kind, values := range []*[]string{&d.Domain, &d.DomainSuffix, &d.DomainKeyword, &d.DomainRegex, &d.IPCIDR} {
		for i, v := range *values {
			count++
			size += len(v) + 4
			if count > 500000 || size > MaxRuleDataBytes || v == "" || !utf8.ValidString(v) {
				return ErrConfiguration
			}
			switch kind {
			case 0, 1:
				var ok bool
				v, ok = normalizeHostname(v)
				if !ok {
					return ErrConfiguration
				}
			case 2:
				if len(v) > 253 || strings.ContainsAny(v, "\r\n\x00") {
					return ErrConfiguration
				}
				v = strings.ToLower(v)
			case 3:
				if len(*values) > 256 || len(v) > 2048 {
					return ErrConfiguration
				}
				if _, e := regexp.Compile(v); e != nil {
					return ErrConfiguration
				}
			case 4:
				p, e := netip.ParsePrefix(v)
				if e != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" {
					return ErrConfiguration
				}
				v = p.Masked().String()
			}
			(*values)[i] = v
		}
		slices.Sort(*values)
		*values = slices.Compact(*values)
	}
	if count == 0 {
		return ErrConfiguration
	}
	return nil
}
func (d *RuleSetData) matcher() object {
	rules := []any{}
	for key, v := range map[string][]string{"domain": d.Domain, "domain_suffix": d.DomainSuffix, "domain_keyword": d.DomainKeyword, "domain_regex": d.DomainRegex, "ip_cidr": d.IPCIDR} {
		if len(v) > 0 {
			rules = append(rules, object{key: v})
		}
	}
	return object{"type": "logical", "mode": "or", "rules": rules}
}
func (d *RuleSetData) match(q RouteQuery) int {
	unknown := false
	if len(d.Domain)+len(d.DomainSuffix)+len(d.DomainKeyword)+len(d.DomainRegex) > 0 {
		if q.Domain == "" {
			unknown = true
		} else {
			if _, ok := slices.BinarySearch(d.Domain, q.Domain); ok {
				return 1
			}
			for _, v := range d.DomainSuffix {
				if q.Domain == v || strings.HasSuffix(q.Domain, "."+v) {
					return 1
				}
			}
			for _, v := range d.DomainKeyword {
				if strings.Contains(q.Domain, v) {
					return 1
				}
			}
			for _, v := range d.DomainRegex {
				re, e := regexp.Compile(v)
				if e == nil && re.MatchString(q.Domain) {
					return 1
				}
			}
		}
	}
	if len(d.IPCIDR) > 0 {
		if q.IP == "" {
			unknown = true
		} else {
			ip, _ := netip.ParseAddr(q.IP)
			for _, v := range d.IPCIDR {
				p, _ := netip.ParsePrefix(v)
				if p.Contains(ip) {
					return 1
				}
			}
		}
	}
	if unknown {
		return -1
	}
	return 0
}
