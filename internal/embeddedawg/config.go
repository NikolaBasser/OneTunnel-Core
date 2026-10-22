// Package embeddedawg embeds the pinned AmneziaWG implementation for both WG
// and AWG. Parsing and packet tests do not create OS interfaces or routes.
package embeddedawg

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"onetunnel/core/internal/protocol"
	"strconv"
	"strings"
)

type Plan struct {
	Addresses     []netip.Prefix
	Routes        []netip.Prefix
	DNS           []net.IP
	SearchDomains []string
	MTU           int
	values        map[string]string
}

func Parse(source string, kind int, full bool) (*Plan, error) {
	if kind != 0 && kind != 1 {
		return nil, protocol.ErrConfiguration
	}
	compiled, err := protocol.Compile(source, kind, full, 1, 2, "unused")
	if err != nil {
		return nil, err
	}
	p := &Plan{MTU: 1420, values: map[string]string{}}
	section := ""
	for _, line := range strings.Split(strings.ReplaceAll(compiled.NativeSource, "\r", ""), "\n") {
		line = strings.TrimSpace(strings.SplitN(strings.SplitN(line, "#", 2)[0], ";", 2)[0])
		if line == "" {
			continue
		}
		if strings.EqualFold(line, "[Interface]") {
			section = "i"
			continue
		}
		if strings.EqualFold(line, "[Peer]") {
			section = "p"
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 {
			return nil, protocol.ErrConfiguration
		}
		key, value := strings.ToLower(strings.TrimSpace(pair[0])), strings.TrimSpace(pair[1])
		p.values[section+key] = value
	}
	for _, entry := range []struct {
		key    string
		target *[]netip.Prefix
	}{{"iaddress", &p.Addresses}, {"pallowedips", &p.Routes}} {
		for _, raw := range strings.Split(p.values[entry.key], ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil {
				return nil, protocol.ErrConfiguration
			}
			*entry.target = append(*entry.target, prefix)
		}
	}
	if mtu := p.values["imtu"]; mtu != "" {
		p.MTU, err = strconv.Atoi(mtu)
		if err != nil || p.MTU < 576 || p.MTU > 65535 {
			return nil, protocol.ErrConfiguration
		}
	}
	for _, prefix := range p.Addresses {
		if prefix.Addr().Is6() && p.MTU < 1280 {
			return nil, protocol.ErrConfiguration
		}
	}
	if raw := p.values["idns"]; raw != "" {
		for _, v := range strings.Split(raw, ",") {
			v = strings.TrimSpace(v)
			if ip := net.ParseIP(v); ip != nil {
				p.DNS = append(p.DNS, ip)
			} else {
				if len(v) > 253 || strings.ContainsAny(v, " \t/\\:") {
					return nil, protocol.ErrConfiguration
				}
				p.SearchDomains = append(p.SearchDomains, v)
			}
		}
	}
	return p, nil
}

func (p *Plan) Endpoint() string { return p.values["pendpoint"] }
func (p *Plan) SetEndpoint(value string) error {
	if _, err := netip.ParseAddrPort(value); err != nil {
		return errors.New("AWG endpoint must be resolved")
	}
	p.values["pendpoint"] = value
	return nil
}

func (p *Plan) UAPI() ([]byte, error) {
	if _, err := netip.ParseAddrPort(p.Endpoint()); err != nil {
		return nil, errors.New("AWG endpoint must be resolved")
	}
	var b strings.Builder
	write := func(key, value string) { b.WriteString(key); b.WriteByte('='); b.WriteString(value); b.WriteByte('\n') }
	key := func(field string) (string, error) {
		raw, err := base64.StdEncoding.DecodeString(p.values[field])
		if err != nil || len(raw) != 32 {
			return "", protocol.ErrConfiguration
		}
		defer clear(raw)
		return hex.EncodeToString(raw), nil
	}
	private, err := key("iprivatekey")
	if err != nil {
		return nil, err
	}
	write("private_key", private)
	if port := p.values["ilistenport"]; port != "" {
		write("listen_port", port)
	}
	for _, field := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"} {
		if value := p.values["i"+field]; value != "" {
			write(field, value)
		}
	}
	write("replace_peers", "true")
	public, err := key("ppublickey")
	if err != nil {
		return nil, err
	}
	write("public_key", public)
	if p.values["ppresharedkey"] != "" {
		v, err := key("ppresharedkey")
		if err != nil {
			return nil, err
		}
		write("preshared_key", v)
	}
	write("endpoint", p.Endpoint())
	write("replace_allowed_ips", "true")
	for _, prefix := range p.Routes {
		write("allowed_ip", prefix.Masked().String())
	}
	if interval := p.values["ppersistentkeepalive"]; interval != "" {
		write("persistent_keepalive_interval", interval)
	}
	return []byte(b.String()), nil
}
