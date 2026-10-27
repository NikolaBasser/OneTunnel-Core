// Package embeddedawg embeds the pinned AmneziaWG implementation for both WG
// and AWG. Parsing and packet tests do not create OS interfaces or routes.
package embeddedawg

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"net"
	"net/netip"
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
	peers         []map[string]string
}

// SamePeer prevents a diagnostic transport from roaming an active peer's key.
func (p *Plan) SamePeer(other *Plan) bool {
	if p == nil || other == nil || p.values["iprivatekey"] != other.values["iprivatekey"] {
		return false
	}
	for _, a := range p.peerValues() {
		for _, b := range other.peerValues() {
			if a["ppublickey"] == b["ppublickey"] {
				return true
			}
		}
	}
	return false
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
			p.peers = append(p.peers, map[string]string{})
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 {
			return nil, protocol.ErrConfiguration
		}
		key, value := strings.ToLower(strings.TrimSpace(pair[0])), strings.TrimSpace(pair[1])
		if section == "p" {
			p.peers[len(p.peers)-1][section+key] = value
		} else {
			p.values[section+key] = value
		}
	}
	for key, value := range p.peers[0] {
		p.values[key] = value
	}
	for _, raw := range strings.Split(p.values["iaddress"], ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, protocol.ErrConfiguration
		}
		p.Addresses = append(p.Addresses, prefix)
	}
	for _, peer := range p.peers {
		for _, raw := range strings.Split(peer["pallowedips"], ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil {
				return nil, protocol.ErrConfiguration
			}
			p.Routes = append(p.Routes, prefix)
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
func (p *Plan) peerValues() []map[string]string {
	if len(p.peers) == 0 {
		return []map[string]string{p.values}
	}
	return p.peers
}
func (p *Plan) Endpoints() []string {
	result := []string{}
	for _, peer := range p.peerValues() {
		result = append(result, peer["pendpoint"])
	}
	return result
}
func (p *Plan) ResolveEndpoints(resolve func(string) (string, error)) error {
	resolved := []string{}
	for _, endpoint := range p.Endpoints() {
		value, err := resolve(endpoint)
		if err != nil {
			return err
		}
		if _, err = netip.ParseAddrPort(value); err != nil {
			return errors.New("AWG endpoint must be resolved")
		}
		resolved = append(resolved, value)
	}
	for i, peer := range p.peerValues() {
		peer["pendpoint"] = resolved[i]
	}
	p.values["pendpoint"] = resolved[0]
	return nil
}
func (p *Plan) SetEndpoint(value string) error {
	if len(p.peerValues()) != 1 {
		return errors.New("multiple AWG endpoints require ResolveEndpoints")
	}
	if _, err := netip.ParseAddrPort(value); err != nil {
		return errors.New("AWG endpoint must be resolved")
	}
	p.values["pendpoint"] = value
	p.peerValues()[0]["pendpoint"] = value
	return nil
}

func (p *Plan) UAPI() ([]byte, error) {
	for _, endpoint := range p.Endpoints() {
		if _, err := netip.ParseAddrPort(endpoint); err != nil {
			return nil, errors.New("AWG endpoint must be resolved")
		}
	}
	var b strings.Builder
	write := func(key, value string) { b.WriteString(key); b.WriteByte('='); b.WriteString(value); b.WriteByte('\n') }
	key := func(value string) (string, error) {
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(raw) != 32 {
			return "", protocol.ErrConfiguration
		}
		defer clear(raw)
		return hex.EncodeToString(raw), nil
	}
	private, err := key(p.values["iprivatekey"])
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
	for field, uapi := range map[string]string{"contentpaddingaddition": "content_padding_addition", "rekeyaftertime": "rekey_after_time", "rekeytimeout": "rekey_timeout", "rejectaftertime": "reject_after_time", "keepalivetimeout": "keepalive_timeout", "maxhandshakeattempts": "max_handshake_attempts"} {
		if value := p.values["i"+field]; value != "" {
			write(uapi, value)
		}
	}
	if p.values["iheaderprotectionkey"] != "" {
		value, err := key(p.values["iheaderprotectionkey"])
		if err != nil {
			return nil, err
		}
		write("header_protection_key", value)
	}
	for field, uapi := range map[string]string{"randomtrailers": "random_trailers", "disablecookies": "disable_cookies"} {
		if value := strings.ToLower(p.values["i"+field]); value != "" {
			write(uapi, strconv.FormatBool(value == "on" || value == "true"))
		}
	}
	write("replace_peers", "true")
	for _, peer := range p.peerValues() {
		public, err := key(peer["ppublickey"])
		if err != nil {
			return nil, err
		}
		write("public_key", public)
		if peer["ppresharedkey"] != "" {
			v, err := key(peer["ppresharedkey"])
			if err != nil {
				return nil, err
			}
			write("preshared_key", v)
		}
		write("endpoint", peer["pendpoint"])
		write("replace_allowed_ips", "true")
		routes := p.Routes
		if len(p.peers) > 0 {
			routes = nil
			for _, raw := range strings.Split(peer["pallowedips"], ",") {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
				if err != nil {
					return nil, err
				}
				routes = append(routes, prefix)
			}
		}
		for _, prefix := range routes {
			write("allowed_ip", prefix.Masked().String())
		}
		if interval := peer["ppersistentkeepalive"]; interval != "" {
			write("persistent_keepalive_interval", interval)
		}
	}
	return []byte(b.String()), nil
}
