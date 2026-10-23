package protocol

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// IDs are append-only: encrypted profiles and the desktop IPC store these values.
const (
	NaiveLibrarySHA256 = "3217c6260fbca5f16072e0b79735742f40109a63bb0ff88fd6b96dd6b54a2928"
	HTTP               = 6
	Trojan             = 7
	TUIC               = 8
	AnyTLS             = 9
	Naive              = 10
	MaxKind            = Naive
)

var Names = []string{"AmneziaWG", "WireGuard", "VLESS", "SOCKS5", "Hysteria2", "Shadowsocks", "HTTP / HTTPS", "Trojan", "TUIC", "AnyTLS", "NaiveProxy"}

func LinkKind(source string) int {
	u, err := url.Parse(strings.TrimSpace(source))
	if err != nil {
		return -1
	}
	switch strings.ToLower(u.Scheme) {
	case "vless":
		return 2
	case "socks5":
		return 3
	case "hy2", "hysteria2":
		return 4
	case "ss":
		return 5
	case "http", "https":
		// A web URL remains a subscription. A proxy URI must be explicit: credentials
		// or an explicit port, with no resource path/query (apart from TLS options).
		if (u.User != nil || u.Port() != "") && (u.Path == "" || u.Path == "/") {
			return HTTP
		}
	case "trojan":
		return Trojan
	case "tuic":
		return TUIC
	case "anytls":
		return AnyTLS
	case "naive+https":
		return Naive
	}
	return -1
}

func nativeProxy(source string, kind int) (object, error) {
	var out object
	if strings.HasPrefix(strings.TrimSpace(source), "{") {
		var err error
		out, err = decodeObject(source)
		if err != nil {
			return nil, err
		}
	} else {
		u, q, err := uri(source)
		if err != nil || LinkKind(source) != kind {
			return nil, ErrConfiguration
		}
		keys := "sni peer alpn insecure allowinsecure"
		if kind == Trojan {
			keys += " security type path host servicename"
		}
		if kind == TUIC {
			keys += " congestion_control udp_relay_mode udp_over_stream zero_rtt_handshake"
		}
		if !allowed(q, keys) {
			return nil, ErrConfiguration
		}
		if get(q, "insecure", "0") != "0" && get(q, "insecure", "") != "false" || get(q, "allowinsecure", "0") != "0" && get(q, "allowinsecure", "") != "false" {
			return nil, ErrConfiguration
		}
		p := port(u, 443)
		if kind == HTTP && u.Scheme == "http" {
			p = port(u, 80)
		}
		if p < 1 || p > 65535 {
			return nil, ErrConfiguration
		}
		types := map[int]string{HTTP: "http", Trojan: "trojan", TUIC: "tuic", AnyTLS: "anytls", Naive: "naive"}
		out = object{"type": types[kind], "server": address(u), "server_port": p}
		if kind == Trojan {
			if get(q, "security", "tls") != "tls" {
				return nil, ErrConfiguration
			}
			switch get(q, "type", "tcp") {
			case "tcp", "raw":
				if q["path"] != "" || q["host"] != "" || q["servicename"] != "" {
					return nil, ErrConfiguration
				}
			case "ws", "httpupgrade":
				transport := object{"type": q["type"], "path": get(q, "path", "/")}
				if q["servicename"] != "" {
					return nil, ErrConfiguration
				}
				if q["host"] != "" {
					if q["type"] == "ws" {
						transport["headers"] = object{"Host": q["host"]}
					} else {
						transport["host"] = q["host"]
					}
				}
				out["transport"] = transport
			case "grpc":
				if q["path"] != "" || q["host"] != "" {
					return nil, ErrConfiguration
				}
				out["transport"] = object{"type": "grpc", "service_name": q["servicename"]}
			default:
				return nil, ErrConfiguration
			}
		}
		if kind == HTTP || kind == Naive {
			if u.User != nil {
				out["username"] = u.User.Username()
				out["password"], _ = u.User.Password()
			}
		} else if kind == TUIC {
			if u.User == nil || !uuid.MatchString(u.User.Username()) {
				return nil, ErrConfiguration
			}
			out["uuid"] = u.User.Username()
			out["password"], _ = u.User.Password()
			for _, key := range []string{"congestion_control", "udp_relay_mode"} {
				if value := q[key]; value != "" {
					out[key] = value
				}
			}
			for _, key := range []string{"udp_over_stream", "zero_rtt_handshake"} {
				if value := q[key]; value != "" {
					b, e := strconv.ParseBool(value)
					if e != nil {
						return nil, ErrConfiguration
					}
					out[key] = b
				}
			}
		} else {
			out["password"] = userinfo(u)
		}
		if kind != HTTP || strings.EqualFold(u.Scheme, "https") {
			tls := object{"enabled": true, "server_name": get(q, "sni", get(q, "peer", address(u)))}
			if q["alpn"] != "" {
				if kind == Naive {
					return nil, ErrConfiguration
				}
				tls["alpn"] = stringsArray(q["alpn"], false)
			}
			out["tls"] = tls
		} else if len(q) != 0 {
			return nil, ErrConfiguration
		}
	}
	expected := map[int]string{HTTP: "http", Trojan: "trojan", TUIC: "tuic", AnyTLS: "anytls", Naive: "naive"}[kind]
	if expected == "" || s(out["type"]) != expected || s(out["server"]) == "" || n(out["server_port"]) < 1 || n(out["server_port"]) > 65535 {
		return nil, ErrConfiguration
	}
	if host := s(out["server"]); strings.ContainsAny(host, " /\\\r\n\t@?#") || (strings.Contains(host, ":") && net.ParseIP(host) == nil) {
		return nil, ErrConfiguration
	}
	// Only bounded outbound options are importable. No files, detours, injected
	// routing, system settings or insecure TLS can cross the privileged boundary.
	allowedKeys := "type tag server server_port username password tls"
	if kind == Trojan {
		allowedKeys += " transport"
	}
	if kind == TUIC {
		allowedKeys += " uuid congestion_control udp_relay_mode udp_over_stream zero_rtt_handshake"
	}
	if kind != HTTP && kind != Naive {
		allowedKeys = strings.ReplaceAll(allowedKeys, " username", "")
	}
	for k := range out {
		if !has(k, allowedKeys) {
			return nil, ErrConfiguration
		}
	}
	if value, ok := out["transport"]; ok {
		transport, ok := value.(map[string]any)
		if !ok {
			return nil, ErrConfiguration
		}
		keys := "type"
		switch s(transport["type"]) {
		case "ws":
			keys += " path headers"
		case "httpupgrade":
			keys += " path host"
		case "grpc":
			keys += " service_name"
		default:
			return nil, ErrConfiguration
		}
		for key, value := range transport {
			if !has(key, keys) {
				return nil, ErrConfiguration
			}
			if key == "headers" {
				headers, ok := value.(map[string]any)
				if !ok || len(headers) != 1 || s(headers["Host"]) == "" || strings.ContainsAny(s(headers["Host"]), "\r\n") {
					return nil, ErrConfiguration
				}
			} else if _, ok := value.(string); !ok {
				return nil, ErrConfiguration
			}
		}
	}
	tls := obj(out["tls"])
	if value, ok := out["tls"]; ok {
		if _, ok := value.(map[string]any); !ok || tls["enabled"] != true {
			return nil, ErrConfiguration
		}
	}
	for k := range tls {
		if !has(k, "enabled server_name alpn certificate") {
			return nil, ErrConfiguration
		}
	}
	for _, key := range []string{"username", "password", "uuid", "congestion_control", "udp_relay_mode"} {
		if value, ok := out[key]; ok {
			if _, ok := value.(string); !ok {
				return nil, ErrConfiguration
			}
		}
	}
	for _, key := range []string{"udp_over_stream", "zero_rtt_handshake"} {
		if value, ok := out[key]; ok {
			if _, ok := value.(bool); !ok {
				return nil, ErrConfiguration
			}
		}
	}
	if value, ok := tls["server_name"]; ok {
		if _, ok := value.(string); !ok {
			return nil, ErrConfiguration
		}
	}
	if value, ok := tls["alpn"]; ok {
		values, ok := value.([]any)
		if !ok || len(values) == 0 {
			return nil, ErrConfiguration
		}
		for _, v := range values {
			if s(v) == "" {
				return nil, ErrConfiguration
			}
		}
	}
	if value, ok := tls["certificate"]; ok {
		values, ok := value.([]any)
		if !ok || len(values) == 0 {
			return nil, ErrConfiguration
		}
		for _, v := range values {
			block, rest := pem.Decode([]byte(s(v)))
			if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
				return nil, ErrConfiguration
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, ErrConfiguration
			}
		}
	}
	if tls["enabled"] == true && s(tls["server_name"]) == "" {
		tls["server_name"] = out["server"]
	}
	if kind != HTTP && tls["enabled"] != true {
		return nil, ErrConfiguration
	}
	if kind != HTTP && kind != TUIC && kind != Naive && s(out["password"]) == "" {
		return nil, ErrConfiguration
	}
	if kind == TUIC && (!uuid.MatchString(s(out["uuid"])) || s(out["password"]) == "" || !has(s(out["congestion_control"]), " cubic new_reno bbr") || !has(s(out["udp_relay_mode"]), " native quic")) {
		return nil, ErrConfiguration
	}
	if kind == Naive && (s(out["username"]) == "" || s(out["password"]) == "" || tls["alpn"] != nil) {
		return nil, ErrConfiguration
	}
	out["tag"] = "proxy"
	return out, nil
}
