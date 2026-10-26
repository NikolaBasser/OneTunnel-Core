// Package protocol validates profiles and builds engine configurations without
// depending on Windows, the desktop UI, or the privileged process launcher.
package protocol

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/net/idna"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

type object = map[string]any

var ErrConfiguration = errors.New("invalid configuration")
var uuid = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Plan struct {
	SharedNative      bool `json:",omitempty"`
	NativeSource      string
	NativeShadowsocks bool
	NeedsXray         bool
	AccurateTime      bool
	Clock             string
	LocalPort         int
	BridgePort        *int
	Xray              string
	Proxy             string
}

func s(v any) string { r, _ := v.(string); return r }
func obj(v any) object {
	r, _ := v.(map[string]any)
	if r == nil {
		return object{}
	}
	return r
}
func arr(v any) []any { r, _ := v.([]any); return r }
func n(v any) int {
	switch x := v.(type) {
	case json.Number:
		i, e := strconv.Atoi(string(x))
		if e == nil {
			return i
		}
	case int:
		return x
	}
	return -1
}
func one(v any) object {
	a := arr(v)
	if len(a) != 1 {
		return object{}
	}
	return obj(a[0])
}
func has(v string, values string) bool {
	for _, x := range strings.Split(values, " ") {
		if v == x {
			return true
		}
	}
	return false
}
func decodeObject(source string) (object, error) {
	d := json.NewDecoder(strings.NewReader(source))
	d.UseNumber()
	var out object
	if d.Decode(&out) != nil || out == nil {
		return nil, ErrConfiguration
	}
	// Reject trailing values, excessive nesting and duplicate keys (including
	// nested advanced transport settings), rather than silently losing options.
	check := json.NewDecoder(strings.NewReader(source))
	check.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 48 {
			return ErrConfiguration
		}
		t, e := check.Token()
		if e != nil {
			return ErrConfiguration
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for check.More() {
					k, e := check.Token()
					if e != nil {
						return ErrConfiguration
					}
					key, ok := k.(string)
					if !ok || seen[key] {
						return ErrConfiguration
					}
					seen[key] = true
					if walk(depth+1) != nil {
						return ErrConfiguration
					}
				}
			case '[':
				for check.More() {
					if walk(depth+1) != nil {
						return ErrConfiguration
					}
				}
			default:
				return ErrConfiguration
			}
			_, e = check.Token()
			return e
		}
		return nil
	}
	if walk(1) != nil {
		return nil, ErrConfiguration
	}
	if _, e := check.Token(); e != io.EOF {
		return nil, ErrConfiguration
	}
	return out, nil
}
func safe(v any, depth int) bool {
	if depth > 48 {
		return false
	}
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			if has(strings.ToLower(k), "certificatefile keyfile keylog masterkeylog secretslog dialerproxy proxysettings") {
				return false
			}
			if strings.EqualFold(k, "allowInsecure") && v == true {
				return false
			}
			if !safe(v, depth+1) {
				return false
			}
		}
	case []any:
		for _, v := range x {
			if !safe(v, depth+1) {
				return false
			}
		}
	}
	return true
}
func uri(source string) (*url.URL, map[string]string, error) {
	u, e := url.Parse(source)
	if e != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
		return nil, nil, ErrConfiguration
	}
	if net.ParseIP(u.Hostname()) == nil {
		host, err := idna.Lookup.ToASCII(u.Hostname())
		if err != nil {
			return nil, nil, ErrConfiguration
		}
		_ = host
	}
	q := map[string]string{}
	for _, item := range strings.Split(u.RawQuery, "&") {
		if item == "" {
			continue
		}
		p := strings.SplitN(item, "=", 2)
		key, e := url.PathUnescape(p[0])
		if e != nil {
			return nil, nil, ErrConfiguration
		}
		key = strings.ToLower(key)
		if _, ok := q[key]; ok {
			return nil, nil, ErrConfiguration
		}
		value := ""
		if len(p) == 2 {
			value, e = url.PathUnescape(p[1])
			if e != nil {
				return nil, nil, ErrConfiguration
			}
		}
		q[key] = value
	}
	return u, q, nil
}
func address(u *url.URL) string {
	if net.ParseIP(u.Hostname()) != nil {
		return u.Hostname()
	}
	host, _ := idna.Lookup.ToASCII(u.Hostname())
	return host
}
func get(q map[string]string, key, fallback string) string {
	if v, ok := q[strings.ToLower(key)]; ok {
		return v
	}
	return fallback
}
func port(u *url.URL, fallback int) int {
	if u.Port() == "" {
		return fallback
	}
	v, e := strconv.Atoi(u.Port())
	if e != nil || v < 1 || v > 65535 {
		return -1
	}
	return v
}
func userinfo(u *url.URL) string {
	if u.User == nil {
		return ""
	}
	p, ok := u.User.Password()
	if ok {
		return u.User.Username() + ":" + p
	}
	return u.User.Username()
}
func stringsArray(v string, skipEmpty bool) []any {
	a := []any{}
	for _, x := range strings.Split(v, ",") {
		if !skipEmpty || x != "" {
			a = append(a, x)
		}
	}
	return a
}
func allowed(q map[string]string, keys string) bool {
	for k := range q {
		if !has(k, keys) {
			return false
		}
	}
	return true
}
func Outbound(source string, kind int) (object, error) {
	source = strings.TrimSpace(source)
	if kind >= HTTP && kind <= MaxKind {
		return nativeProxy(source, kind)
	}
	var original object
	var e error
	if strings.HasPrefix(source, "{") {
		original, e = decodeObject(source)
	} else {
		switch kind {
		case 2:
			original, e = vless(source)
		case 4:
			original, e = hysteria(source)
		case 5:
			original, e = shadowsocks(source)
		default:
			return nil, ErrConfiguration
		}
	}
	if e != nil {
		return nil, ErrConfiguration
	}
	if _, ok := original["proxySettings"]; ok {
		return nil, ErrConfiguration
	}
	if _, ok := original["dialerProxy"]; ok {
		return nil, ErrConfiguration
	}
	settings := obj(original["settings"])
	stream := obj(original["streamSettings"])
	var peer object
	expected := ""
	switch kind {
	case 2:
		expected = "vless"
		peer = one(settings["vnext"])
		user := one(peer["users"])
		if !uuid.MatchString(s(user["id"])) {
			return nil, ErrConfiguration
		}
		network := s(stream["network"])
		if network == "" {
			network = "tcp"
		}
		security := s(stream["security"])
		if security == "" {
			security = "none"
		}
		if !has(network, "tcp raw ws websocket grpc httpupgrade xhttp splithttp kcp mkcp hysteria") || !has(security, "none tls reality") {
			return nil, ErrConfiguration
		}
		if network == "hysteria" && security != "tls" {
			return nil, ErrConfiguration
		}
		if security == "reality" {
			r := obj(stream["realitySettings"])
			if !has(network, "tcp raw xhttp splithttp grpc") || (strings.TrimSpace(s(r["publicKey"])) == "" && strings.TrimSpace(s(r["password"])) == "") {
				return nil, ErrConfiguration
			}
		}
		flow := s(user["flow"])
		if !has(flow, " xtls-rprx-vision xtls-rprx-vision-udp443") || (flow != "" && (!has(network, "tcp raw") || security == "none")) {
			return nil, ErrConfiguration
		}
	case 4:
		expected = "hysteria"
		peer = settings
		if n(settings["version"]) != 2 || s(stream["network"]) != "hysteria" || s(stream["security"]) != "tls" || n(obj(stream["hysteriaSettings"])["version"]) != 2 {
			return nil, ErrConfiguration
		}
	case 5:
		expected = "shadowsocks"
		peer = one(settings["servers"])
		if !has(s(peer["method"]), "aes-128-gcm aes-256-gcm chacha20-poly1305 chacha20-ietf-poly1305 xchacha20-poly1305 xchacha20-ietf-poly1305 2022-blake3-aes-128-gcm 2022-blake3-aes-256-gcm 2022-blake3-chacha20-poly1305") || s(peer["password"]) == "" {
			return nil, ErrConfiguration
		}
	default:
		return nil, ErrConfiguration
	}
	if s(original["protocol"]) != expected || strings.TrimSpace(s(peer["address"])) == "" || n(peer["port"]) < 1 || n(peer["port"]) > 65535 || !safe(settings, 1) || !safe(stream, 1) {
		return nil, ErrConfiguration
	}
	return object{"tag": "proxy", "protocol": expected, "settings": settings, "streamSettings": stream}, nil
}
func vless(source string) (object, error) {
	u, q, e := uri(source)
	if e != nil || !strings.EqualFold(u.Scheme, "vless") || port(u, -1) < 1 || !uuid.MatchString(userinfo(u)) {
		return nil, ErrConfiguration
	}
	if !allowed(q, "encryption security type flow sni fp pbk sid spx alpn path host servicename mode extra headertype seed authority multimode allowinsecure insecure ed eh pcs pqv ech publickey password auth") {
		return nil, ErrConfiguration
	}
	if has(get(q, "allowInsecure", "false"), "1 true") || has(get(q, "insecure", "false"), "1 true") {
		return nil, ErrConfiguration
	}
	network := get(q, "type", "tcp")
	security := get(q, "security", "none")
	stream := object{"network": network, "security": security}
	user := object{"id": strings.ToLower(userinfo(u)), "encryption": get(q, "encryption", "none"), "flow": get(q, "flow", "")}
	if security == "tls" {
		tls := object{"serverName": get(q, "sni", u.Hostname()), "fingerprint": get(q, "fp", "chrome"), "allowInsecure": false}
		if v, ok := q["alpn"]; ok {
			tls["alpn"] = stringsArray(v, true)
		}
		if v, ok := q["pcs"]; ok {
			tls["pinnedPeerCertSha256"] = v
		}
		if v, ok := q["ech"]; ok {
			tls["echConfigList"] = v
		}
		stream["tlsSettings"] = tls
	}
	if security == "reality" {
		r := object{"serverName": get(q, "sni", u.Hostname()), "fingerprint": get(q, "fp", "chrome"), "publicKey": get(q, "pbk", get(q, "publicKey", get(q, "password", ""))), "shortId": get(q, "sid", ""), "spiderX": get(q, "spx", "/")}
		if v, ok := q["pqv"]; ok {
			r["mldsa65Verify"] = v
		}
		stream["realitySettings"] = r
	}
	path := get(q, "path", "/")
	host := get(q, "host", "")
	switch network {
	case "xhttp", "splithttp":
		x := object{"path": path, "host": host, "mode": get(q, "mode", "auto")}
		if v, ok := q["extra"]; ok {
			extra, e := decodeObject(v)
			if e != nil {
				return nil, e
			}
			x["extra"] = extra
		}
		stream["xhttpSettings"] = x
	case "ws", "websocket":
		ws := object{"path": path, "headers": object{"Host": host}}
		if v, ok := q["ed"]; ok {
			i, e := strconv.ParseInt(v, 10, 32)
			if e != nil || i < 0 {
				return nil, ErrConfiguration
			}
			ws["maxEarlyData"] = int(i)
		}
		if v, ok := q["eh"]; ok {
			ws["earlyDataHeaderName"] = v
		}
		stream["wsSettings"] = ws
	case "httpupgrade":
		stream["httpupgradeSettings"] = object{"host": host, "path": path}
	case "grpc":
		stream["grpcSettings"] = object{"serviceName": get(q, "serviceName", ""), "authority": get(q, "authority", ""), "multiMode": has(get(q, "multiMode", get(q, "mode", "")), "true multi")}
	case "tcp", "raw":
		header := object{"type": get(q, "headerType", "none")}
		if s(header["type"]) == "http" {
			header["request"] = object{"path": []any{path}, "headers": object{"Host": []any{host}}}
		}
		stream["tcpSettings"] = object{"header": header}
	case "kcp", "mkcp":
		if get(q, "seed", "") != "" || get(q, "headerType", "none") != "none" {
			return nil, ErrConfiguration
		}
		stream["kcpSettings"] = object{}
	case "hysteria":
		stream["hysteriaSettings"] = object{"version": 2, "auth": get(q, "auth", get(q, "password", ""))}
	}
	return object{"protocol": "vless", "settings": object{"vnext": []any{object{"address": address(u), "port": port(u, -1), "users": []any{user}}}}, "streamSettings": stream}, nil
}
func b64(v string) (string, error) {
	v = strings.TrimRight(strings.ReplaceAll(strings.ReplaceAll(v, "-", "+"), "_", "/"), "=")
	b, e := base64.RawStdEncoding.DecodeString(v)
	if e != nil {
		return "", ErrConfiguration
	}
	return string(b), nil
}
func shadowsocks(source string) (object, error) {
	if !strings.HasPrefix(strings.ToLower(source), "ss://") {
		return nil, ErrConfiguration
	}
	body := strings.SplitN(source[5:], "#", 2)[0]
	if strings.Contains(body, "?") {
		return nil, ErrConfiguration
	}
	var e error
	if !strings.Contains(body, "@") {
		body, e = b64(body)
		if e != nil {
			return nil, e
		}
	}
	at := strings.LastIndex(body, "@")
	if at < 1 {
		return nil, ErrConfiguration
	}
	auth, e := url.PathUnescape(body[:at])
	if e != nil {
		return nil, ErrConfiguration
	}
	if !strings.Contains(auth, ":") {
		auth, e = b64(auth)
		if e != nil {
			return nil, e
		}
	}
	a := strings.SplitN(auth, ":", 2)
	if len(a) != 2 || a[0] == "" {
		return nil, ErrConfiguration
	}
	u, _, e := uri("ss://" + strings.TrimRight(body[at+1:], "/"))
	if e != nil || port(u, -1) < 1 {
		return nil, ErrConfiguration
	}
	return object{"protocol": "shadowsocks", "settings": object{"servers": []any{object{"address": address(u), "port": port(u, -1), "method": a[0], "password": a[1]}}}, "streamSettings": object{"network": "tcp", "security": "none"}}, nil
}
func hysteria(source string) (object, error) {
	u, q, e := uri(source)
	if e != nil || !has(strings.ToLower(u.Scheme), "hy2 hysteria2") || port(u, 443) < 1 || !allowed(q, "sni insecure pinsha256 obfs obfs-password ech alpn") || !has(get(q, "insecure", "0"), "0 false") {
		return nil, ErrConfiguration
	}
	tls := object{"serverName": get(q, "sni", u.Hostname()), "allowInsecure": false, "alpn": []any{"h3"}}
	if v, ok := q["pinsha256"]; ok {
		tls["pinnedPeerCertSha256"] = v
	}
	if v, ok := q["ech"]; ok {
		tls["echConfigList"] = v
	}
	if v, ok := q["alpn"]; ok {
		tls["alpn"] = stringsArray(v, false)
	}
	stream := object{"network": "hysteria", "security": "tls", "tlsSettings": tls, "hysteriaSettings": object{"version": 2, "auth": userinfo(u)}}
	if obfs := q["obfs"]; obfs != "" {
		if obfs != "salamander" || len(utf16.Encode([]rune(q["obfs-password"]))) < 4 {
			return nil, ErrConfiguration
		}
		stream["finalmask"] = object{"udp": []any{object{"type": "salamander", "settings": object{"password": q["obfs-password"]}}}}
	}
	return object{"protocol": "hysteria", "settings": object{"address": address(u), "port": port(u, 443), "version": 2}, "streamSettings": stream}, nil
}
func socks(source string) (object, error) {
	u, q, e := uri(source)
	if e != nil || !strings.EqualFold(u.Scheme, "socks5") || port(u, -1) < 1 || len(q) != 0 {
		return nil, ErrConfiguration
	}
	out := object{"type": "socks", "tag": "proxy", "server": address(u), "server_port": port(u, -1), "version": "5"}
	if u.User != nil {
		user := u.User.Username()
		password, _ := u.User.Password()
		if len(user) < 1 || len(user) > 255 || len(password) > 255 {
			return nil, ErrConfiguration
		}
		out["username"] = user
		out["password"] = password
	}
	return out, nil
}
func nativeSS(out object) bool {
	stream := obj(out["streamSettings"])
	if !has(s(stream["network"]), " tcp raw") || !has(s(stream["security"]), " none") {
		return false
	}
	for k, v := range stream {
		if !has(k, "network security tcpSettings rawSettings") {
			return false
		}
		if k == "tcpSettings" || k == "rawSettings" {
			settings, ok := v.(map[string]any)
			if !ok {
				return false
			}
			for key, val := range settings {
				h, ok := val.(map[string]any)
				if key != "header" || !ok || !has(s(h["type"]), " none") {
					return false
				}
			}
		}
	}
	return true
}
func Compile(source string, kind int, tun bool, localPort, bridgePort int, xrayPath string) (Plan, error) {
	p := Plan{}
	source = strings.TrimSpace(source)
	if source == "" || len(utf16.Encode([]rune(source))) > 131072 {
		return p, ErrConfiguration
	}
	if kind == 0 || kind == 1 {
		native, e := tunnel(source, kind, tun)
		p.NativeSource = native
		return p, e
	}
	if kind < 2 || kind > MaxKind || localPort < 1 || localPort > 65535 {
		return p, ErrConfiguration
	}
	p.LocalPort = localPort
	var outbound object
	var e error
	if kind == 3 {
		outbound, e = socks(source)
	} else {
		outbound, e = Outbound(source, kind)
	}
	if e != nil {
		return Plan{}, e
	}
	p.NativeShadowsocks = kind == 5 && nativeSS(outbound)
	p.NeedsXray = kind < HTTP && kind != 3 && !p.NativeShadowsocks
	if p.NeedsXray {
		if bridgePort < 1 || bridgePort > 65535 || bridgePort == localPort {
			return Plan{}, ErrConfiguration
		}
		p.BridgePort = &bridgePort
		x := object{"log": object{"loglevel": "none"}, "inbounds": []any{object{"tag": "local", "listen": "127.0.0.1", "port": bridgePort, "protocol": "socks", "settings": object{"auth": "noauth", "udp": true}}}, "outbounds": []any{outbound}}
		b, _ := json.Marshal(x)
		p.Xray = string(b)
		outbound = object{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": bridgePort, "version": "5"}
	} else if p.NativeShadowsocks {
		peer := one(obj(outbound["settings"])["servers"])
		method := s(peer["method"])
		p.AccurateTime = strings.HasPrefix(method, "2022-")
		if p.AccurateTime {
			p.Clock = `{"enabled":true,"server":"time.cloudflare.com","server_port":123,"interval":"30m"}`
		}
		if method == "chacha20-poly1305" {
			method = "chacha20-ietf-poly1305"
		}
		if method == "xchacha20-poly1305" {
			method = "xchacha20-ietf-poly1305"
		}
		outbound = object{"type": "shadowsocks", "tag": "proxy", "server": peer["address"], "server_port": peer["port"], "method": method, "password": peer["password"]}
		if peer["uot"] == true {
			version := peer["UoTVersion"]
			if version == nil {
				version = 2
			}
			outbound["udp_over_tcp"] = object{"enabled": true, "version": version}
		}
	}
	config := proxyConfig(outbound, tun, localPort, xrayPath, p.NeedsXray)
	b, _ := json.Marshal(config)
	p.Proxy = string(b)
	return p, nil
}

func proxyConfig(outbound object, tun bool, localPort int, xrayPath string, needsXray bool) object {
	inbounds := []any{object{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": localPort}}
	outbounds := []any{outbound}
	route := object{"final": "proxy", "auto_detect_interface": true}
	config := object{"log": object{"level": "error"}, "route": route}
	if tun {
		inbounds = append(inbounds, object{"type": "tun", "tag": "tun-in", "interface_name": "OneTunnel", "address": []any{"172.30.19.1/30", "fdfe:dcba:9876::1/126"}, "auto_route": true, "strict_route": true, "dns_mode": "hijack", "route_address": []any{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}, "stack": "mixed"})
		config["dns"] = object{"servers": []any{object{"type": "https", "tag": "remote-dns", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "tls": object{"enabled": true, "server_name": "cloudflare-dns.com"}, "detour": "proxy"}}, "final": "remote-dns"}
		rules := []any{object{"inbound": []any{"tun-in"}, "action": "sniff"}, object{"port": 53, "action": "hijack-dns"}, object{"protocol": "dns", "action": "hijack-dns"}}
		if needsXray {
			outbounds = append(outbounds, object{"type": "direct", "tag": "xray-uplink"})
			rules = append([]any{object{"process_path": []any{xrayPath}, "action": "route", "outbound": "xray-uplink"}}, rules...)
		}
		route["rules"] = rules
	}
	config["inbounds"] = inbounds
	config["outbounds"] = outbounds
	return config
}
func tunnel(source string, kind int, full bool) (string, error) {
	section := ""
	interfaces, peers := 0, 0
	fields := map[string]string{}
	awg := regexp.MustCompile(`^(Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5])$`)
	for _, raw := range strings.Split(source, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.EqualFold(line, "[Interface]") {
			section = "i"
			interfaces++
			continue
		}
		if strings.EqualFold(line, "[Peer]") {
			section = "p"
			peers++
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 || section == "" {
			return "", ErrConfiguration
		}
		key, value := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		valid := section == "i" && has(strings.ToLower(key), "privatekey address dns mtu listenport") || section == "p" && has(strings.ToLower(key), "publickey presharedkey allowedips endpoint persistentkeepalive") || section == "i" && kind == 0 && awg.MatchString(key)
		k := section + strings.ToLower(key)
		if !valid || value == "" || fields[k] != "" {
			return "", ErrConfiguration
		}
		fields[k] = value
	}
	if interfaces != 1 || peers != 1 {
		return "", ErrConfiguration
	}
	for _, key := range []string{"iprivatekey", "ppublickey", "ppresharedkey"} {
		v := fields[key]
		if v == "" && key == "ppresharedkey" {
			continue
		}
		b, e := base64.StdEncoding.DecodeString(v)
		if e != nil || len(b) != 32 {
			return "", ErrConfiguration
		}
	}
	for _, key := range []string{"iaddress", "pallowedips"} {
		if fields[key] == "" {
			return "", ErrConfiguration
		}
		for _, cidr := range strings.Split(fields[key], ",") {
			if _, _, e := net.ParseCIDR(strings.TrimSpace(cidr)); e != nil {
				return "", ErrConfiguration
			}
		}
	}
	u, e := url.Parse("udp://" + fields["pendpoint"])
	if e != nil || u.Hostname() == "" || port(u, -1) < 1 {
		return "", ErrConfiguration
	}
	if full {
		if fields["idns"] == "" {
			return "", ErrConfiguration
		}
		routes := "0.0.0.0/0"
		if strings.Contains(fields["iaddress"], ":") {
			routes += ", ::/0"
		}
		re := regexp.MustCompile(`(?mi)^([ \t]*AllowedIPs[ \t]*=)[^\r\n]+`)
		source = re.ReplaceAllString(source, "${1} "+routes)
	}
	return source, nil
}
