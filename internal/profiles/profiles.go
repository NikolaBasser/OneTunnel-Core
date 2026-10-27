// Package profiles owns import, subscriptions and profile policy. It has no UI
// dependency and never starts a network engine or modifies Windows networking.
package profiles

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"github.com/rivo/uniseg"
)

const MaxBytes = 4 * 1024 * 1024

type Profile = control.Profile
type SubscriptionMetadata struct {
	Upload    *uint64
	Download  *uint64
	Total     *uint64
	Expire    *uint64
	UpdatedAt string
}
type ImportResult struct {
	Profiles   []Profile
	Duplicates int
	Skipped    int
	Metadata   *SubscriptionMetadata
}
type MergeResult struct {
	Profiles []Profile
	Added    int
	Updated  int
	Removed  int
}

var ErrImport = errors.New("Не удалось разобрать конфигурацию. Проверь формат и параметры подключения.")
var awgFields = regexp.MustCompile(`(?mi)^\s*(` + protocol.AWGFieldPattern + `)\s*=`)

func newID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func ValidName(s string) bool {
	return utf8.ValidString(s) && len(utf16.Encode([]rune(s))) <= 4096 && uniseg.GraphemeClusterCount(s) <= 100 && strings.IndexFunc(s, unicode.IsControl) < 0
}
func ImportedName(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
	g := uniseg.NewGraphemes(s)
	var b strings.Builder
	for i := 0; i < 100 && g.Next(); i++ {
		b.WriteString(g.Str())
	}
	return b.String()
}
func IsURL(s string) bool {
	if protocol.LinkKind(s) == protocol.HTTP {
		return false
	}
	u, e := url.Parse(strings.TrimSpace(s))
	return e == nil && u.Host != "" && (u.Scheme == "https" || u.Scheme == "http")
}
func SecureURL(s string) bool {
	u, e := url.Parse(strings.TrimSpace(s))
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}
func GroupName(group, name, source string, subscription bool) (string, error) {
	group = strings.TrimSpace(group)
	if subscription && group == "" {
		group = strings.TrimSpace(name)
	}
	if subscription && group == "" {
		u, e := url.Parse(source)
		if e == nil && u.Scheme == "https" && u.Host != "" {
			group = "Подписка · " + u.Hostname()
		}
	}
	if group == "" {
		group = "Без группы"
		if subscription {
			group = "Импортированные"
		}
	}
	if !ValidName(group) {
		return "", errors.New("Название группы: до 100 символов или эмодзи.")
	}
	return group, nil
}

func Parse(name, source string, requested *int) (Profile, error) {
	source = strings.TrimSpace(source)
	lower := strings.ToLower(source)
	if strings.HasPrefix(lower, "vpn://") || strings.HasPrefix(lower, "amnezia://") {
		return amnezia(name, source)
	}
	if source == "" || len(utf16.Encode([]rune(source))) > 131072 {
		return Profile{}, ErrImport
	}
	kind := -1
	switch {
	case strings.HasPrefix(source, "{"):
		var out map[string]any
		if json.Unmarshal([]byte(source), &out) != nil {
			return Profile{}, ErrImport
		}
		if typ, ok := out["type"].(string); ok {
			kinds := map[string]int{"http": protocol.HTTP, "trojan": protocol.Trojan, "tuic": protocol.TUIC, "anytls": protocol.AnyTLS, "naive": protocol.Naive}
			var found bool
			kind, found = kinds[typ]
			if !found {
				return Profile{}, ErrImport
			}
		} else {
			switch out["protocol"] {
			case "vless":
				kind = 2
			case "hysteria":
				kind = 4
			case "shadowsocks":
				kind = 5
			default:
				return Profile{}, ErrImport
			}
		}
	case protocol.LinkKind(source) >= protocol.HTTP:
		kind = protocol.LinkKind(source)
	case strings.HasPrefix(lower, "vless://"):
		kind = 2
	case strings.HasPrefix(lower, "ss://"):
		kind = 5
	case strings.HasPrefix(lower, "hy2://") || strings.HasPrefix(lower, "hysteria2://"):
		kind = 4
	case strings.HasPrefix(lower, "socks5://"):
		kind = 3
	default:
		kind = 1
		if awgFields.MatchString(source) {
			kind = 0
		}
		if requested != nil {
			kind = *requested
		}
	}
	if requested != nil && kind != *requested {
		return Profile{}, ErrImport
	}
	if kind == 1 && awgFields.MatchString(source) {
		return Profile{}, ErrImport
	}
	if _, e := protocol.Compile(source, kind, false, 18001, 18002, "xray.exe"); e != nil {
		return Profile{}, ErrImport
	}
	if strings.TrimSpace(name) == "" {
		if kind >= 2 && !strings.HasPrefix(source, "{") {
			if i := strings.IndexByte(source, '#'); i >= 0 {
				name, _ = url.PathUnescape(source[i+1:])
			}
		}
		if strings.TrimSpace(name) == "" {
			names := protocol.Names
			name = names[kind] + " · новое подключение"
		}
	}
	if !ValidName(name) {
		return Profile{}, errors.New("Название должно содержать до 100 символов или эмодзи без управляющих символов.")
	}
	return Profile{ID: newID(), Name: strings.TrimSpace(name), Protocol: kind, Source: source, Group: "Без группы"}, nil
}

func Validate(p Profile) error {
	check := p
	if p.Reliability != nil && p.Reliability.AutoSelect && !protocol.NetworkOptionsEmpty(p.Network) {
		return ErrImport
	}
	check.Network = nil // Stored policy is validated independently of runtime mode.
	if e := control.Validate(control.Request{Version: 1, Command: "start", Profile: &check, FullDevice: check.Reliability == nil || !check.Reliability.AutoSelect}); e != "" {
		return ErrImport
	}
	if !ValidName(p.Name) || !ValidName(p.Group) {
		return ErrImport
	}
	if _, e := Parse(p.Name, p.Source, &p.Protocol); e != nil {
		return e
	}
	if e := protocol.ValidateOptions(p.Source, p.Protocol, p.Transport); e != nil {
		return errors.New("Несовместимые параметры фрагментации, шумов или MUX. Проверь транспорт, Vision и допустимые диапазоны.")
	}
	if e := protocol.ValidateNetworkOptions(p.Network, p.Protocol, true); e != nil {
		return ErrImport
	}
	if p.Protocol < 2 && !protocol.NetworkOptionsEmpty(p.Network) {
		if _, e := protocol.CompileWithNetwork(p.Source, p.Protocol, true, 18001, 18002, "unused", p.Transport, p.Network); e != nil {
			return ErrImport
		}
	}
	return nil
}
func Identity(p Profile) (string, error) {
	if p.Protocol < 2 {
		return strings.TrimSpace(p.Source), nil
	}
	if p.Protocol != 3 {
		out, e := protocol.Outbound(p.Source, p.Protocol)
		if e != nil {
			return "", e
		}
		b, _ := json.Marshal(out)
		return string(b), nil
	}
	plan, e := protocol.Compile(p.Source, p.Protocol, false, 18001, 18002, "xray.exe")
	if e != nil {
		return "", e
	}
	var c struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if json.Unmarshal([]byte(plan.Proxy), &c) != nil || len(c.Outbounds) == 0 {
		return "", ErrImport
	}
	return string(c.Outbounds[0]), nil
}
func decode64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	s = strings.NewReplacer("-", "+", "_", "/").Replace(strings.TrimRight(s, "="))
	return base64.RawStdEncoding.DecodeString(s)
}

func ParseSubscription(payload string) (ImportResult, error) {
	r := ImportResult{Profiles: []Profile{}}
	if len(payload) > MaxBytes {
		return r, errors.New("Подписка больше 4 МБ.")
	}
	payload = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(payload), "\ufeff"))
	seen := map[string]bool{}
	candidates := 0
	add := func(name, source string) error {
		candidates++
		if candidates > 2000 {
			return errors.New("В подписке больше 2000 записей.")
		}
		p, e := Parse(ImportedName(name), source, nil)
		if e != nil {
			r.Skipped++
			return nil
		}
		id, e := Identity(p)
		if e != nil {
			r.Skipped++
			return nil
		}
		if seen[id] {
			r.Duplicates++
		} else {
			seen[id] = true
			r.Profiles = append(r.Profiles, p)
		}
		return nil
	}
	if !strings.HasPrefix(payload, "{") && !strings.HasPrefix(payload, "[") && !strings.Contains(payload, "://") {
		b, e := decode64(payload)
		if e != nil {
			return r, ErrImport
		}
		defer clear(b)
		payload = strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff"))
	}
	if strings.HasPrefix(payload, "{") || strings.HasPrefix(payload, "[") {
		var root any
		if !boundedJSON([]byte(payload)) || json.Unmarshal([]byte(payload), &root) != nil {
			return r, ErrImport
		}
		configs, ok := root.([]any)
		if !ok {
			configs = []any{root}
		}
		for _, item := range configs {
			o, ok := item.(map[string]any)
			if !ok {
				r.Skipped++
				continue
			}
			proto, _ := o["protocol"].(string)
			if proto == "vless" || proto == "hysteria" || proto == "shadowsocks" || supportedNativeType(o) {
				b, _ := json.Marshal(o)
				if e := add("", string(b)); e != nil {
					return r, e
				}
				continue
			}
			outs, ok := o["outbounds"].([]any)
			if !ok {
				r.Skipped++
				continue
			}
			name, _ := o["remarks"].(string)
			count := 0
			for _, v := range outs {
				out, _ := v.(map[string]any)
				if supportedNativeType(out) {
					count++
					continue
				}
				if out["protocol"] == "vless" || out["protocol"] == "hysteria" || out["protocol"] == "shadowsocks" {
					count++
				}
			}
			for _, v := range outs {
				out, ok := v.(map[string]any)
				if !ok {
					continue
				}
				if supportedNativeType(out) {
					b, _ := json.Marshal(out)
					if e := add(nativeTag(out), string(b)); e != nil {
						return r, e
					}
					continue
				}
				switch out["protocol"] {
				case "vless", "hysteria", "shadowsocks":
					title := name
					if count > 1 {
						tag, _ := out["tag"].(string)
						if tag == "" {
							tag = "VLESS"
						}
						title += " · " + tag
					}
					b, _ := json.Marshal(out)
					if e := add(title, string(b)); e != nil {
						return r, e
					}
				case "freedom", "blackhole", "dns":
				default:
					r.Skipped++
				}
			}
		}
	} else {
		for _, line := range strings.Split(payload, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			low := strings.ToLower(line)
			if protocol.LinkKind(low) >= 2 {
				if e := add("", line); e != nil {
					return r, e
				}
			} else {
				r.Skipped++
			}
		}
	}
	if len(r.Profiles) == 0 {
		return r, errors.New("В подписке не найдено совместимых профилей. Нужны JSON Xray, список ссылок или Base64.")
	}
	return r, nil
}

func boundedJSON(data []byte) bool {
	depth := 0
	quoted, escaped := false, false
	for _, c := range data {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
		} else if c == '{' || c == '[' {
			depth++
			if depth > 48 {
				return false
			}
		} else if c == '}' || c == ']' {
			depth--
		}
	}
	return true
}
func amnezia(name, source string) (Profile, error) {
	b, e := decode64(source[strings.Index(source, "://")+3:])
	if e != nil || len(b) > MaxBytes {
		return Profile{}, ErrImport
	}
	defer clear(b)
	if len(b) >= 6 && b[4] == 0x78 {
		size := int(binary.BigEndian.Uint32(b))
		if size > MaxBytes {
			return Profile{}, ErrImport
		}
		reader, e := zlib.NewReader(bytes.NewReader(b[4:]))
		if e != nil {
			return Profile{}, ErrImport
		}
		decoded, e := io.ReadAll(io.LimitReader(reader, MaxBytes+1))
		reader.Close()
		if e != nil || len(decoded) != size {
			return Profile{}, ErrImport
		}
		defer clear(decoded)
		b = decoded
	}
	var root map[string]any
	if !boundedJSON(b) || json.Unmarshal(b, &root) != nil {
		return Profile{}, ErrImport
	}
	var found []Profile
	containers, _ := root["containers"].([]any)
	for _, v := range containers {
		c, _ := v.(map[string]any)
		key := ""
		switch c["container"] {
		case "amnezia-awg":
			key = "awg"
		case "amnezia-wireguard":
			key = "wireguard"
		case "amnezia-xray":
			key = "xray"
		case "amnezia-ssxray":
			key = "ssxray"
		default:
			continue
		}
		details, _ := c[key].(map[string]any)
		last := details["last_config"]
		if text, ok := last.(string); ok {
			if !boundedJSON([]byte(text)) || json.Unmarshal([]byte(text), &last) != nil {
				return Profile{}, ErrImport
			}
		}
		config, _ := last.(map[string]any)
		text, _ := config["config"].(string)
		if text == "" && (key == "xray" || key == "ssxray") {
			encoded, _ := json.Marshal(config)
			text = string(encoded)
		}
		if text == "" {
			continue
		}
		title := name
		if strings.TrimSpace(title) == "" {
			title, _ = root["description"].(string)
			if title == "" {
				title = "Amnezia"
			}
			title = ImportedName(title)
		}
		if key == "xray" || key == "ssxray" {
			batch, e := ParseSubscription(text)
			if e != nil {
				return Profile{}, e
			}
			for _, p := range batch.Profiles {
				p.Name = title
				found = append(found, p)
			}
		} else {
			dns1, _ := root["dns1"].(string)
			dns2, _ := root["dns2"].(string)
			text = strings.NewReplacer("$PRIMARY_DNS", dns1, "$SECONDARY_DNS", dns2).Replace(text)
			lines := strings.Split(text, "\n")
			for i, line := range lines {
				pair := strings.SplitN(line, "=", 2)
				if len(pair) == 2 && strings.EqualFold(strings.TrimSpace(pair[0]), "DNS") {
					var values []string
					for _, v := range strings.Split(pair[1], ",") {
						if v = strings.TrimSpace(v); v != "" {
							values = append(values, v)
						}
					}
					lines[i] = pair[0] + "= " + strings.Join(values, ", ")
				}
			}
			kind := 1
			if key == "awg" {
				kind = 0
			}
			p, e := Parse(title, strings.Join(lines, "\n"), &kind)
			if e != nil {
				return Profile{}, e
			}
			found = append(found, p)
		}
	}
	if len(found) != 1 {
		return Profile{}, errors.New("Ключ Amnezia должен содержать одно готовое подключение. Экспортируй .conf или ссылку подключения; ключи с API не поддерживаются.")
	}
	return found[0], nil
}

func Merge(existing, incoming []Profile, group string) (MergeResult, error) {
	r := MergeResult{Profiles: []Profile{}}
	protocols := map[int]bool{}
	for _, p := range incoming {
		protocols[p.Protocol] = true
	}
	var target []Profile
	identities := map[string]string{}
	targetIDs := map[string]bool{}
	for _, p := range existing {
		if p.Group == group && protocols[p.Protocol] {
			id, e := Identity(p)
			if e != nil {
				return r, e
			}
			target = append(target, p)
			identities[p.ID] = id
			targetIDs[p.ID] = true
		}
	}
	used := map[string]bool{}
	var replacements []Profile
	for _, fresh := range incoming {
		id, e := Identity(fresh)
		if e != nil {
			return r, e
		}
		var match *Profile
		for i, p := range target {
			if !used[p.ID] && p.Protocol == fresh.Protocol && identities[p.ID] == id {
				match = &target[i]
				break
			}
		}
		if match == nil {
			var matches []int
			for i, p := range target {
				if !used[p.ID] && p.Protocol == fresh.Protocol && p.Name == fresh.Name {
					matches = append(matches, i)
				}
			}
			if len(matches) == 1 {
				match = &target[matches[0]]
			}
		}
		fresh.Group = group
		if match == nil {
			r.Added++
		} else {
			used[match.ID] = true
			fresh.ID = match.ID
			fresh.Transport = match.Transport
			fresh.Reliability = match.Reliability
			fresh.Network = protocol.CloneNetworkOptions(match.Network)
			if fresh.Source != match.Source || fresh.Name != match.Name {
				r.Updated++
			}
		}
		replacements = append(replacements, fresh)
	}
	inserted := false
	for _, p := range existing {
		if !targetIDs[p.ID] {
			r.Profiles = append(r.Profiles, p)
		} else if !inserted {
			r.Profiles = append(r.Profiles, replacements...)
			inserted = true
		}
	}
	if !inserted {
		r.Profiles = append(r.Profiles, replacements...)
	}
	r.Removed = len(target) - len(used)
	return r, nil
}

func supportedNativeType(out map[string]any) bool {
	typ, _ := out["type"].(string)
	return typ == "http" || typ == "trojan" || typ == "tuic" || typ == "anytls" || typ == "naive"
}
func nativeTag(out map[string]any) string { tag, _ := out["tag"].(string); return tag }
