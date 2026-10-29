package profiles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

type ProviderRoutingInput struct {
	URL    string
	Index  int
	SHA256 string
}
type ProviderRoutingChoice struct {
	Index int
	Label string
}
type ProviderRoutingResult struct {
	Profiles []ProviderRoutingChoice
	SHA256   string
	Draft    *RuleImportResult
	Warnings []string
}
type providerConfig struct {
	Remarks   string                           `json:"remarks"`
	Outbounds []struct{ Tag, Protocol string } `json:"outbounds"`
	Routing   struct {
		Rules          []json.RawMessage
		DomainStrategy string
	} `json:"routing"`
}

func validProviderURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && len(raw) <= 4096 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}
func providerPresetOnly(n *protocol.NetworkOptions, raw string) bool {
	var s []presetSource
	if json.Unmarshal([]byte(raw), &s) != nil || len(s) != 1 || s[0].Format != "provider-xray" {
		return false
	}
	if _, e := presetCatalog(n, raw); e != nil {
		return false
	}
	return n != nil && len(n.Targets) == 0 && len(n.Rules) > 0
}
func providerRoutingDraft(ctx context.Context, input *ProviderRoutingInput) (ProviderRoutingResult, error) {
	if input == nil || !validProviderURL(input.URL) || input.Index < -1 || input.Index >= 256 {
		return ProviderRoutingResult{}, errors.New("Укажите HTTPS-ссылку провайдера без имени пользователя и пароля.")
	}
	ctx, cancel := context.WithTimeout(ctx, 110*time.Second)
	defer cancel()
	client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 || !validProviderURL(r.URL.String()) {
			return errors.New("redirect")
		}
		return nil
	}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, input.URL, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "OneTunnel")
	response, e := client.Do(req)
	if e != nil {
		return ProviderRoutingResult{}, errors.New("Не удалось загрузить подписку провайдера; прежний черновик сохранён.")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return ProviderRoutingResult{}, fmt.Errorf("Провайдер вернул HTTP %d; прежний черновик сохранён.", response.StatusCode)
	}
	content, e := readBounded(response.Body, protocol.MaxGeoFileBytes)
	if e != nil {
		return ProviderRoutingResult{}, errors.New("Подписка не прочитана или превышает 128 МиБ; прежний черновик сохранён.")
	}
	cache := map[string][]byte{}
	return parseProviderRouting(ctx, content, *input, func(format, category string) (*protocol.RuleSetData, error) {
		b, found := cache[format]
		var e error
		if !found {
			b, e = downloadLoyal(ctx, format, category)
			if e == nil {
				cache[format] = b
			}
		}
		if e != nil {
			return nil, e
		}
		return protocol.ImportLoyalsoldier(format, category, b)
	})
}

func parseProviderRouting(ctx context.Context, content []byte, input ProviderRoutingInput, geo func(string, string) (*protocol.RuleSetData, error)) (ProviderRoutingResult, error) {
	var configs []providerConfig
	if len(content) > protocol.MaxGeoFileBytes {
		return ProviderRoutingResult{}, protocol.ErrConfiguration
	}
	if json.Unmarshal(content, &configs) != nil {
		var one providerConfig
		if json.Unmarshal(content, &one) != nil {
			return ProviderRoutingResult{}, errors.New("Нужна подписка в формате Xray JSON: объект или список конфигураций.")
		}
		configs = []providerConfig{one}
	}
	if len(configs) == 0 || len(configs) > 256 {
		return ProviderRoutingResult{}, errors.New("Подписка должна содержать от 1 до 256 конфигураций.")
	}
	sum := sha256.Sum256(content)
	result := ProviderRoutingResult{SHA256: hex.EncodeToString(sum[:])}
	for i, c := range configs {
		label := strings.TrimSpace(c.Remarks)
		if label == "" {
			label = fmt.Sprintf("Конфигурация %d", i+1)
		}
		if len(label) > 512 {
			label = "Слишком длинное название"
		}
		result.Profiles = append(result.Profiles, ProviderRoutingChoice{i, label})
	}
	if input.Index < 0 {
		return result, nil
	}
	if input.Index >= len(configs) || input.SHA256 != result.SHA256 {
		return ProviderRoutingResult{}, errors.New("Подписка изменилась. Обновите список конфигураций и выберите заново.")
	}
	c := configs[input.Index]
	n := &protocol.NetworkOptions{}
	tags := map[string]string{}
	for _, o := range c.Outbounds {
		action := ""
		switch o.Protocol {
		case "freedom":
			action = "direct"
		case "blackhole":
			action = "reject"
		case "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria", "hysteria2", "wireguard":
			action = "proxy"
		}
		if _, exists := tags[o.Tag]; exists {
			tags[o.Tag] = ""
		} else {
			tags[o.Tag] = action
		}
	}
	warn := func(i int, reason string) {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Правило %d пропущено: %s", i+1, reason))
	}
	for i, raw := range c.Routing.Rules {
		if i >= 128 {
			return ProviderRoutingResult{}, errors.New("В конфигурации больше 128 исходных правил; импорт отменён.")
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return ProviderRoutingResult{}, protocol.ErrConfiguration
		}
		unsupported := []string{}
		for k := range fields {
			if !slices.Contains([]string{"type", "domain", "ip", "network", "port", "outboundTag", "balancerTag"}, k) {
				unsupported = append(unsupported, k)
			}
		}
		if len(unsupported) > 0 {
			slices.Sort(unsupported)
			warn(i, "неподдерживаемые условия: "+strings.Join(unsupported, ", "))
			continue
		}
		var r struct {
			Type, Network, Port, OutboundTag, BalancerTag string
			Domain, IP                                    []string
		}
		if json.Unmarshal(raw, &r) != nil || r.Type != "field" {
			warn(i, "неподдерживаемый формат")
			continue
		}
		if r.BalancerTag != "" {
			warn(i, "балансировщик провайдера не переносится; остальной трафик использует выбранный сервер OneTunnel")
			continue
		}
		action := tags[r.OutboundTag]
		if action == "" {
			warn(i, "неизвестное действие или сервер")
			continue
		}
		if len(r.Domain) > 0 && len(r.IP) > 0 {
			warn(i, "совместное условие домена и IP")
			continue
		}
		networks := []string{r.Network}
		if r.Network == "tcp,udp" || r.Network == "udp,tcp" {
			networks = []string{"tcp", "udp"}
		}
		data := &protocol.RuleSetData{}
		bad := ""
		values := r.Domain
		format := "geosite"
		if len(r.IP) > 0 {
			values = r.IP
			format = "geoip"
		}
		for _, v := range values {
			if strings.HasPrefix(v, format+":") {
				category := strings.TrimPrefix(v, format+":")
				if len(category) > 120 || !geoCategory.MatchString(category) {
					bad = "неподдерживаемая категория"
					break
				}
				d, e := geo(format, category)
				if e != nil {
					return ProviderRoutingResult{}, fmt.Errorf("Не удалось подготовить %s:%s; прежний черновик сохранён. %w", format, category, e)
				}
				data.Domain = append(data.Domain, d.Domain...)
				data.DomainSuffix = append(data.DomainSuffix, d.DomainSuffix...)
				data.DomainKeyword = append(data.DomainKeyword, d.DomainKeyword...)
				data.DomainRegex = append(data.DomainRegex, d.DomainRegex...)
				data.IPCIDR = append(data.IPCIDR, d.IPCIDR...)
				continue
			}
			if format == "geoip" {
				p, e := netip.ParsePrefix(v)
				if e != nil {
					a, err := netip.ParseAddr(v)
					if err != nil {
						bad = "неподдерживаемый IP-список"
						break
					}
					bits := 128
					if a.Is4() {
						bits = 32
					}
					p = netip.PrefixFrom(a, bits)
				}
				data.IPCIDR = append(data.IPCIDR, p.String())
				continue
			}
			switch {
			case strings.HasPrefix(v, "domain:"):
				data.DomainSuffix = append(data.DomainSuffix, strings.TrimPrefix(v, "domain:"))
			case strings.HasPrefix(v, "full:"):
				data.Domain = append(data.Domain, strings.TrimPrefix(v, "full:"))
			case strings.HasPrefix(v, "regexp:"):
				data.DomainRegex = append(data.DomainRegex, strings.TrimPrefix(v, "regexp:"))
			case strings.Contains(v, ":"):
				bad = "неподдерживаемое условие домена"
			default:
				data.DomainKeyword = append(data.DomainKeyword, v)
			}
		}
		if bad != "" {
			warn(i, bad)
			continue
		}
		name := fmt.Sprintf("provider-%d", i+1)
		candidate := protocol.CloneNetworkOptions(n)
		if len(values) > 0 {
			candidate.RuleSets = append(candidate.RuleSets, protocol.RuleSet{Name: name, Data: data})
		}
		for _, network := range networks {
			rule := protocol.NetworkRule{Action: action, Network: network, Port: r.Port}
			switch {
			case len(values) > 0:
				rule.Kind = "rule-set"
				rule.Value = name
			case r.Port != "":
				rule.Kind = "port"
				rule.Value = r.Port
				rule.Port = ""
			case network != "":
				rule.Kind = "network"
				rule.Value = network
				rule.Network = ""
			default:
				bad = "правило без условий"
			}
			candidate.Rules = append(candidate.Rules, rule)
		}
		normalized, e := protocol.NormalizeNetworkOptions(candidate)
		if e != nil || bad != "" {
			warn(i, "неподдерживаемое значение или превышение лимита; правило не расширено")
			continue
		}
		n = normalized
	}
	if len(n.Rules) == 0 {
		return ProviderRoutingResult{}, errors.New("В выбранной конфигурации нет совместимых правил. Прежний черновик сохранён.")
	}
	if c.Routing.DomainStrategy != "" && c.Routing.DomainStrategy != "AsIs" {
		result.Warnings = append(result.Warnings, "Стратегия разрешения доменов провайдера не переносится; используется DNS OneTunnel.")
	}
	result.Warnings = append(result.Warnings, "Выбор маршрутизации не заменяет сервер и DNS текущего профиля. Действие VPN использует выбранный сервер OneTunnel; несовпавший трафик также идёт через него.")
	source := presetSource{Name: "provider-source", Format: "provider-xray", URL: input.URL, Index: input.Index, Label: result.Profiles[input.Index].Label, Warnings: result.Warnings}
	draft := presetDraftResult(n, []presetSource{source}, len(n.Rules))
	result.Draft = &draft
	return result, nil
}
