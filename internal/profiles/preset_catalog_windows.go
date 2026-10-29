package profiles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

type presetSource struct {
	Name, Format, Category, Action string
	Pending                        bool
}
type PresetRow struct {
	Name, Format, Category, Action   string
	Pending                          bool
	DisplayName, ActionLabel, Status string
}

var geoCategory = regexp.MustCompile(`^[a-z0-9][a-z0-9._!\-]*(?:@[a-z0-9][a-z0-9_\-]*)?$`)

func normalizedPresetSource(r RuleImportInput) (presetSource, error) {
	category := strings.ToLower(strings.TrimSpace(r.Category))
	category = strings.TrimPrefix(category, r.Format+":")
	if r.Format == "geosite" || r.Format == "geoip" {
		if !geoCategory.MatchString(category) || len(category) > 120 || r.Format == "geoip" && strings.Contains(category, "@") {
			return presetSource{}, errors.New("Укажите одну категорию: для geosite, например youtube или category-ads-all; для geoip — ru или telegram.")
		}
	}
	if _, e := loyalURL(r.Format, category); e != nil {
		return presetSource{}, e
	}
	name := strings.ToLower(strings.TrimSpace(r.Name))
	if name == "" {
		hash := sha256.Sum256([]byte(r.Format + ":" + category))
		name = "loyal-" + r.Format + "-" + hex.EncodeToString(hash[:4])
	}
	probe := &protocol.NetworkOptions{RuleSets: []protocol.RuleSet{{Name: name, Members: []protocol.NetworkRule{{Kind: "domain", Value: "example.invalid"}}}}, Rules: []protocol.NetworkRule{{Kind: "rule-set", Value: name, Action: r.Action}}}
	checked, e := protocol.NormalizeNetworkOptions(probe)
	if e != nil {
		return presetSource{}, errors.New("Проверьте название набора и действие. Название: латинские буквы, цифры и дефис, до 32 символов.")
	}
	return presetSource{Name: name, Format: r.Format, Category: category, Action: checked.Rules[0].Action, Pending: true}, nil
}
func presetCatalog(n *protocol.NetworkOptions, raw string) ([]presetSource, error) {
	var sources []presetSource
	if len(raw) > 65536 {
		return nil, protocol.ErrConfiguration
	}
	if strings.TrimSpace(raw) != "" {
		dec := json.NewDecoder(bytes.NewBufferString(raw))
		dec.DisallowUnknownFields()
		if dec.Decode(&sources) != nil || dec.Decode(new(any)) != io.EOF {
			return nil, protocol.ErrConfiguration
		}
	}
	if len(sources) > protocol.MaxRuleSets {
		return nil, protocol.ErrConfiguration
	}
	// Retired origins become local snapshots; never reinterpret their contents.
	kept := make([]presetSource, 0, len(sources))
	for _, s := range sources {
		if s.Format == "clash-domain" || s.Format == "clash-ipcidr" {
			found := false
			if n != nil {
				for _, r := range n.Rules {
					if r.Kind == "rule-set" && r.Value == s.Name {
						found = true
						break
					}
				}
			}
			if !found {
				continue
			}
			s.Format = ""
			s.Category = ""
			s.Pending = false
		}
		kept = append(kept, s)
	}
	sources = kept
	seen := map[string]bool{}
	for i, s := range sources {
		if s.Name == "" || seen[s.Name] {
			return nil, protocol.ErrConfiguration
		}
		seen[s.Name] = true
		if s.Format != "" {
			check, e := normalizedPresetSource(RuleImportInput{Name: s.Name, Format: s.Format, Category: s.Category, Action: s.Action})
			if e != nil || check.Name != s.Name || check.Category != s.Category {
				return nil, protocol.ErrConfiguration
			}
			sources[i].Action = check.Action
		} else if s.Pending {
			return nil, protocol.ErrConfiguration
		}
		if !s.Pending {
			found := false
			if n != nil {
				for _, r := range n.Rules {
					if r.Kind == "rule-set" && r.Value == s.Name {
						sources[i].Action = r.Action
						found = true
						break
					}
				}
			}
			if !found {
				return nil, protocol.ErrConfiguration
			}
		}
	}
	if n != nil {
		for _, r := range n.Rules {
			if r.Kind == "rule-set" && !seen[r.Value] {
				sources = append(sources, presetSource{Name: r.Value, Action: r.Action})
				seen[r.Value] = true
			}
		}
	}
	if len(sources) > protocol.MaxRuleSets {
		return nil, protocol.ErrConfiguration
	}
	return sources, nil
}
func presetCatalogFromText(text, raw string) ([]presetSource, error) {
	n, e := (NetworkInput{Mode: "default", RulesText: text}).Parse()
	if e != nil {
		return nil, e
	}
	return presetCatalog(n, raw)
}
func encodePresetCatalog(s []presetSource) string {
	if len(s) == 0 {
		return ""
	}
	b, _ := json.Marshal(s)
	return string(b)
}
func presetRows(sources []presetSource) []PresetRow {
	rows := make([]PresetRow, 0, len(sources))
	for _, s := range sources {
		name, status := s.Format+" · "+s.Category, "Готов"
		if s.Format == "" {
			name = "Сохранённый набор"
			status = "Укажите источник"
		}
		if s.Pending {
			status = "Нужно обновить"
		}
		rows = append(rows, PresetRow{Name: s.Name, Format: s.Format, Category: s.Category, Action: s.Action, Pending: s.Pending, DisplayName: name, ActionLabel: map[string]string{"proxy": "VPN / прокси", "direct": "Напрямую", "reject": "Блокировать"}[s.Action], Status: status})
	}
	return rows
}
func presetDraftInput(input *NetworkInput) (*protocol.NetworkOptions, []presetSource, error) {
	if input == nil {
		return nil, nil, protocol.ErrConfiguration
	}
	n, e := (NetworkInput{Mode: "default", RulesText: input.RulesText}).Parse()
	if e != nil {
		return nil, nil, e
	}
	if !presetOnly(n) {
		return nil, nil, errors.New("Ручные правила остаются в отдельном режиме «Свои правила».")
	}
	if n == nil {
		n = &protocol.NetworkOptions{}
	}
	sources, e := presetCatalog(n, input.PresetConfigText)
	return n, sources, e
}
func presetDraftResult(n *protocol.NetworkOptions, sources []presetSource, count int) RuleImportResult {
	return RuleImportResult{RulesText: routeText(n), PresetSummary: presetSummary(n), PresetConfigText: encodePresetCatalog(sources), PresetRows: presetRows(sources), Count: count}
}
func configurePresetDraft(input *NetworkInput, request *RuleImportInput, remove bool) (RuleImportResult, error) {
	if request == nil {
		return RuleImportResult{}, protocol.ErrConfiguration
	}
	n, sources, e := presetDraftInput(input)
	if e != nil {
		return RuleImportResult{}, e
	}
	if remove {
		found := false
		sources = slices.DeleteFunc(sources, func(s presetSource) bool {
			if s.Name == request.Name {
				found = true
				return true
			}
			return false
		})
		if !found {
			return RuleImportResult{}, errors.New("Выберите набор в списке.")
		}
		n.Rules = slices.DeleteFunc(n.Rules, func(r protocol.NetworkRule) bool { return r.Kind == "rule-set" && r.Value == request.Name })
		n.RuleSets = slices.DeleteFunc(n.RuleSets, func(s protocol.RuleSet) bool { return s.Name == request.Name })
	} else {
		source, e := normalizedPresetSource(*request)
		if e != nil {
			return RuleImportResult{}, e
		}
		index := -1
		for i, s := range sources {
			if s.Name == source.Name {
				index = i
			}
		}
		if index >= 0 {
			if !request.Replace {
				return RuleImportResult{}, errors.New("Набор уже есть. Выберите его в списке для изменения.")
			}
			sources[index] = source
		} else {
			if len(sources) >= protocol.MaxRuleSets {
				return RuleImportResult{}, errors.New("Можно добавить до 16 наборов.")
			}
			sources = append(sources, source)
		}
	}
	return presetDraftResult(n, sources, 0), nil
}
func refreshPresetDraft(ctx context.Context, input *NetworkInput) (RuleImportResult, error) {
	_, sources, e := presetDraftInput(input)
	if e != nil {
		return RuleImportResult{}, e
	}
	if len(sources) == 0 {
		return RuleImportResult{}, errors.New("Сначала добавьте хотя бы один набор.")
	}
	ctx, cancel := context.WithTimeout(ctx, 110*time.Second)
	defer cancel()
	cache := map[string][]byte{}
	totalBytes, count := 0, 0
	n := &protocol.NetworkOptions{}
	for i, s := range sources {
		if s.Format == "" {
			return RuleImportResult{}, errors.New("У старого набора не указан источник. Выберите его, задайте формат и категорию, затем нажмите «Добавить / изменить».")
		}
		url, e := loyalURL(s.Format, s.Category)
		if e != nil {
			return RuleImportResult{}, e
		}
		content, ok := cache[url]
		if !ok {
			content, e = downloadLoyal(ctx, s.Format, s.Category)
			if e != nil {
				return RuleImportResult{}, e
			}
			totalBytes += len(content)
			if totalBytes > 96*1024*1024 {
				return RuleImportResult{}, errors.New("Общий объём исходных наборов превышает 96 МиБ.")
			}
			cache[url] = content
		}
		data, e := protocol.ImportLoyalsoldier(s.Format, s.Category, content)
		if e != nil {
			return RuleImportResult{}, errors.New("Категория «" + s.Category + "» не найдена или содержит неподдерживаемые данные. Прежний черновик сохранён.")
		}
		n.RuleSets = append(n.RuleSets, protocol.RuleSet{Name: s.Name, Data: data})
		n.Rules = append(n.Rules, protocol.NetworkRule{Kind: "rule-set", Value: s.Name, Action: s.Action})
		sources[i].Pending = false
		count += len(data.Domain) + len(data.DomainSuffix) + len(data.DomainKeyword) + len(data.DomainRegex) + len(data.IPCIDR)
	}
	n, e = protocol.NormalizeNetworkOptions(n)
	if e != nil {
		return RuleImportResult{}, errors.New("Наборы не помещаются в политику. Удалите ненужный набор; прежние данные сохранены.")
	}
	return presetDraftResult(n, sources, count), nil
}

// The paired preset has one fixed order; a failed download returns no partial draft.
func recommendedPresetDraft(ctx context.Context) (RuleImportResult, error) {
	return refreshPresetDraft(ctx, recommendedPresetInput())
}

func recommendedPresetInput() *NetworkInput {
	return &NetworkInput{Mode: "default", PresetConfigText: encodePresetCatalog([]presetSource{
		{Name: "loyal-ads", Format: "geosite", Category: "category-ads-all", Action: "reject", Pending: true},
		{Name: "loyal-ru-sites", Format: "geosite", Category: "category-ru", Action: "direct", Pending: true},
		{Name: "loyal-ru-ip", Format: "geoip", Category: "ru", Action: "direct", Pending: true},
	})}
}
func appendRuleDraft(input *NetworkInput, rule *protocol.NetworkRule) (RuleImportResult, error) {
	if input == nil || rule == nil {
		return RuleImportResult{}, protocol.ErrConfiguration
	}
	n, e := (NetworkInput{Mode: "default", RulesText: input.RulesText}).Parse()
	if e != nil {
		return RuleImportResult{}, e
	}
	if n == nil {
		n = &protocol.NetworkOptions{}
	}
	n.Rules = append(n.Rules, *rule)
	n, e = protocol.NormalizeNetworkOptions(n)
	if e != nil {
		return RuleImportResult{}, errors.New("Правило не добавлено. Проверьте тип, значение, действие, условия и имя дополнительного сервера. Допустимо до 64 правил.")
	}
	return RuleImportResult{RulesText: routeText(n)}, nil
}
