package profiles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

type RuleImportInput struct {
	Format, Category, Name, Action, Path string
	Download, Replace                    bool
}
type RuleImportResult struct {
	PresetConfigText  string
	PresetRows        []PresetRow
	PresetSummary     string
	RulesText, SHA256 string
	Count             int
}

func loyalURL(format, category string) (string, error) {
	if format == "geosite" || format == "geoip" {
		return "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/" + format + ".dat", nil
	}
	return "", fmt.Errorf("Поддерживаются только geosite.dat и geoip.dat.")
}
func downloadLoyal(ctx context.Context, format, category string) ([]byte, error) {
	url, e := loyalURL(format, category)
	if e != nil {
		return nil, e
	}
	return downloadLoyalURL(ctx, format, url)
}
func downloadLoyalURL(ctx context.Context, format, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("rule_import_redirect") }}
	for attempt := 0; attempt < 2; attempt++ {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if e != nil {
			return nil, e
		}
		response, e := client.Do(req)
		if e != nil {
			if ctx.Err() == nil && attempt == 0 {
				continue
			}
			return nil, fmt.Errorf("Не удалось загрузить %s.dat с GitHub; прежние правила сохранены: %w", format, e)
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return nil, fmt.Errorf("GitHub вернул HTTP %d; прежние правила сохранены.", response.StatusCode)
		}
		// Keep read failures distinct from a genuinely oversized database.
		content, e := readBounded(response.Body, protocol.MaxGeoFileBytes)
		response.Body.Close()
		if e == nil {
			return content, nil
		}
		if errors.Is(e, errBoundedSize) {
			return nil, fmt.Errorf("%s.dat превышает допустимые 128 МиБ; прежние правила сохранены.", format)
		}
		if ctx.Err() == nil && attempt == 0 {
			continue
		}
		return nil, fmt.Errorf("Загрузка %s.dat прервалась; прежние правила сохранены. Повторите обновление: %w", format, e)
	}
	panic("unreachable")
}
func importRuleDraft(ctx context.Context, input *NetworkInput, request *RuleImportInput) (RuleImportResult, error) {
	fail := func(e error) (RuleImportResult, error) { return RuleImportResult{}, e }
	if input == nil || request == nil {
		return fail(protocol.ErrConfiguration)
	}
	if request.Format != "geosite" && request.Format != "geoip" {
		return fail(fmt.Errorf("Поддерживаются только geosite.dat и geoip.dat."))
	}
	options, e := input.Parse()
	if e != nil {
		return fail(e)
	}
	if options == nil {
		options = &protocol.NetworkOptions{}
	}
	name := strings.ToLower(strings.TrimSpace(request.Name))
	category := strings.ToLower(strings.TrimSpace(request.Category))
	category = strings.TrimPrefix(category, request.Format+":")
	if (request.Format == "geosite" || request.Format == "geoip") && (!geoCategory.MatchString(category) || len(category) > 120 || request.Format == "geoip" && strings.Contains(category, "@")) {
		return fail(fmt.Errorf("Укажите категорию: geosite — например youtube или category-ads-all; geoip — ru или telegram."))
	}
	// Validate names/actions before any download or file read.
	probe := &protocol.NetworkOptions{RuleSets: []protocol.RuleSet{{Name: name, Members: []protocol.NetworkRule{{Kind: "domain", Value: "example.invalid"}}}}, Rules: []protocol.NetworkRule{{Kind: "rule-set", Value: name, Action: request.Action}}}
	if _, e = protocol.NormalizeNetworkOptions(probe); e != nil {
		return fail(fmt.Errorf("Имя набора: латинские буквы, цифры и дефис, до 32 символов. Выберите действие."))
	}
	index := -1
	for i, set := range options.RuleSets {
		if set.Name == name {
			index = i
		}
	}
	if index >= 0 && !request.Replace {
		return fail(fmt.Errorf("Набор с таким именем уже есть. Для обновления разрешите замену содержимого; порядок и действия правил сохранятся."))
	}
	if index < 0 && (len(options.RuleSets) >= protocol.MaxRuleSets || len(options.Rules) >= protocol.MaxNetworkRules) {
		return fail(fmt.Errorf("Достигнут предел наборов или правил."))
	}
	var content []byte
	if request.Download {
		if request.Path != "" {
			return fail(protocol.ErrConfiguration)
		}
		content, e = downloadLoyal(ctx, request.Format, category)
	} else {
		var f *os.File
		f, e = os.Open(request.Path)
		if e == nil {
			defer f.Close()
			var st os.FileInfo
			st, e = f.Stat()
			if e == nil && (!st.Mode().IsRegular() || st.Size() > protocol.MaxGeoFileBytes) {
				e = fmt.Errorf("Нужен обычный файл не более 128 МиБ.")
			}
			if e == nil {
				content, e = readBounded(f, protocol.MaxGeoFileBytes)
			}
		}
	}
	if e != nil {
		return fail(e)
	}
	data, e := protocol.ImportLoyalsoldier(request.Format, category, content)
	if e != nil {
		return fail(fmt.Errorf("Набор не импортирован: %w. Проверьте формат, категорию и размер; правила не усечены.", e))
	}
	set := protocol.RuleSet{Name: name, Data: data}
	if index >= 0 {
		options.RuleSets[index] = set
	} else {
		options.RuleSets = append(options.RuleSets, set)
		options.Rules = append(options.Rules, protocol.NetworkRule{Kind: "rule-set", Value: name, Action: request.Action})
	}
	normalized, e := protocol.NormalizeNetworkOptions(options)
	if e != nil {
		return fail(e)
	}
	policy := struct {
		Rules    []protocol.NetworkRule
		Targets  []protocol.PolicyTarget `json:",omitempty"`
		RuleSets []protocol.RuleSet
	}{normalized.Rules, normalized.Targets, normalized.RuleSets}
	encoded, e := json.Marshal(policy)
	if e != nil {
		return fail(e)
	}
	hash := sha256.Sum256(content)
	catalog, err := presetCatalog(normalized, input.PresetConfigText)
	if err != nil {
		return fail(err)
	}
	if source, err := normalizedPresetSource(*request); err == nil {
		source.Pending = false
		for _, r := range normalized.Rules {
			if r.Kind == "rule-set" && r.Value == name {
				source.Action = r.Action
				break
			}
		}
		for i, s := range catalog {
			if s.Name == name {
				source.Name = name
				catalog[i] = source
			}
		}
	}
	return RuleImportResult{PresetConfigText: encodePresetCatalog(catalog), PresetRows: presetRows(catalog), PresetSummary: presetSummary(normalized), RulesText: string(encoded), SHA256: hex.EncodeToString(hash[:]), Count: len(data.Domain) + len(data.DomainSuffix) + len(data.DomainKeyword) + len(data.DomainRegex) + len(data.IPCIDR)}, nil
}
